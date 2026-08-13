/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.plugin.core.debug.gui.emulation;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.MouseEvent;
import java.util.*;
import java.util.stream.Collectors;

import javax.swing.*;

import db.Transaction;
import docking.*;
import docking.action.ActionContextProvider;
import docking.action.DockingActionIf;
import docking.action.builder.ActionBuilder;
import docking.menu.DialogToolbarButton;
import docking.widgets.table.*;
import ghidra.app.plugin.core.data.AbstractSettingsDialog;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.gui.emulation.FunctionEmulationHarness.*;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.services.*;
import ghidra.debug.api.control.ControlMode;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.docking.settings.*;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.pcode.utils.Utils;
import ghidra.program.database.data.DataTypeUtilities;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.ByteMemBufferImpl;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.util.FunctionChangeRecord;
import ghidra.program.util.ProgramEvent;
import ghidra.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.GhidraTableFilterPanel;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

public class DebuggerEmulateFunctionDialog extends DialogComponentProvider {
	static final int GAP = 5;
	static final String FMT_VA = "Vararg %d";
	static final String FMT_CUSTOM = "Custom %d";
	static final String PREFIX_PROBE = "Probe ";
	static final String FMT_PROBE = PREFIX_PROBE + "%d";

	protected static class VarActionContext<T extends VarRow> extends DefaultActionContext {
		private final List<T> selection;

		public VarActionContext(List<T> selection) {
			this.selection = selection;
		}

		public List<T> getSelection() {
			return selection;
		}
	}

	protected static class InputActionContext extends VarActionContext<InputRow> {
		public InputActionContext(List<InputRow> selection) {
			super(selection);
		}
	}

	protected static class OutputActionContext extends VarActionContext<OutputRow> {
		public OutputActionContext(List<OutputRow> selection) {
			super(selection);
		}
	}

	protected abstract static class ActionContainer implements ActionContextProvider {
		protected final JComponent component;
		private final List<DockingActionIf> actions = new ArrayList<>();
		private boolean valid;

		public ActionContainer(JComponent container) {
			this.component = container;
		}

		protected abstract void addGroupSeparator();

		public void addAction(DockingActionIf action) {
			if (actions.add(action)) {
				valid = false;
			}
		}

		private void revalidate() {
			if (valid) {
				return;
			}
			component.removeAll();

			Map<String, List<DockingActionIf>> byGroup = actions.stream()
					.collect(Collectors.groupingBy(a -> a.getToolBarData().getToolBarGroup()));
			boolean first = true;
			for (Map.Entry<String, List<DockingActionIf>> ent : byGroup.entrySet()) {
				List<DockingActionIf> actions = ent.getValue();
				actions.sort(Comparator.comparing(a -> a.getToolBarData().getToolBarSubGroup()));
				if (!first) {
					addGroupSeparator();
				}
				for (DockingActionIf action : actions) {
					component.add(new DialogToolbarButton(action, this));
				}
				first = false;
			}
			valid = true;
		}

		public void contextChanged() {
			revalidate();
			ActionContext ctx = getActionContext(null);
			for (DockingActionIf action : actions) {
				action.setEnabled(action.isEnabledForContext(ctx));
			}
		}

		/* Testing */ DockingActionIf byName(String name) {
			return actions.stream().filter(a -> name.equals(a.getName())).findFirst().orElseThrow();
		}
	}

	protected abstract static class HorizontalBoxActionContainer extends ActionContainer {
		public HorizontalBoxActionContainer() {
			super(Box.createHorizontalBox());
		}

		@Override
		protected void addGroupSeparator() {
			component.add(Box.createHorizontalStrut(5));
			component.add(DockingUtils.createToolbarSeparator());
			component.add(Box.createHorizontalStrut(5));
		}
	}

	protected final PluginTool tool;
	protected final Function function;
	protected final SleighLanguage language;

	protected JTextField textSentinel;
	protected JTextField textSnapshotPeriod;
	protected JTextField textNextAlloc;
	protected Address sentinel;
	protected long snapshotPeriod;
	protected Address nextAlloc;

	protected final InputsTableModel inputsTableModel;
	protected GTable inputsTable;
	protected GhidraTableFilterPanel<InputRow> inputsFilterPanel;

	protected final OutputsTableModel outputsTableModel;
	protected GTable outputsTable;
	protected GhidraTableFilterPanel<OutputRow> outputsFilterPanel;

	protected final ActionContainer inputActions = new HorizontalBoxActionContainer() {
		@Override
		public ActionContext getActionContext(MouseEvent e) {
			return new InputActionContext(inputsFilterPanel.getSelectedItems());
		}
	};
	protected final ActionContainer outputActions = new HorizontalBoxActionContainer() {
		@Override
		public ActionContext getActionContext(MouseEvent e) {
			return new OutputActionContext(outputsFilterPanel.getSelectedItems());
		}
	};

	protected final DomainObjectListener listenerForFunction = new DomainObjectListenerBuilder(this)
			.any(DomainObjectEvent.RESTORED)
			.terminate(inputActions::contextChanged)
			.with(FunctionChangeRecord.class)
			.each(ProgramEvent.FUNCTION_CHANGED)
			.call(this::functionChanged)
			.build();

	public DebuggerEmulateFunctionDialog(PluginTool tool, Function function) {
		super("Emulate %s of %s".formatted(function.getName(), function.getProgram().getName()),
			false, true, true, true);
		if (!(function.getProgram().getLanguage() instanceof SleighLanguage language)) {
			throw new IllegalArgumentException("Sleigh language required");
		}
		this.tool = tool;
		this.function = function;
		this.language = language;

		inputsTableModel = new InputsTableModel(tool, this);
		outputsTableModel = new OutputsTableModel(tool, this);

		inputsTableModel.addTableModelListener(evt -> {
			inputActions.contextChanged();
		});
		outputsTableModel.addTableModelListener(evt -> {
			outputActions.contextChanged();
		});

		sentinel = language.getDefaultSpace().getAddress(0xdeadbeef);
		snapshotPeriod = 1;
		nextAlloc = language.getDefaultDataSpace().getAddress(0x7beef000);

		populateComponents();
		createActions();

		initializeVarTables();
		inputActions.contextChanged();
		outputActions.contextChanged();

		function.getProgram().addListener(listenerForFunction);

	}

	protected void populateComponents() {
		JPanel panel = new JPanel(new BorderLayout());

		{
			JPanel opts = new JPanel();
			opts.setLayout(new BoxLayout(opts, BoxLayout.Y_AXIS));
			opts.getAccessibleContext().setAccessibleName("Options");
			{
				Box box = Box.createHorizontalBox();
				box.setBorder(BorderFactory.createEmptyBorder(GAP, GAP, GAP, GAP));
				JLabel label = new JLabel("Ending Return Address:");
				label.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, GAP));
				box.add(label);
				textSentinel = new JTextField("deadbeef");
				box.add(textSentinel);
				opts.add(box);
			}
			{
				Box box = Box.createHorizontalBox();
				box.setBorder(BorderFactory.createEmptyBorder(GAP, GAP, GAP, GAP));
				JLabel label = new JLabel("Snapshot Period (0 for none):");
				label.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, GAP));
				box.add(label);
				textSnapshotPeriod = new JTextField(Long.toString(snapshotPeriod));
				box.add(textSnapshotPeriod);
				opts.add(box);
			}
			{
				Box box = Box.createHorizontalBox();
				box.setBorder(BorderFactory.createEmptyBorder(GAP, GAP, GAP, GAP));
				JLabel label = new JLabel("Next Allocation:");
				label.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, GAP));
				box.add(label);
				textNextAlloc = new JTextField(nextAlloc.toString());
				box.add(textNextAlloc);
				opts.add(box);
			}
			panel.add(opts, BorderLayout.NORTH);
		}
		{
			JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
			{
				JPanel inputsTablePanel = new JPanel(new BorderLayout());
				JPanel topBar = new JPanel(new BorderLayout());
				topBar.add(new JLabel("Inputs:"), BorderLayout.WEST);
				topBar.add(inputActions.component, BorderLayout.EAST);
				topBar.add(new JSeparator(SwingConstants.HORIZONTAL), BorderLayout.NORTH);
				inputsTablePanel.add(topBar, BorderLayout.NORTH);

				inputsTable = new GTable(inputsTableModel);
				inputsTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
				inputsTablePanel.add(new JScrollPane(inputsTable));
				inputsFilterPanel = new GhidraTableFilterPanel<>(inputsTable, inputsTableModel);
				inputsTablePanel.add(inputsFilterPanel, BorderLayout.SOUTH);
				inputsTablePanel.getAccessibleContext().setAccessibleName("Inputs Filters");
				splitPane.setTopComponent(inputsTablePanel);
			}
			{
				JPanel outputsTablePanel = new JPanel(new BorderLayout());
				JPanel topBar = new JPanel(new BorderLayout());
				topBar.add(new JLabel("Outputs:"), BorderLayout.WEST);
				topBar.add(outputActions.component, BorderLayout.EAST);
				topBar.add(new JSeparator(SwingConstants.HORIZONTAL), BorderLayout.NORTH);
				outputsTablePanel.add(topBar, BorderLayout.NORTH);

				outputsTable = new GTable(outputsTableModel);
				outputsTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
				outputsTablePanel.add(new JScrollPane(outputsTable));
				outputsFilterPanel = new GhidraTableFilterPanel<>(outputsTable, outputsTableModel);
				outputsTablePanel.add(outputsFilterPanel, BorderLayout.SOUTH);
				outputsTablePanel.getAccessibleContext().setAccessibleName("Outputs Filters");
				splitPane.setBottomComponent(outputsTablePanel);
			}
			panel.add(splitPane);
		}

		panel.getAccessibleContext().setAccessibleName("Emulate " + function.getName());
		addWorkPanel(panel);

		addOKButton();
		okButton.setText("Run");
		addDismissButton();

		inputsTable.getSelectionModel().addListSelectionListener(evt -> {
			inputActions.contextChanged();
		});
		outputsTable.getSelectionModel().addListSelectionListener(evt -> {
			outputActions.contextChanged();
		});

		textSentinel.setInputVerifier(new AddressInputVerifier(language.getAddressFactory()) {
			@Override
			protected boolean verifyAddress(Address address) {
				sentinel = address;
				return true;
			}

			@Override
			protected void reject(String message) {
				setStatusText(message, MessageType.ERROR);
			}
		});
		textSnapshotPeriod.setInputVerifier(new LongInputVerifier() {
			@Override
			protected boolean verifyLong(long value) {
				snapshotPeriod = value;
				return true;
			}

			@Override
			protected void reject(String message) {
				setStatusText(message, MessageType.ERROR);
			}
		});
		textNextAlloc.setInputVerifier(new AddressInputVerifier(language.getAddressFactory()) {
			@Override
			protected boolean verifyAddress(Address address) {
				nextAlloc = address;
				return true;
			}

			@Override
			protected void reject(String message) {
				setStatusText(message, MessageType.ERROR);
			}
		});
	}

	@Override
	protected void dialogClosed() {
		function.getProgram().removeListener(listenerForFunction);
		super.dialogClosed();
	}

	protected void createActions() {
		inputActions.addAction(new ActionBuilder("Add Custom Input", getTitle())
				.toolBarIcon(DebuggerResources.ICON_ADD)
				.toolBarGroup("Add", "1")
				.onAction(this::addCustomInputActivated)
				.build());
		inputActions.addAction(new ActionBuilder("Add Vararg Input", getTitle())
				// TODO: ICON
				.toolBarIcon(DebuggerResources.ICON_OBJECT_POPULATED)
				.toolBarGroup("Add", "2")
				.enabledWhen(this::addVarargEnabled)
				.onAction(this::addVarargActivated)
				.build());
		inputActions.addAction(new ActionBuilder("Allocate and Add Pointer Inputs", getTitle())
				// TODO: ICON
				.toolBarIcon(DebuggerResources.ICON_REGIONS)
				.toolBarGroup("Add", "3")
				.description("""
						Allocate and add input variables for pointed-to types. \
						Hold SHIFT for arrays. Hold CTRL for strings.""")
				.withContext(InputActionContext.class)
				.enabledWhen(this::addPointerVarsEnabled)
				.onAction(this::addPointerInputsActivated)
				.build());
		inputActions.addAction(new ActionBuilder("Remove Input", getTitle())
				.toolBarIcon(DebuggerResources.ICON_DELETE)
				.toolBarGroup("Delete", "1")
				.withContext(InputActionContext.class)
				.enabledWhen(this::removeInputEnabled)
				.onAction(this::removeInputActivated)
				.build());
		inputActions.addAction(new ActionBuilder("Clear Inputs", getTitle())
				.toolBarIcon(DebuggerResources.ICON_CLEAR)
				.toolBarGroup("Delete", "2")
				.onAction(this::clearInputsActivated)
				.build());
		inputActions.addAction(new ActionBuilder("Refresh Parameter Inputs", getTitle())
				.toolBarIcon(DebuggerResources.ICON_REFRESH)
				.toolBarGroup("Util")
				.onAction(this::refreshInputsActivated)
				.build());

		outputActions.addAction(new ActionBuilder("Add Custom Output", getTitle())
				.toolBarIcon(DebuggerResources.ICON_ADD)
				.toolBarGroup("Add", "1")
				.onAction(this::addOutputActivated)
				.build());
		outputActions.addAction(new ActionBuilder("Add Pointer Outputs", getTitle())
				// TODO: ICON
				.toolBarIcon(DebuggerResources.ICON_REGIONS)
				.toolBarGroup("Add", "2")
				.description("""
						Add output variables for pointed-to types. \
						Hold SHIFT for arrays. Hold CTRL for strings.""")
				.withContext(OutputActionContext.class)
				.enabledWhen(this::addPointerVarsEnabled)
				.onAction(this::addPointerOutputsActivated)
				.build());
		outputActions.addAction(new ActionBuilder("Remove Output", getTitle())
				.toolBarIcon(DebuggerResources.ICON_DELETE)
				.toolBarGroup("Delete", "1")
				.withContext(OutputActionContext.class)
				.enabledWhen(this::removeOutputEnabled)
				.onAction(this::removeOutputActivated)
				.build());
		outputActions.addAction(new ActionBuilder("Clear Outputs", getTitle())
				.toolBarIcon(DebuggerResources.ICON_CLEAR)
				.toolBarGroup("Delete", "2")
				.onAction(this::clearOutputsActivated)
				.build());
		outputActions.addAction(new ActionBuilder("Refresh Return Outputs", getTitle())
				.toolBarIcon(DebuggerResources.ICON_REFRESH)
				.toolBarGroup("Util")
				.onAction(this::refreshOutputsActivated)
				.build());

		new ActionBuilder("Type Settings", getTitle())
				.popupMenuPath("Type Settings")
				.withContext(VarActionContext.class)
				.enabledWhen(this::typeSettingsEnabled)
				.onAction(this::typeSettingsActivated)
				.buildAndInstallLocal(this);
	}

	private void functionChanged(FunctionChangeRecord rec) {
		if (rec.getFunction() == function) {
			inputActions.contextChanged();
		}
	}

	<T extends VarRow> Optional<T> findRow(RowObjectTableModel<T> model, String name) {
		return model.getModelData().stream().filter(v -> name.equals(v.getName())).findAny();
	}

	private DataType findParameterType(int i) {
		Parameter parameter = function.getParameter(i);
		if (parameter == null) {
			throw new IllegalArgumentException("No such parameter %d".formatted(i));
		}
		Optional<InputRow> row = findRow(inputsTableModel, parameter.getName());
		if (row.isPresent() && row.get().getType() != null) {
			return row.get().getType();
		}
		return parameter.getDataType();
	}

	private Optional<DataType> findVarargType(int i) {
		return findRow(inputsTableModel, FMT_VA.formatted(i)).map(input -> input.getType());
	}

	private boolean conflictsInputName(RowObjectTableModel<? extends VarRow> model, String name) {
		return findRow(model, name).isPresent();
	}

	private String chooseCustomName(RowObjectTableModel<? extends VarRow> model) {
		for (int i = 1;; i++) {
			String name = FMT_CUSTOM.formatted(i);
			if (!conflictsInputName(model, name)) {
				return name;
			}
		}
	}

	private byte[] promptString(String title, String message, DataType type, Settings settings) {
		while (true) {
			Object response = JOptionPane.showInputDialog(rootPanel, message, title,
				JOptionPane.QUESTION_MESSAGE, DebuggerResources.ICON_REGIONS, null, null);
			if (response == null) {
				return null;
			}
			try {
				String str = response.toString();
				return type.encodeValue(str,
					new ByteMemBufferImpl(language.getDefaultDataSpace().getAddress(0),
						new byte[] {}, language.isBigEndian()),
					settings, -1);
			}
			catch (Exception e) {
				setStatusText(e.getMessage(), MessageType.ERROR);
			}
		}
	}

	private int promptIntGt1(String title, String message) {
		while (true) {
			Object response = JOptionPane.showInputDialog(rootPanel, message, title,
				JOptionPane.QUESTION_MESSAGE, DebuggerResources.ICON_REGIONS, null, null);
			clearStatusText();
			if (response == null) {
				return -1;
			}
			try {
				int count = Integer.parseInt(response.toString());
				if (count >= 1) {
					return count;
				}
				setStatusText("Must be 1 or greater", MessageType.ERROR);
			}
			catch (Exception e) {
				setStatusText(e.getMessage(), MessageType.ERROR);
			}
		}
	}

	private VarStorage promptStorage(String title) {
		while (true) {
			Object expr = JOptionPane.showInputDialog(rootPanel, "Expression", title,
				JOptionPane.QUESTION_MESSAGE, DebuggerResources.ICON_ADD, null, null);
			clearStatusText();
			if (expr == null) {
				return null;
			}
			try {
				return VarStorage.fromExpression(language, expr.toString());
			}
			catch (Exception e) {
				setStatusText(e.getMessage(), MessageType.ERROR);
			}
		}
	}

	private void addCustomInputActivated(ActionContext ctx) {
		VarStorage storage = promptStorage("Add Custom Input");
		if (storage == null) {
			return;
		}
		inputsTableModel.add(new InputRow(language, chooseCustomName(inputsTableModel),
			storage, null));
	}

	private boolean removeInputEnabled(InputActionContext ctx) {
		return !ctx.getSelection().isEmpty();
	}

	private void removeInputActivated(InputActionContext ctx) {
		for (InputRow row : ctx.getSelection()) {
			inputsTableModel.delete(row);
		}
	}

	private boolean addVarargEnabled(ActionContext ctx) {
		DataTypeManagerService dtms = tool.getService(DataTypeManagerService.class);
		return dtms != null && function.hasVarArgs();
	}

	private static DataType getBaseDataType(DataType dt) {
		return dt instanceof TypeDef tdef ? tdef.getBaseDataType() : dt;
	}

	private boolean addPointerVarsEnabled(VarActionContext<?> ctx) {
		List<? extends VarRow> sel = ctx.getSelection();
		if (sel.isEmpty()) {
			return false;
		}
		for (VarRow input : sel) {
			DataType baseType = getBaseDataType(input.getType());
			if (!(baseType instanceof Pointer)) {
				return false;
			}
		}
		return true;
	}

	private Varnode doAllocate(int length) {
		Address addr = nextAlloc;
		nextAlloc = nextAlloc.add(length);
		textNextAlloc.setText(nextAlloc.toString());
		return new Varnode(addr, length);
	}

	interface Allocator {
		void allocate(int length);
	}

	interface RowConstructor<T> {
		T create(String name, VarStorage storage, DataType type);
	}

	abstract class VarAdder<T extends VarRow> {
		protected final T from;
		protected final DefaultEnumeratedColumnTableModel<?, T> into;
		protected final List<T> added;

		public VarAdder(T from, DefaultEnumeratedColumnTableModel<?, T> into, List<T> added) {
			this.from = from;
			this.into = into;
			this.added = added;
		}

		byte[] addrToBytes(Address address, int length) {
			return Utils.longToBytes(address.getOffset(), length, language.isBigEndian());
		}

		void allocate(int length) {
			// Extension point
		}

		abstract T newRow(String name, VarStorage storage, DataType type);

		public void addPointerVars(int count) {
			if (!(getBaseDataType(from.getType()) instanceof Pointer ptr)) {
				return;
			}
			DataType dest = ptr.getDataType();
			int length = dest.getLength();
			int alignedLen = dest.getAlignedLength();
			if (length == -1) {
				throw new IllegalArgumentException(
					"DataType %s has dynamic length".formatted(dest));
			}
			allocate((alignedLen * (count - 1)) + length);

			AddressSpace space = function.getProgram().getLanguage().getDefaultDataSpace();
			int offset = 0;

			if (!(DataTypeUtilities.getBaseDataType(dest) instanceof Composite composite)) {
				for (int i = 0; i < count; i++) {
					VarStorage deref = from.getStorage().deref(language, space, offset, length);
					String name = count == 1 // LATER: Cull unnecessary ()s?
							? "*(%s)".formatted(from.name)
							: "(%s)[%d]".formatted(from.name, i);
					findRow(into, name).ifPresent(into::delete);
					T row = newRow(name, deref, dest);
					into.add(row);
					added.add(row);

					offset += alignedLen;
				}
				return;
			}

			for (int i = 0; i < count; i++) {
				for (DataTypeComponent comp : composite.getDefinedComponents()) {
					VarStorage deref = from.getStorage()
							.deref(language, space, offset + comp.getOffset(), comp.getLength());
					String fieldName = comp.getFieldName();
					if (fieldName == null) {
						fieldName = comp.getDefaultFieldName();
					}
					String name = count == 1
							? "(%s)->%s".formatted(from.name, fieldName)
							: "(%s)[%d].%s".formatted(from.name, i, fieldName);
					findRow(into, name).ifPresent(into::delete);
					T row = newRow(name, deref, comp.getDataType());
					into.add(row);
					added.add(row);
				}

				offset += alignedLen;
			}
		}

		record SettingsAndValue(Settings settings, byte[] encoded) {}

		abstract SettingsAndValue defaultStringValue(String name, DataType type);

		public void addStringVar() {
			AddressSpace space = function.getProgram().getLanguage().getDefaultDataSpace();

			DataType strType = deriveStringType(from.type);
			if (strType == null) {
				return;
			}
			SettingsAndValue value = defaultStringValue(from.name, strType);
			Varnode alloc = doAllocate(value.encoded.length);
			from.setValue(addrToBytes(alloc.getAddress(), from.length));
			VarStorage deref = from.getStorage().deref(language, space, alloc.getSize());
			T row = newRow("*(%s)".formatted(from.name), deref, strType);
			copySettings(value.settings, row.getSettings(), strType.getSettingsDefinitions());
			row.setValue(value.encoded);
			added.add(row);
			into.add(row);
		}
	}

	class InputAdder extends VarAdder<InputRow> {
		private final Map<DataType, Settings> settingsMap;

		public InputAdder(InputRow from, List<InputRow> added,
				Map<DataType, Settings> settingsMap) {
			super(from, inputsTableModel, added);
			this.settingsMap = settingsMap;
		}

		@Override
		SettingsAndValue defaultStringValue(String name, DataType type) {
			Settings settings = settingsMap.computeIfAbsent(type, t -> {
				Settings s = new SettingsImpl();
				tool.showDialog(new VarDataSettingsDialog(type, s));
				return s;
			});
			byte[] encoded =
				promptString("Allocate String", "Value of %s".formatted(name), type, settings);
			return new SettingsAndValue(settings, encoded);
		}

		@Override
		void allocate(int length) {
			Varnode alloc = doAllocate(length);
			from.setValue(addrToBytes(alloc.getAddress(), from.length));
		}

		@Override
		InputRow newRow(String name, VarStorage storage, DataType type) {
			return new InputRow(language, name, storage, type, Set.of(from.name));
		}
	}

	class OutputAdder extends VarAdder<OutputRow> {
		public OutputAdder(OutputRow from, List<OutputRow> added) {
			super(from, outputsTableModel, added);
		}

		@Override
		SettingsAndValue defaultStringValue(String name, DataType type) {
			int length = promptIntGt1("Add String", "Length of %s".formatted(name));
			if (length < -1) {
				return null;
			}
			return new SettingsAndValue(new SettingsImpl(), new byte[length]);
		}

		@Override
		OutputRow newRow(String name, VarStorage storage, DataType type) {
			return new OutputRow(language, name, storage, type);
		}
	}

	AbstractStringDataType deriveStringType(DataType dt) {
		if (!(dt instanceof Pointer ptr)) {
			return null;
		}
		return switch (ptr.getDataType()) {
			case AbstractStringDataType strType -> strType;
			case CharDataType charType -> TerminatedStringDataType.dataType;
			default -> null;
		};
	}

	private int getCount(ActionContext ctx) {
		if ((ctx.getEventClickModifiers() & ActionEvent.SHIFT_MASK) == 0) {
			return 1;
		}
		return promptIntGt1("Allocate Pointer Array Inputs", "Count");
	}

	private void addPointerInputsActivated(InputActionContext ctx) {
		List<InputRow> added = new ArrayList<>();
		Map<DataType, Settings> settingsMap = new HashMap<>();
		if ((ctx.getEventClickModifiers() & ActionEvent.CTRL_MASK) != 0) {
			for (InputRow input : ctx.getSelection()) {
				new InputAdder(input, added, settingsMap).addStringVar();
			}
		}
		else {
			int count = getCount(ctx);
			if (count < 0) {
				return;
			}
			for (InputRow input : ctx.getSelection()) {
				new InputAdder(input, added, settingsMap).addPointerVars(count);
			}
		}
		if (!added.isEmpty()) {
			inputsFilterPanel.setSelectedItems(added);
		}
	}

	private void addPointerOutputsActivated(OutputActionContext ctx) {
		List<OutputRow> added = new ArrayList<>();
		if ((ctx.getEventClickModifiers() & ActionEvent.CTRL_MASK) != 0) {
			for (OutputRow output : ctx.getSelection()) {
				new OutputAdder(output, added).addStringVar();
			}
		}
		else {
			int count = getCount(ctx);
			if (count < 0) {
				return;
			}
			for (OutputRow output : ctx.getSelection()) {
				new OutputAdder(output, added).addPointerVars(count);
			}
			if (!added.isEmpty()) {
				outputsFilterPanel.setSelectedItems(added);
			}
		}
	}

	private void addVarargActivated(ActionContext ctx) {
		DataTypeManagerService dtms = tool.getService(DataTypeManagerService.class);
		if (dtms == null) {
			return;
		}
		DataType chosenDt = dtms.promptForDataType(null);
		if (chosenDt == null) {
			return;
		}
		Program program = function.getProgram();
		DataTypeManager dtm = program.getDataTypeManager();
		try (Transaction tx = program.openTransaction("Resolve data type")) {
			chosenDt = dtm.resolve(chosenDt, DataTypeConflictHandler.DEFAULT_HANDLER);
		}

		PrototypeModel cc = function.getCallingConvention();
		PrototypePieces proto = new PrototypePieces(cc, function.getReturnType());

		int paramCount = function.getParameterCount();
		for (int i = 0; i < paramCount; i++) {
			proto.intypes.add(findParameterType(i));
		}
		for (int i = 1;; i++) {
			Optional<DataType> dt = findVarargType(i);
			if (dt.isEmpty()) {
				break;
			}
			proto.intypes.add(dt.get());
		}
		proto.intypes.add(chosenDt);

		ArrayList<ParameterPieces> result = new ArrayList<>();
		cc.assignParameterStorage(proto, dtm, result, true);
		CompilerSpec cSpec = program.getCompilerSpec();
		String name = FMT_VA.formatted(result.size() - 1); // -1 to account for "return" param
		ParameterPieces last = result.getLast();
		InputRow input = new InputRow(language, name,
			VarStorage.fromVariableStorage(last.getVariableStorage(program), cSpec), last.type);
		inputsTableModel.add(input);
	}

	private void refreshInputsActivated(ActionContext ctx) {
		doRefreshInputs();
	}

	private void clearInputsActivated(ActionContext ctx) {
		inputsTableModel.clear();
	}

	private void addOutputActivated(ActionContext ctx) {
		outputsTableModel.add(new OutputRow(language, chooseCustomName(outputsTableModel),
			promptStorage("Add Output"), null));
	}

	private boolean removeOutputEnabled(OutputActionContext ctx) {
		return !ctx.getSelection().isEmpty();
	}

	private void removeOutputActivated(OutputActionContext ctx) {
		for (OutputRow row : ctx.getSelection()) {
			outputsTableModel.delete(row);
		}
	}

	private void refreshOutputsActivated(ActionContext ctx) {
		doRefreshOutputs();
	}

	private void clearOutputsActivated(ActionContext ctx) {
		outputsTableModel.clear();
	}

	private void doRefreshInputs() {
		CompilerSpec cSpec = function.getProgram().getCompilerSpec();
		for (Parameter parameter : function.getParameters()) {
			findRow(inputsTableModel, parameter.getName()).ifPresent(inputsTableModel::delete);
			inputsTableModel.add(InputRow.fromVariable(parameter, cSpec));
		}
	}

	private void doRefreshOutputs() {
		CompilerSpec cSpec = function.getProgram().getCompilerSpec();
		Parameter ret = function.getReturn();
		findRow(outputsTableModel, ret.getName()).ifPresent(outputsTableModel::delete);
		if (!(ret.getDataType() instanceof VoidDataType) &&
			!ret.getVariableStorage().isUnassignedStorage()) {
			outputsTableModel.add(OutputRow.fromVariable(ret, cSpec));
		}
	}

	private boolean typeSettingsEnabled(VarActionContext<?> ctx) {
		return ctx != null && ctx.getSelection().size() == 1;
	}

	protected static void copySettings(Settings src, Settings dst, SettingsDefinition[] defs) {
		for (SettingsDefinition sd : defs) {
			sd.copySetting(src, dst);
		}
	}

	protected class VarDataSettingsDialog extends AbstractSettingsDialog {
		private final Settings mySettings;

		public VarDataSettingsDialog(DataType type, Settings mySettings) {
			super("Settings for %s".formatted(type), type.getSettingsDefinitions(), mySettings);
			this.mySettings = mySettings;
		}

		@Override
		protected Settings getSettings() {
			return super.getSettings();
		}

		@Override
		protected void okCallback() {
			super.okCallback();
		}

		@Override
		protected String[] getSuggestedValues(StringSettingsDefinition settingsDefinition) {
			if (!settingsDefinition.supportsSuggestedValues()) {
				return null;
			}
			return settingsDefinition.getSuggestedValues(mySettings);
		}

		@Override
		protected void applySettings() throws CancelledException {
			copySettings(getSettings(), mySettings, getSettingsDefinitions());
		}
	}

	private void typeSettingsActivated(VarActionContext<?> ctx) {
		VarRow row = ctx.getSelection().getFirst();
		DataType type = row.getType();
		if (type == null) {
			return;
		}
		tool.showDialog(new VarDataSettingsDialog(row.getType(), row.getSettings()));
		// It is modal
		row.settingsChanged();
		if (row instanceof InputRow) {
			inputsTableModel.fireTableDataChanged();
		}
		else {
			outputsTableModel.fireTableDataChanged();
		}
	}

	protected void initializeVarTables() {
		doRefreshInputs();
		doRefreshOutputs();
	}

	protected GTable containingTable(Component c) {
		for (Component p = c; p != null; p = p.getParent()) {
			if (p == inputsTable) {
				return inputsTable;
			}
			if (p == outputsTable) {
				return outputsTable;
			}
		}
		return null;
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		if (event == null) {
			return super.getActionContext(event);
		}
		GTable table = containingTable(event.getComponent());
		if (table == inputsTable) {
			return inputActions.getActionContext(event);
		}
		else if (table == outputsTable) {
			return outputActions.getActionContext(event);
		}
		return super.getActionContext(event);
	}

	@Override
	protected void okCallback() {
		super.okCallback();

		clearStatusText();

		DebuggerTraceManagerService traceManager =
			tool.getService(DebuggerTraceManagerService.class);
		DebuggerControlService controlService = tool.getService(DebuggerControlService.class);

		executeProgressTask(new Task("Emulate", true, false, false, false) {
			@Override
			public void run(TaskMonitor monitor) throws CancelledException {
				monitor.setMessage("Starting");
				try (FunctionEmulationHarness harness =
					FunctionEmulationHarness.start(tool, function, monitor)) {
					/**
					 * Sentinel placement precedes input initialization, because 1) The user's say
					 * should override anything we do automatically, though it may be a foot gun,
					 * and 2) input initialization commits the state to the trace. We'd have to
					 * commit again were we to place the sentinel after.
					 */
					monitor.setMessage("Placing end breakpoint");
					harness.placeSentinel(sentinel);
					monitor.setMessage("Initializing inputs");
					initializeInputs(harness.init());
					monitor.setMessage("Installing injects");
					harness.installInjects();
					monitor.setMessage("Emulating");
					EmulationResult result = harness.run(snapshotPeriod);
					if (result.error() != null) {
						setStatusText("Emulation Error: %s".formatted(result.error().getMessage()),
							MessageType.ERROR);
					}
					else if (!sentinel.equals(harness.emuThread.getCounter())) {
						setStatusText("Emulator interrupted before completion", MessageType.ERROR);
					}
					monitor.setMessage("Capturing Outputs");
					captureOutputs(harness.eval(result.snap()), harness.getProbesOut());

					if (snapshotPeriod != 0) {
						if (traceManager != null) {
							monitor.setMessage("Opening Trace");
							traceManager.openTrace(harness.trace);
							traceManager.activate(DebuggerCoordinates.NOWHERE
									.trace(harness.trace)
									.snap(result.defaultSnap()));
						}

						if (controlService != null) {
							controlService.setCurrentMode(harness.trace, ControlMode.RW_EMULATOR);
						}
					}
				}
				catch (Exception e) {
					setStatusText(e.getMessage(), MessageType.ERROR);
					Msg.error(this, "Emulation Setup Error", e);
				}
			}
		}, 500);
	}

	class InputInitializer {
		final Eval eval;
		final Collection<InputRow> inputs;
		final Map<String, InputRow> remains;

		public InputInitializer(Eval eval, Collection<InputRow> inputs) {
			this.eval = eval;
			this.inputs = inputs;
			this.remains = inputs
					.stream()
					.collect(Collectors.toMap(InputRow::getName,
						java.util.function.Function.identity()));
		}

		public void initializeInputs() {
			for (InputRow input : inputs) {
				initializeInput(input);
			}
		}

		public void initializeInput(InputRow input) {
			if (remains.remove(input.name) == null) {
				return;
			}
			doInitialize(input);
		}

		public void doInitialize(InputRow input) {
			initializeDependencies(input);
			eval.writeVariable(input.storage, input.value);
		}

		public void initializeDependency(String name) {
			InputRow input = remains.remove(name);
			if (input == null) {
				return;
			}
			doInitialize(input);
		}

		public void initializeDependencies(InputRow input) {
			for (String dep : input.depsByName) {
				initializeDependency(dep);
			}
		}

		public String toHex(byte[] value, int length) {
			return Utils.bytesToBigInteger(value, length, language.isBigEndian(), false)
					.toString(16);
		}

		public void checkConflicts() {
			for (InputRow r : inputs) {
				LocAndVal value = eval.readVariable(r.storage);
				if (!(Arrays.equals(value.value(), r.value))) {
					throw new IllegalStateException("Input %s conflicts: 0x%s != 0x%s".formatted(
						r.storage, toHex(r.value, r.length), toHex(value.value(), r.length)));
				}
			}
		}
	}

	protected void initializeInputs(Eval eval) {
		InputInitializer initializer = new InputInitializer(eval, inputsTableModel.getModelData());
		initializer.initializeInputs();
		initializer.checkConflicts();
		eval.commit();
	}

	protected void captureOutputs(Eval eval, List<ProbeOut> probesOut) {
		for (OutputRow r : outputsTableModel.copyModelData()) {
			if (r.name.startsWith(PREFIX_PROBE)) {
				outputsTableModel.delete(r);
			}
			else {
				LocAndVal value = eval.readVariable(r.storage);
				r.setValue(value.value());
			}
		}
		CompilerSpec cSpec = function.getProgram().getCompilerSpec();
		for (int i = 0; i < probesOut.size(); i++) {
			ProbeOut po = probesOut.get(i);
			OutputRow row = new OutputRow(language, FMT_PROBE.formatted(i + 1),
				VarStorage.fromPieces(new Varnode[] { po.vn() }, cSpec), null);
			row.setValue(po.value());
			outputsTableModel.add(row);
		}
		Swing.runLater(outputsTableModel::fireTableDataChanged);
	}
}
