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
package ghidra.app.plugin.core.debug.gui.pcode;

import java.awt.*;
import java.math.BigInteger;
import java.util.*;
import java.util.List;
import java.util.function.BiConsumer;
import java.util.function.Function;
import java.util.stream.Collectors;

import javax.swing.*;
import javax.swing.table.*;

import org.apache.commons.lang3.StringUtils;

import docking.action.DockingAction;
import docking.widgets.table.*;
import docking.widgets.table.DefaultEnumeratedColumnTableModel.EnumeratedTableColumn;
import ghidra.GhidraOptions;
import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.gui.pcode.UniqueRow.RefType;
import ghidra.app.plugin.core.debug.service.emulation.DebuggerTracePcodeEmulator;
import ghidra.app.services.DebuggerEmulationService;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.async.SwingExecutorService;
import ghidra.base.widgets.table.DataTypeTableCellEditor;
import ghidra.docking.settings.Settings;
import ghidra.framework.options.AutoOptions;
import ghidra.framework.options.annotation.*;
import ghidra.framework.plugintool.AutoService;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.exec.PcodeExecutorState;
import ghidra.pcode.exec.PcodeFrame;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.Language;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.trace.model.Trace;
import ghidra.trace.model.time.TraceSchedule;
import ghidra.util.ColorUtils;
import ghidra.util.HTMLUtilities;
import ghidra.util.database.UndoableTransaction;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.GhidraTableFilterPanel;
import ghidra.util.table.column.AbstractGColumnRenderer;

public class DebuggerPcodeStepperProvider extends ComponentProviderAdapter {
	private static final String BACKGROUND_COLOR = "Background Color";
	private static final String ADDRESS_COLOR = "Address Color";
	private static final String CONSTANT_COLOR = "Constant Color";
	private static final String REGISTERS_COLOR = "Registers Color";
	private static final String LABELS_LOCAL_COLOR = "Labels, Local Color";
	private static final String MNEMONIC_COLOR = "Mnemonic Color";

	protected static final Comparator<Varnode> UNIQUE_COMPARATOR = (u1, u2) -> {
		assert u1.isUnique() && u2.isUnique();
		return u1.getAddress().compareTo(u2.getAddress());
	};

	protected enum PcodeTableColumns implements EnumeratedTableColumn<PcodeTableColumns, PcodeRow> {
		SEQUENCE("Sequence", Integer.class, PcodeRow::getSequence),
		CODE("Code", String.class, PcodeRow::getCode);

		private final String header;
		private final Function<PcodeRow, ?> getter;
		private final Class<?> cls;

		<T> PcodeTableColumns(String header, Class<T> cls, Function<PcodeRow, T> getter) {
			this.header = header;
			this.cls = cls;
			this.getter = getter;
		}

		@Override
		public String getHeader() {
			return header;
		}

		@Override
		public Class<?> getValueClass() {
			return cls;
		}

		@Override
		public Object getValueOf(PcodeRow row) {
			return getter.apply(row);
		}

		@Override
		public boolean isSortable() {
			return this == SEQUENCE; // HACK
		}
	}

	protected static class PcodeTableModel
			extends DefaultEnumeratedColumnTableModel<PcodeTableColumns, PcodeRow> {
		public PcodeTableModel() {
			super("p-code", PcodeTableColumns.class);
		}

		@Override
		public List<PcodeTableColumns> defaultSortOrder() {
			return List.of(PcodeTableColumns.SEQUENCE);
		}
	}

	protected enum UniqueTableColumns
		implements EnumeratedTableColumn<UniqueTableColumns, UniqueRow> {
		REF("Ref", RefType.class, UniqueRow::getRefType),
		UNIQUE("Unique", String.class, UniqueRow::getName),
		BYTES("Bytes", String.class, UniqueRow::getBytes),
		VALUE("Value", BigInteger.class, UniqueRow::getValue),
		TYPE("Type", DataType.class, UniqueRow::getDataType, UniqueRow::setDataType),
		REPR("Repr", String.class, UniqueRow::getValueRepresentation);

		private final String header;
		private final Function<UniqueRow, ?> getter;
		private final BiConsumer<UniqueRow, Object> setter;
		private final Class<?> cls;

		@SuppressWarnings("unchecked")
		<T> UniqueTableColumns(String header, Class<T> cls, Function<UniqueRow, T> getter,
				BiConsumer<UniqueRow, T> setter) {
			this.header = header;
			this.cls = cls;
			this.getter = getter;
			this.setter = (BiConsumer<UniqueRow, Object>) setter;
		}

		<T> UniqueTableColumns(String header, Class<T> cls, Function<UniqueRow, T> getter) {
			this(header, cls, getter, null);
		}

		@Override
		public Class<?> getValueClass() {
			return cls;
		}

		@Override
		public Object getValueOf(UniqueRow row) {
			return getter.apply(row);
		}

		@Override
		public String getHeader() {
			return header;
		}

		@Override
		public void setValueOf(UniqueRow row, Object value) {
			setter.accept(row, value);
		}

		@Override
		public boolean isEditable(UniqueRow row) {
			return setter != null;
		}
	}

	protected static class UniqueTableModel
			extends DefaultEnumeratedColumnTableModel<UniqueTableColumns, UniqueRow> {
		public UniqueTableModel() {
			super("Unique", UniqueTableColumns.class);
		}

		@Override
		public List<UniqueTableColumns> defaultSortOrder() {
			return List.of(UniqueTableColumns.UNIQUE);
		}
	}

	class UniqueDataTypeEditor extends DataTypeTableCellEditor {
		public UniqueDataTypeEditor() {
			super(plugin.getTool());
		}

		@Override
		protected DataType resolveSelection(DataType dataType) {
			if (dataType == null) {
				return null;
			}
			try (UndoableTransaction tid =
				UndoableTransaction.start(current.getTrace(), "Resolve DataType", true)) {
				return current.getTrace().getDataTypeManager().resolve(dataType, null);
			}
		}
	}

	class CounterBackgroundCellRenderer extends AbstractGColumnRenderer<String> {
		Color foregroundColor = getForeground();

		@Override
		public Component getTableCellRendererComponent(GTableCellRenderingData data) {
			super.getTableCellRendererComponent(data);
			setForeground(pcodeTable.getForeground());
			boolean isCurrent = counter == data.getRowModelIndex();
			if (data.isSelected()) {
				if (isCurrent) {
					setBackground(ColorUtils.blend(counterColor, cursorColor, 0.5f));
				}
				// else background is already set. Leave it alone
			}
			else if (isCurrent) {
				setBackground(counterColor);
			}
			else {
				setBackground(pcodeTable.getBackground());
				setOpaque(true);
			}
			setBorder(noFocusBorder);
			return this;
		}

		@Override
		public String getFilterString(String t, Settings settings) {
			return t;
		}
	}

	class PcodeCellRenderer extends CounterBackgroundCellRenderer {
		{
			setHTMLRenderingEnabled(true);
		}

		@Override
		protected void configureFont(JTable table, TableModel model, int column) {
			setFont(fixedWidthFont);
		}

		@Override
		public Component getTableCellRendererComponent(GTableCellRenderingData data) {
			super.getTableCellRendererComponent(data);
			setText(injectStyle(getText()));
			return this;
		}

		String injectStyle(String html) {
			if (StringUtils.startsWithIgnoreCase(html, "<html>")) {
				return style + html.substring("<html>".length());
			}
			return html;
		}
	}

	class UniqueRefCellRenderer extends AbstractGColumnRenderer<RefType> {
		@Override
		public Component getTableCellRendererComponent(GTableCellRenderingData data) {
			super.getTableCellRendererComponent(data);
			setText("");
			switch ((RefType) data.getValue()) {
				case NONE:
					setIcon(null);
					break;
				case READ:
					setIcon(DebuggerResources.ICON_UNIQUE_REF_READ);
					break;
				case WRITE:
					setIcon(DebuggerResources.ICON_UNIQUE_REF_WRITE);
					break;
				case READ_WRITE:
					setIcon(DebuggerResources.ICON_UNIQUE_REF_RW);
					break;
				default:
					throw new AssertionError();
			}
			return this;
		}

		@Override
		public String getFilterString(RefType t, Settings settings) {
			return t.name();
		}
	}

	protected static String createColoredStyle(String cls, Color color) {
		if (color == null) {
			return "";
		}
		return " ." + cls + " { color:" + HTMLUtilities.toHexString(color) + "; }";
	}

	protected static boolean sameCoordinates(DebuggerCoordinates a, DebuggerCoordinates b) {
		if (!Objects.equals(a.getTrace(), b.getTrace())) {
			return false;
		}
		if (!Objects.equals(a.getTime(), b.getTime())) {
			return false;
		}
		if (!Objects.equals(a.getThread(), b.getThread())) {
			return false;
		}
		return true;
	}

	private final DebuggerPcodeStepperPlugin plugin;

	DebuggerCoordinates current = DebuggerCoordinates.NOWHERE;
	DebuggerCoordinates previous = DebuggerCoordinates.NOWHERE;
	int counter;

	@AutoServiceConsumed
	private DebuggerTraceManagerService traceManager;
	@AutoServiceConsumed // NB. also by method
	private DebuggerEmulationService emulationService;
	@SuppressWarnings("unused")
	private AutoService.Wiring autoServiceWiring;

	@AutoOptionDefined(
		name = DebuggerResources.OPTION_NAME_COLORS_PCODE_COUNTER,
		description = "Background color for the current p-code operation",
		help = @HelpInfo(anchor = "colors"))
	private Color counterColor = DebuggerResources.DEFAULT_COLOR_PCODE_COUNTER;

	private Color backgroundColor;
	private Color cursorColor;
	private Color addressColor;
	private Color constantColor;
	private Color registerColor;
	private Color uniqueColor;
	private Color opColor;

	@SuppressWarnings("unused")
	private AutoOptions.Wiring autoOptionsWiring;

	String style = "<html>";

	JSplitPane mainPanel = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);

	GhidraTable uniqueTable;
	UniqueTableModel uniqueTableModel = new UniqueTableModel();
	private GhidraTableFilterPanel<UniqueRow> uniqueFilterPanel;

	GhidraTable pcodeTable;
	PcodeTableModel pcodeTableModel = new PcodeTableModel();
	// No filter panel on p-code

	DockingAction actionStepBackward;
	DockingAction actionStepForward;

	public DebuggerPcodeStepperProvider(DebuggerPcodeStepperPlugin plugin) {
		super(plugin.getTool(), DebuggerResources.TITLE_PROVIDER_PCODE, plugin.getName(), null);
		this.plugin = plugin;

		this.autoServiceWiring = AutoService.wireServicesConsumed(plugin, this);
		this.autoOptionsWiring = AutoOptions.wireOptions(plugin, this);

		setIcon(DebuggerResources.ICON_PROVIDER_PCODE);
		setHelpLocation(DebuggerResources.HELP_PROVIDER_PCODE);
		setWindowMenuGroup(DebuggerPluginPackage.NAME);

		buildMainPanel();

		createActions();

		setVisible(true);
		contextChanged();
	}

	@AutoOptionConsumed(
		name = DebuggerResources.OPTION_NAME_COLORS_PCODE_COUNTER)
	private void setCounterColor() {
		pcodeTableModel.fireTableDataChanged();
	}

	@AutoOptionConsumed(
		category = GhidraOptions.CATEGORY_BROWSER_DISPLAY,
		name = BACKGROUND_COLOR)
	private void setBackgroundColor(Color backgroundColor) {
		this.backgroundColor = backgroundColor;
		if (pcodeTable != null) {
			pcodeTable.setBackground(backgroundColor);
		}
	}

	@AutoOptionConsumed(
		category = GhidraOptions.CATEGORY_BROWSER_FIELDS,
		name = GhidraOptions.HIGHLIGHT_CURSOR_LINE_COLOR)
	private void setCursorColor(Color cursorColor) {
		this.cursorColor = cursorColor;
		if (pcodeTable != null) {
			pcodeTable.setSelectionBackground(cursorColor);
		}
	}

	@AutoOptionConsumed(
		category = GhidraOptions.CATEGORY_BROWSER_DISPLAY,
		name = ADDRESS_COLOR)
	private void setAddressColor(Color addressColor) {
		this.addressColor = addressColor;
		recomputeStyle();
	}

	@AutoOptionConsumed(
		category = GhidraOptions.CATEGORY_BROWSER_DISPLAY,
		name = CONSTANT_COLOR)
	private void setConstantColor(Color constantColor) {
		this.constantColor = constantColor;
		recomputeStyle();
	}

	@AutoOptionConsumed(
		category = GhidraOptions.CATEGORY_BROWSER_DISPLAY,
		name = REGISTERS_COLOR)
	private void setRegisterColor(Color registerColor) {
		this.registerColor = registerColor;
		recomputeStyle();
	}

	@AutoOptionConsumed(
		category = GhidraOptions.CATEGORY_BROWSER_DISPLAY,
		name = LABELS_LOCAL_COLOR)
	private void setUniqueColor(Color uniqueColor) {
		this.uniqueColor = uniqueColor;
		recomputeStyle();
	}

	@AutoOptionConsumed(
		category = GhidraOptions.CATEGORY_BROWSER_DISPLAY,
		name = MNEMONIC_COLOR)
	private void setOpColor(Color opColor) {
		this.opColor = opColor;
		recomputeStyle();
	}

	protected void recomputeStyle() {
		StringBuilder sb = new StringBuilder("<html><head><style>");
		sb.append(createColoredStyle("address", addressColor));
		sb.append(createColoredStyle("constant", constantColor));
		sb.append(createColoredStyle("register", registerColor));
		sb.append(createColoredStyle("unique", uniqueColor));
		sb.append(createColoredStyle("op", opColor));
		sb.append("</style></head>"); // NB. </html> should already be at end
		style = sb.toString();
		pcodeTableModel.fireTableDataChanged();
	}

	protected void buildMainPanel() {
		JPanel pcodePanel = new JPanel(new BorderLayout());
		pcodeTable = new GhidraTable(pcodeTableModel);
		pcodePanel.add(new JScrollPane(pcodeTable));
		mainPanel.setLeftComponent(pcodePanel);

		JPanel uniquePanel = new JPanel(new BorderLayout());
		uniqueTable = new GhidraTable(uniqueTableModel);
		uniquePanel.add(new JScrollPane(uniqueTable));
		uniqueFilterPanel = new GhidraTableFilterPanel<>(uniqueTable, uniqueTableModel);
		uniquePanel.add(uniqueFilterPanel, BorderLayout.SOUTH);
		mainPanel.setRightComponent(uniquePanel);

		pcodeTable.setTableHeader(null);
		pcodeTable.setBackground(backgroundColor);
		pcodeTable.setSelectionBackground(cursorColor);
		pcodeTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		pcodeTable.getSelectionModel().addListSelectionListener(evt -> {
			if (evt.getValueIsAdjusting()) {
				return;
			}
			uniqueTableModel.fireTableDataChanged();
		});

		TableColumnModel pcodeColModel = pcodeTable.getColumnModel();
		TableColumn seqCol = pcodeColModel.getColumn(PcodeTableColumns.SEQUENCE.ordinal());
		seqCol.setCellRenderer(new CounterBackgroundCellRenderer());
		seqCol.setMinWidth(24);
		seqCol.setMaxWidth(24);
		TableColumn codeCol = pcodeColModel.getColumn(PcodeTableColumns.CODE.ordinal());
		codeCol.setCellRenderer(new PcodeCellRenderer());
		//codeCol.setPreferredWidth(75);

		TableColumnModel uniqueColModel = uniqueTable.getColumnModel();
		TableColumn refCol = uniqueColModel.getColumn(UniqueTableColumns.REF.ordinal());
		refCol.setCellRenderer(new UniqueRefCellRenderer());
		refCol.setMinWidth(24);
		refCol.setMaxWidth(24);
		TableColumn uniqCol = uniqueColModel.getColumn(UniqueTableColumns.UNIQUE.ordinal());
		uniqCol.setPreferredWidth(45);
		TableColumn bytesCol = uniqueColModel.getColumn(UniqueTableColumns.BYTES.ordinal());
		bytesCol.setCellRenderer(CustomToStringCellRenderer.MONO_OBJECT);
		bytesCol.setPreferredWidth(65);
		TableColumn valCol = uniqueColModel.getColumn(UniqueTableColumns.VALUE.ordinal());
		valCol.setCellRenderer(CustomToStringCellRenderer.MONO_BIG_HEX); // TODO: Changed coloring
		valCol.setPreferredWidth(45);
		TableColumn typeCol = uniqueColModel.getColumn(UniqueTableColumns.TYPE.ordinal());
		typeCol.setCellEditor(new UniqueDataTypeEditor());
		typeCol.setPreferredWidth(45);
		TableColumn reprCol = uniqueColModel.getColumn(UniqueTableColumns.REPR.ordinal());
		reprCol.setPreferredWidth(45);
	}

	protected void createActions() {
		actionStepBackward = DebuggerResources.StepPcodeBackwardAction.builder(plugin)
				.enabledWhen(c -> current.getTrace() != null && current.getTime().pTickCount() != 0)
				.onAction(c -> stepBackwardActivated())
				.buildAndInstallLocal(this);
		actionStepForward = DebuggerResources.StepPcodeForwardAction.builder(plugin)
				.enabledWhen(
					c -> current.getThread() != null)
				.onAction(c -> stepForwardActivated())
				.buildAndInstallLocal(this);
	}

	private void stepBackwardActivated() {
		if (current.getTrace() == null) {
			return;
		}
		TraceSchedule time = current.getTime().steppedPcodeBackward(1);
		if (time == null) {
			return;
		}
		traceManager.activateTime(time);
	}

	private void stepForwardActivated() {
		if (current.getThread() == null) {
			return;
		}
		TraceSchedule time = current.getTime().steppedPcodeForward(current.getThread(), 1);
		traceManager.activateTime(time);
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}

	public void coordinatesActivated(DebuggerCoordinates coordinates) {
		if (sameCoordinates(current, coordinates)) {
			current = coordinates;
			return;
		}
		previous = current;
		current = coordinates;

		doLoadPcodeFrame();

		setSubTitle(current.getTime().toString());

		contextChanged();
	}

	protected void populateSingleton(PcodeRow row) {
		counter = 0;
		pcodeTableModel.clear();
		pcodeTableModel.add(row);
		uniqueTableModel.clear();
	}

	protected void populateFromFrame(PcodeFrame frame, PcodeExecutorState<byte[]> state) {
		populatePcode(frame);
		populateUnique(frame, state);
	}

	protected void populatePcode(PcodeFrame frame) {
		Language language = current.getTrace().getBaseLanguage();
		int index = frame.index();
		List<PcodeRow> toAdd = frame.getCode()
				.stream()
				.map(op -> new OpPcodeRow(language, op, index == op.getSeqnum().getTime()))
				.collect(Collectors.toCollection(ArrayList::new));
		if (frame.isBranch()) {
			counter = toAdd.size();
			toAdd.add(new BranchPcodeRow(counter, frame.getBranched()));
		}
		else if (frame.isFallThrough()) {
			counter = toAdd.size();
			toAdd.add(new FallthroughPcodeRow(counter));
		}
		else {
			counter = index;
		}
		pcodeTableModel.clear();
		pcodeTableModel.addAll(toAdd);
		pcodeTable.getSelectionModel().setSelectionInterval(counter, counter);
		pcodeTable.scrollToSelectedRow();
	}

	protected void populateUnique(PcodeFrame frame, PcodeExecutorState<byte[]> state) {
		Language language = current.getTrace().getBaseLanguage();
		// NOTE: They may overlap. I don't think I care.
		Set<Varnode> uniques = new TreeSet<>(UNIQUE_COMPARATOR);
		for (PcodeOp op : frame.getCode()) {
			Varnode out = op.getOutput();
			if (out != null && out.isUnique()) {
				uniques.add(out);
			}
			for (Varnode in : op.getInputs()) {
				if (in.isUnique()) {
					uniques.add(in);
				}
			}
		}
		// TODO: Highlight uniques that the selected op(s) reference
		//       (including overlaps)
		// TODO: Permit modification of unique variables
		List<UniqueRow> toAdd =
			uniques.stream()
					.map(u -> new UniqueRow(this, language, state, u))
					.collect(Collectors.toList());
		uniqueTableModel.clear();
		uniqueTableModel.addAll(toAdd);
	}

	protected void doLoadPcodeFrame() {
		if (emulationService == null) {
			return;
		}
		DebuggerCoordinates current = this.current; // Volatile, also after background
		Trace trace = current.getTrace();
		if (trace == null) {
			return;
		}
		if (current.getThread() == null) {
			populateSingleton(EnumPcodeRow.NO_THREAD);
			return;
		}
		TraceSchedule time = current.getTime();
		if (time.pTickCount() == 0) {
			populateSingleton(EnumPcodeRow.DECODE);
			return;
		}
		DebuggerTracePcodeEmulator emu = emulationService.getCachedEmulator(trace, time);
		if (emu != null) {
			doLoadPcodeFrameFromEmulator(emu);
			return;
		}
		emulationService.backgroundEmulate(trace, time).thenAcceptAsync(__ -> {
			if (current != this.current) {
				return;
			}
			doLoadPcodeFrameFromEmulator(emulationService.getCachedEmulator(trace, time));
		}, SwingExecutorService.INSTANCE);
	}

	protected void doLoadPcodeFrameFromEmulator(DebuggerTracePcodeEmulator emu) {
		PcodeThread<byte[]> thread = emu.getThread(current.getThread().getPath(), false);
		if (thread == null) {
			/**
			 * Happens when focus is on a thread not stepped in the schedule. Stepping it would
			 * create it and decode its first instruction.
			 */
			populateSingleton(EnumPcodeRow.DECODE);
			return;
		}
		PcodeFrame frame = thread.getFrame();
		if (frame == null) {
			/**
			 * Happens when an instruction is completed via p-code stepping, but the next
			 * instruction has not been decoded, yet.
			 */
			populateSingleton(EnumPcodeRow.DECODE);
			return;
		}
		populateFromFrame(frame, thread.getState());
	}

	@AutoServiceConsumed
	private void setEmulationService(DebuggerEmulationService emulationService) {
		doLoadPcodeFrame();
	}
}
