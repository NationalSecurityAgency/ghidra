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
package ghidra.app.plugin.core.debug.gui.register;

import java.awt.*;
import java.awt.event.*;
import java.math.BigInteger;
import java.util.*;
import java.util.List;
import java.util.Map.Entry;
import java.util.concurrent.CompletableFuture;
import java.util.function.*;
import java.util.stream.Collectors;

import javax.swing.*;
import javax.swing.table.TableColumn;
import javax.swing.table.TableColumnModel;

import org.apache.commons.lang3.exception.ExceptionUtils;

import com.google.common.collect.Range;

import docking.*;
import docking.action.*;
import docking.action.builder.ActionBuilder;
import docking.actions.PopupActionProvider;
import docking.widgets.table.*;
import docking.widgets.table.ColumnSortState.SortDirection;
import docking.widgets.table.DefaultEnumeratedColumnTableModel.EnumeratedTableColumn;
import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.gui.DebuggerProvider;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.mapping.DebuggerRegisterMapper;
import ghidra.app.services.*;
import ghidra.async.AsyncLazyValue;
import ghidra.async.AsyncUtils;
import ghidra.base.widgets.table.DataTypeTableCellEditor;
import ghidra.dbg.error.DebuggerModelAccessException;
import ghidra.dbg.target.TargetRegisterBank;
import ghidra.dbg.target.TargetThread;
import ghidra.framework.model.DomainObject;
import ghidra.framework.model.DomainObjectChangeRecord;
import ghidra.framework.options.AutoOptions;
import ghidra.framework.options.SaveState;
import ghidra.framework.options.annotation.*;
import ghidra.framework.plugintool.AutoService;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictException;
import ghidra.program.model.lang.*;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.trace.model.*;
import ghidra.trace.model.Trace.*;
import ghidra.trace.model.listing.*;
import ghidra.trace.model.memory.TraceMemoryRegisterSpace;
import ghidra.trace.model.memory.TraceMemoryState;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.util.*;
import ghidra.util.Msg;
import ghidra.util.Swing;
import ghidra.util.data.DataTypeParser.AllowedDataTypes;
import ghidra.util.database.UndoableTransaction;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.GhidraTableFilterPanel;
import ghidra.util.task.TaskMonitor;

public class DebuggerRegistersProvider extends ComponentProviderAdapter
		implements DebuggerProvider, PopupActionProvider {
	private static final String KEY_DEBUGGER_COORDINATES = "DebuggerCoordinates";

	protected enum RegisterTableColumns
		implements EnumeratedTableColumn<RegisterTableColumns, RegisterRow> {
		FAV("Fav", Boolean.class, RegisterRow::isFavorite, RegisterRow::setFavorite, r -> true, SortDirection.DESCENDING),
		NUMBER("#", Integer.class, RegisterRow::getNumber),
		NAME("Name", String.class, RegisterRow::getName),
		VALUE("Value", BigInteger.class, RegisterRow::getValue, RegisterRow::setValue, RegisterRow::isValueEditable, SortDirection.ASCENDING),
		TYPE("Type", DataType.class, RegisterRow::getDataType, RegisterRow::setDataType, r -> true, SortDirection.ASCENDING),
		REPR("Repr", String.class, RegisterRow::getRepresentation);

		private final String header;
		private final Function<RegisterRow, ?> getter;
		private final BiConsumer<RegisterRow, Object> setter;
		private final Predicate<RegisterRow> editable;
		private final Class<?> cls;
		private final SortDirection direction;

		<T> RegisterTableColumns(String header, Class<T> cls, Function<RegisterRow, T> getter) {
			this(header, cls, getter, null, null, SortDirection.ASCENDING);
		}

		@SuppressWarnings("unchecked")
		<T> RegisterTableColumns(String header, Class<T> cls, Function<RegisterRow, T> getter,
				BiConsumer<RegisterRow, T> setter, Predicate<RegisterRow> editable,
				SortDirection direction) {
			this.header = header;
			this.cls = cls;
			this.getter = getter;
			this.setter = (BiConsumer<RegisterRow, Object>) setter;
			this.editable = editable;
			this.direction = direction;
		}

		@Override
		public Class<?> getValueClass() {
			return cls;
		}

		@Override
		public Object getValueOf(RegisterRow row) {
			return getter.apply(row);
		}

		@Override
		public String getHeader() {
			return header;
		}

		@Override
		public boolean isEditable(RegisterRow row) {
			return editable != null && editable.test(row);
		}

		@Override
		public void setValueOf(RegisterRow row, Object value) {
			setter.accept(row, value);
		}

		@Override
		public SortDirection defaultSortDirection() {
			return direction;
		}
	}

	protected static class RegistersTableModel
			extends DefaultEnumeratedColumnTableModel<RegisterTableColumns, RegisterRow> {
		public RegistersTableModel() {
			super("Registers", RegisterTableColumns.class);
		}

		@Override
		public List<RegisterTableColumns> defaultSortOrder() {
			return List.of(RegisterTableColumns.FAV, RegisterTableColumns.NUMBER);
		}
	}

	protected static boolean sameCoordinates(DebuggerCoordinates a, DebuggerCoordinates b) {
		if (!Objects.equals(a.getTrace(), b.getTrace())) {
			return false;
		}
		if (!Objects.equals(a.getRecorder(), b.getRecorder())) {
			return false; // For live read/writes
		}
		if (!Objects.equals(a.getThread(), b.getThread())) {
			return false;
		}
		if (!Objects.equals(a.getTime(), b.getTime())) {
			return false;
		}
		if (!Objects.equals(a.getFrame(), b.getFrame())) {
			return false;
		}
		return true;
	}

	class TraceChangeListener extends TraceDomainObjectListener {
		public TraceChangeListener() {
			listenForUntyped(DomainObject.DO_OBJECT_RESTORED, e -> objectRestored(e));
			listenFor(TraceMemoryBytesChangeType.CHANGED, this::registerValueChanged);
			listenFor(TraceMemoryStateChangeType.CHANGED, this::registerStateChanged);
			listenFor(TraceCodeChangeType.ADDED, this::registerTypeAdded);
			listenFor(TraceCodeChangeType.DATA_TYPE_REPLACED, this::registerTypeReplaced);
			listenFor(TraceCodeChangeType.LIFESPAN_CHANGED, this::registerTypeLifespanChanged);
			listenFor(TraceCodeChangeType.REMOVED, this::registerTypeRemoved);
			listenFor(TraceThreadChangeType.DELETED, this::threadDeleted);
			listenFor(TraceThreadChangeType.LIFESPAN_CHANGED, this::threadDestroyed);
		}

		private boolean isVisible(TraceAddressSpace space) {
			TraceThread curThread = current.getThread();
			if (curThread == null) {
				return false;
			}
			if (space.getThread() != curThread) {
				return false;
			}
			if (space.getFrameLevel() != current.getFrame()) {
				return false;
			}
			return true;
		}

		private boolean isVisible(TraceAddressSpace space, TraceAddressSnapRange range) {
			if (!isVisible(space)) {
				return false;
			}
			TraceProgramView view = current.getView();
			if (view == null || !view.getViewport().containsAnyUpper(range.getLifespan())) {
				return false;
			}
			// Probably not worth checking for occlusion here. Just a little refresh waste.
			return true;
		}

		private void refreshRange(AddressRange range) {
			TraceMemoryRegisterSpace space = getRegisterMemorySpace(false);
			// ...   If I got an event for it, it ought to exist.
			assert space != null;

			// TODO: Just certain rows?
			regsTableModel.fireTableDataChanged();
		}

		private void objectRestored(DomainObjectChangeRecord rec) {
			coordinatesActivated(current.withReFoundThread());
		}

		private void registerValueChanged(TraceAddressSpace space, TraceAddressSnapRange range,
				byte[] oldIsNull, byte[] newVal) {
			if (!isVisible(space, range)) {
				return;
			}
			refreshRange(range.getRange());
		}

		private void registerStateChanged(TraceAddressSpace space, TraceAddressSnapRange range,
				TraceMemoryState oldState, TraceMemoryState newState) {
			if (!isVisible(space, range)) {
				return;
			}
			recomputeViewKnown();
			refreshRange(range.getRange());
		}

		private void registerTypeAdded(TraceAddressSpace space, TraceAddressSnapRange range,
				TraceCodeUnit oldIsNull, TraceCodeUnit newUnit) {
			if (!isVisible(space, range)) {
				return;
			}
			refreshRange(range.getRange());
		}

		private void registerTypeReplaced(TraceAddressSpace space, TraceAddressSnapRange range,
				long oldTypeID, long newTypeID) {
			if (!isVisible(space, range)) {
				return;
			}
			refreshRange(range.getRange());
		}

		private void registerTypeLifespanChanged(TraceAddressSpace space, TraceCodeUnit unit,
				Range<Long> oldSpan, Range<Long> newSpan) {
			if (!isVisible(space)) {
				return;
			}
			TraceProgramView view = current.getView();
			if (view == null) {
				return;
			}
			TraceTimeViewport viewport = view.getViewport();
			if (viewport.containsAnyUpper(oldSpan) == viewport.containsAnyUpper(newSpan)) {
				return;
			}
			// A little waste if occluded, but probably cheaper than checking.
			AddressRange range = new AddressRangeImpl(unit.getMinAddress(), unit.getMaxAddress());
			refreshRange(range); // Slightly wasteful, as we already have the data unit
		}

		private void registerTypeRemoved(TraceAddressSpace space, TraceAddressSnapRange range,
				TraceCodeUnit oldUnit, TraceCodeUnit newIsNull) {
			if (!isVisible(space)) {
				return;
			}
			refreshRange(range.getRange());
		}

		private void threadDeleted(TraceThread thread) {
			//checkEditsEnabled();
		}

		private void threadDestroyed(TraceThread thread, Range<Long> oldSpan, Range<Long> newSpan) {
			//checkEditsEnabled();
		}
	}

	class RegAccessListener implements TraceRecorderListener {
		@Override
		public void registerBankMapped(TraceRecorder recorder) {
			Swing.runIfSwingOrRunLater(() -> loadValues());
		}

		@Override
		public void registerAccessibilityChanged(TraceRecorder recorder) {
			Swing.runIfSwingOrRunLater(() -> loadValues());
		}
	}

	class RegisterValueCellRenderer extends HexBigIntegerTableCellRenderer {
		@Override
		public final Component getTableCellRendererComponent(GTableCellRenderingData data) {
			super.getTableCellRendererComponent(data);
			RegisterRow row = (RegisterRow) data.getRowObject();
			if (!row.isKnown()) {
				if (data.isSelected()) {
					setForeground(registerStaleSelColor);
				}
				else {
					setForeground(registerStaleColor);
				}
			}
			else if (row.isChanged()) {
				if (data.isSelected()) {
					setForeground(registerChangesSelColor);
				}
				else {
					setForeground(registerChangesColor);
				}
			}
			return this;
		}
	}

	class RegisterDataTypeEditor extends DataTypeTableCellEditor {
		public RegisterDataTypeEditor() {
			super(plugin.getTool());
		}

		@Override
		protected AllowedDataTypes getAllowed(int row, int column) {
			return AllowedDataTypes.FIXED_LENGTH;
		}

		@Override
		protected boolean validateSelection(DataType dataType) {
			RegisterRow row = regsTableModel.getModelData().get(regsTable.getEditingRow());
			if (row == null) {
				return false;
			}
			return dataType.getLength() == row.getRegister().getMinimumByteSize();
		}

		@Override
		protected DataType resolveSelection(DataType dataType) {
			if (dataType == null) {
				return null;
			}
			try (UndoableTransaction tid =
				UndoableTransaction.start(currentTrace, "Resolve DataType", true)) {
				return currentTrace.getDataTypeManager().resolve(dataType, null);
			}
		}
	}

	final DebuggerRegistersPlugin plugin;
	private final Map<CompilerSpec, LinkedHashSet<Register>> selectionByCSpec;
	private final Map<CompilerSpec, LinkedHashSet<Register>> favoritesByCSpec;
	private final boolean isClone;

	DebuggerCoordinates previous = DebuggerCoordinates.NOWHERE;
	DebuggerCoordinates current = DebuggerCoordinates.NOWHERE;
	private AsyncLazyValue<Void> readTheseCoords =
		new AsyncLazyValue<>(this::readRegistersIfLiveAndAccessible); /* "read" past tense */
	private Trace currentTrace; // Copy for transition
	private TraceRecorder currentRecorder; // Copy of transition

	@AutoServiceConsumed
	private DebuggerModelService modelService;
	@AutoServiceConsumed
	private DebuggerTraceManagerService traceManager;
	@AutoServiceConsumed
	private DebuggerListingService listingService;
	@AutoServiceConsumed
	private MarkerService markerService; // TODO: Mark address types (separate plugin?)
	@SuppressWarnings("unused")
	private final AutoService.Wiring autoServiceWiring;

	@AutoOptionDefined(
		name = DebuggerResources.OPTION_NAME_COLORS_REGISTER_STALE, //
		description = "Text color for registers whose value is not known", //
		help = @HelpInfo(anchor = "colors"))
	protected Color registerStaleColor = DebuggerResources.DEFAULT_COLOR_REGISTER_STALE;
	@AutoOptionDefined(
		name = DebuggerResources.OPTION_NAME_COLORS_REGISTER_STALE_SEL, //
		description = "Selected text color for registers whose value is not known", //
		help = @HelpInfo(anchor = "colors"))
	protected Color registerStaleSelColor = DebuggerResources.DEFAULT_COLOR_REGISTER_STALE_SEL;
	@AutoOptionDefined(
		name = DebuggerResources.OPTION_NAME_COLORS_REGISTER_CHANGED, //
		description = "Text color for registers whose value just changed", //
		help = @HelpInfo(anchor = "colors"))
	protected Color registerChangesColor = DebuggerResources.DEFAULT_COLOR_REGISTER_CHANGED;
	@AutoOptionDefined(
		name = DebuggerResources.OPTION_NAME_COLORS_REGISTER_CHANGED_SEL, //
		description = "Selected text color for registers whose value just changed", //
		help = @HelpInfo(anchor = "colors"))
	protected Color registerChangesSelColor = DebuggerResources.DEFAULT_COLOR_REGISTER_CHANGED_SEL;

	@SuppressWarnings("unused")
	private final AutoOptions.Wiring autoOptionsWiring;

	private final TraceChangeListener traceChangeListener = new TraceChangeListener();
	private final RegAccessListener regAccessListener = new RegAccessListener();

	private JPanel mainPanel = new JPanel(new BorderLayout());

	GhidraTable regsTable;
	RegistersTableModel regsTableModel = new RegistersTableModel();
	private GhidraTableFilterPanel<RegisterRow> regsFilterPanel;
	Map<Register, RegisterRow> regMap = new HashMap<>();

	private final DebuggerAvailableRegistersDialog availableRegsDialog;

	DockingAction actionSelectRegisters;
	DockingAction actionCreateSnapshot;
	ToggleDockingAction actionEnableEdits;
	DockingAction actionClearDataType;

	DebuggerRegisterActionContext myActionContext;
	AddressSetView viewKnown;

	protected DebuggerRegistersProvider(final DebuggerRegistersPlugin plugin,
			Map<CompilerSpec, LinkedHashSet<Register>> selectionByCSpec,
			Map<CompilerSpec, LinkedHashSet<Register>> favoritesByCSpec, boolean isClone) {
		super(plugin.getTool(), DebuggerResources.TITLE_PROVIDER_REGISTERS, plugin.getName());
		this.plugin = plugin;
		this.selectionByCSpec = selectionByCSpec;
		this.favoritesByCSpec = favoritesByCSpec;
		this.isClone = isClone;

		this.autoServiceWiring = AutoService.wireServicesConsumed(plugin, this);
		this.autoOptionsWiring = AutoOptions.wireOptions(plugin, this);

		setIcon(DebuggerResources.ICON_PROVIDER_REGISTERS);
		setHelpLocation(DebuggerResources.HELP_PROVIDER_REGISTERS);
		setWindowMenuGroup(DebuggerPluginPackage.NAME);

		buildMainPanel();

		plugin.getTool().addPopupActionProvider(this);

		availableRegsDialog = new DebuggerAvailableRegistersDialog(this);

		setDefaultWindowPosition(WindowPosition.RIGHT);
		createActions();

		if (isClone) {
			setTitle("[" + DebuggerResources.TITLE_PROVIDER_REGISTERS + "]");
			setWindowGroup("Debugger.Core.disconnected");
			setIntraGroupPosition(WindowPosition.STACK);
			mainPanel.setBorder(BorderFactory.createLineBorder(Color.ORANGE, 2));
			setTransient();
		}
		else {
			setTitle(DebuggerResources.TITLE_PROVIDER_REGISTERS);
			setWindowGroup("Debugger.Core");
		}

		setVisible(true);
		contextChanged();
	}

	@Override
	public void removeFromTool() {
		plugin.providerRemoved(this);
		plugin.getTool().removePopupActionProvider(this);
		super.removeFromTool();
	}

	protected void buildMainPanel() {
		regsTable = new GhidraTable(regsTableModel);
		// TODO: Allow multiple selection for copy, etc.?
		mainPanel.add(new JScrollPane(regsTable));
		regsFilterPanel = new GhidraTableFilterPanel<>(regsTable, regsTableModel);
		mainPanel.add(regsFilterPanel, BorderLayout.SOUTH);

		regsTable.getSelectionModel().addListSelectionListener(evt -> {
			myActionContext = new DebuggerRegisterActionContext(this,
				regsFilterPanel.getSelectedItem(), regsTable);
			contextChanged();
		});
		regsTable.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (e.getClickCount() == 2) {
					navigateToAddress();
				}
			}
		});
		regsTable.addKeyListener(new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				if (e.getKeyCode() == KeyEvent.VK_ENTER) {
					navigateToAddress();
				}
			}
		});

		TableColumnModel columnModel = regsTable.getColumnModel();
		TableColumn favCol = columnModel.getColumn(RegisterTableColumns.FAV.ordinal());
		favCol.setPreferredWidth(1);
		TableColumn numCol = columnModel.getColumn(RegisterTableColumns.NUMBER.ordinal());
		numCol.setPreferredWidth(1);
		TableColumn nameCol = columnModel.getColumn(RegisterTableColumns.NAME.ordinal());
		nameCol.setPreferredWidth(40);
		TableColumn valCol = columnModel.getColumn(RegisterTableColumns.VALUE.ordinal());
		valCol.setCellRenderer(new RegisterValueCellRenderer());
		valCol.setCellEditor(new HexBigIntegerTableCellEditor());
		valCol.setPreferredWidth(100);
		TableColumn typeCol = columnModel.getColumn(RegisterTableColumns.TYPE.ordinal());
		typeCol.setCellEditor(new RegisterDataTypeEditor());
		typeCol.setPreferredWidth(50);
		TableColumn reprCol = columnModel.getColumn(RegisterTableColumns.REPR.ordinal());
		reprCol.setPreferredWidth(100);
	}

	@Override
	public List<DockingActionIf> getPopupActions(Tool t, ActionContext context) {
		if (context != myActionContext || context == null || listingService == null) {
			return List.of();
		}
		Register register = myActionContext.getSelected().getRegister();
		BigInteger value = getRegisterValue(register);
		if (value == null) {
			return List.of();
		}
		long lv = value.longValue();
		List<DockingActionIf> result = new ArrayList<>();
		String pluginName = plugin.getName();
		for (AddressSpace space : currentTrace.getBaseAddressFactory().getAddressSpaces()) {
			if (space.isRegisterSpace()) {
				continue;
			}
			Address address;
			try {
				address = space.getAddress(lv);
			}
			catch (AddressOutOfBoundsException e) {
				continue;
			}
			if (currentTrace.getMemoryManager()
					.getRegionContaining(current.getSnap(), address) == null) {
				continue;
			}
			String name = "Goto " + address.toString(true);
			result.add(new ActionBuilder(name, pluginName).popupMenuPath(name).onAction(ctx -> {
				if (listingService == null) {
					return;
				}
				listingService.goTo(address, true);
			}).build());
		}
		return result;
	}

	protected void navigateToAddress() {
		if (listingService == null || myActionContext == null) {
			return;
		}
		RegisterRow row = myActionContext.getSelected();
		TraceData data = getRegisterData(row.getRegister());
		if (data == null || data.getValueClass() != Address.class) {
			return;
		}
		Address address = (Address) TraceRegisterUtils.getValueHackPointer(data);
		if (address == null) {
			return;
		}
		listingService.goTo(address, true);
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		if (myActionContext == null) {
			return super.getActionContext(event);
		}
		return myActionContext;
	}

	protected void createActions() {
		actionSelectRegisters = DebuggerResources.SelectRegistersAction.builder(plugin)
				.enabledWhen(c -> current.getThread() != null)
				.onAction(c -> selectRegistersActivated())
				.buildAndInstallLocal(this);
		if (!isClone) {
			actionCreateSnapshot = DebuggerResources.CreateSnapshotAction.builder(plugin)
					.enabledWhen(c -> current.getThread() != null)
					.onAction(c -> createSnapshotActivated())
					.buildAndInstallLocal(this);
		}
		actionEnableEdits = DebuggerResources.EnableRegisterEditsAction.builder(plugin)
				.enabledWhen(c -> current.getThread() != null)
				.onAction(c -> {
				})
				.buildAndInstallLocal(this);
		actionClearDataType = new ActionBuilder("Clear Register Type", plugin.getName())
				.enabledWhen(c -> current.getThread() != null)
				.keyBinding(KeyStroke.getKeyStroke(KeyEvent.VK_DELETE, 0))
				.onAction(c -> clearDataTypeActivated())
				.buildAndInstallLocal(this);
	}

	private void selectRegistersActivated() {
		TraceThread curThread = current.getThread();
		if (curThread == null) {
			return;
		}
		availableRegsDialog.setLanguage(curThread.getTrace().getBaseLanguage());
		Set<Register> viewKnown = computeDefaultRegisterSelection(curThread);
		availableRegsDialog.setKnown(viewKnown);
		Set<Register> selection = getSelectionFor(curThread);
		// NOTE: Modifies selection in place
		availableRegsDialog.setSelection(selection);
		tool.showDialog(availableRegsDialog);
	}

	private void createSnapshotActivated() {
		DebuggerRegistersProvider clone = cloneAsDisconnected();
		clone.setIntraGroupPosition(WindowPosition.RIGHT);
		tool.showComponentProvider(clone, true);
	}

	private void clearDataTypeActivated() {
		if (myActionContext == null) {
			return;
		}
		RegisterRow row = myActionContext.getSelected();
		row.setDataType(null);
	}

	// TODO: "Refresh" action to flush cache and re-fetch selected registers

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}

	@Override
	public boolean isSnapshot() {
		return isClone;
	}

	protected String computeSubTitle() {
		TraceThread curThread = current.getThread();
		return curThread == null ? "" : curThread.getName();
	}

	protected void updateSubTitle() {
		setSubTitle(computeSubTitle());
	}

	private void removeOldTraceListener() {
		if (currentTrace == null) {
			return;
		}
		currentTrace.removeListener(traceChangeListener);
	}

	private void addNewTraceListener() {
		if (currentTrace == null) {
			return;
		}
		currentTrace.addListener(traceChangeListener);
	}

	private void doSetTrace(Trace trace) {
		if (currentTrace == trace) {
			return;
		}
		actionEnableEdits.setSelected(false);
		removeOldTraceListener();
		this.currentTrace = trace;
		addNewTraceListener();
	}

	private void removeOldRecorderListener() {
		if (currentRecorder == null) {
			return;
		}
		currentRecorder.removeListener(regAccessListener);
	}

	private void addNewRecorderListener() {
		if (currentRecorder == null) {
			return;
		}
		currentRecorder.addListener(regAccessListener);
	}

	private void doSetRecorder(TraceRecorder recorder) {
		if (currentRecorder == recorder) {
			return;
		}
		removeOldRecorderListener();
		this.currentRecorder = recorder;
		addNewRecorderListener();
	}

	public void coordinatesActivated(DebuggerCoordinates coordinates) {
		if (sameCoordinates(current, coordinates)) {
			current = coordinates;
			return;
		}

		previous = current;
		current = coordinates;

		readTheseCoords = new AsyncLazyValue<>(this::readRegistersIfLiveAndAccessible);
		doSetTrace(current.getTrace());
		doSetRecorder(current.getRecorder());
		updateSubTitle();

		recomputeViewKnown();
		loadRegistersAndValues();
		contextChanged();
		//checkEditsEnabled();
	}

	protected void traceClosed(Trace trace) {
		if (isClone) {
			if (current.getTrace() == trace) {
				coordinatesActivated(DebuggerCoordinates.NOWHERE);
				removeFromTool();
			}
		}
	}

	boolean canWriteTarget() {
		if (!current.isAliveAndPresent()) {
			return false;
		}
		TraceRecorder recorder = current.getRecorder();
		TargetRegisterBank targetRegs =
			recorder.getTargetRegisterBank(current.getThread(), current.getFrame());
		if (targetRegs == null) {
			return false;
		}
		return true;
	}

	boolean canWriteTargetRegister(Register register) {
		if (!computeEditsEnabled()) {
			return false;
		}
		Collection<Register> onTarget =
			current.getRecorder().getRegisterMapper(current.getThread()).getRegistersOnTarget();
		if (!onTarget.contains(register) && !onTarget.contains(register.getBaseRegister())) {
			return false;
		}
		return true;
	}

	BigInteger getRegisterValue(Register register) {
		TraceMemoryRegisterSpace regs = getRegisterMemorySpace(false);
		if (regs == null) {
			return BigInteger.ZERO;
		}
		return regs.getViewValue(current.getViewSnap(), register).getUnsignedValue();
	}

	void writeRegisterValue(Register register, BigInteger value) {
		writeRegisterValue(new RegisterValue(register, value));
	}

	void writeRegisterValue(RegisterValue rv) {
		rv = combineWithTraceBaseRegisterValue(rv);
		CompletableFuture<Void> future = current.getRecorder()
				.writeThreadRegisters(current.getThread(), current.getFrame(),
					Map.of(rv.getRegister(), rv));
		future.exceptionally(ex -> {
			ex = AsyncUtils.unwrapThrowable(ex);
			if (ex instanceof DebuggerModelAccessException) {
				Msg.error(this, "Could not write target register", ex);
				plugin.getTool()
						.setStatusInfo("Could not write target register: " + ex.getMessage());
			}
			else {
				Msg.showError(this, getComponent(), "Edit Register",
					"Could not write target register", ex);
			}
			return null;
		});
	}

	private RegisterValue combineWithTraceBaseRegisterValue(RegisterValue rv) {
		TraceMemoryRegisterSpace regs = getRegisterMemorySpace(false);
		long snap = current.getSnap();
		return TraceRegisterUtils.combineWithTraceBaseRegisterValue(rv, snap, regs, true);
	}

	/**
	 * TODO: Make this smart enough to replace a component type when applicable? NOTE: Would require
	 * cloning the type to avoid effects elsewhere. Maybe just keep a dedicated data type for this
	 * register and modify it.... Well, that works until you consider changes in time....
	 */
	void writeRegisterDataType(Register register, DataType dataType) {
		try (UndoableTransaction tid =
			UndoableTransaction.start(current.getTrace(), "Edit Register Type", false)) {
			TraceCodeRegisterSpace space = getRegisterMemorySpace(true).getCodeSpace(true);
			long snap = current.getSnap();
			space.definedUnits().clear(Range.closed(snap, snap), register, TaskMonitor.DUMMY);
			if (dataType != null) {
				space.definedData().create(Range.atLeast(snap), register, dataType);
			}
			tid.commit();
		}
		catch (CodeUnitInsertionException | DataTypeConflictException | CancelledException e) {
			throw new AssertionError(e);
		}
	}

	TraceData getRegisterData(Register register) {
		TraceCodeRegisterSpace space = getRegisterCodeSpace(false);
		if (space == null) {
			return null;
		}
		long snap = current.getSnap();
		return space.definedData().getForRegister(snap, register);
	}

	DataType getRegisterDataType(Register register) {
		TraceData data = getRegisterData(register);
		if (data == null) {
			return null;
		}
		return data.getDataType();
	}

	String getRegisterValueRepresentation(Register register) {
		TraceData data = getRegisterData(register);
		if (data == null) {
			return null;
		}
		return TraceRegisterUtils.getValueRepresentationHackPointer(data);
	}

	void recomputeViewKnown() {
		TraceMemoryRegisterSpace regs = getRegisterMemorySpace(false);
		TraceProgramView view = current.getView();
		if (regs == null || view == null) {
			viewKnown = null;
			return;
		}
		viewKnown = new AddressSet(view.getViewport()
				.unionedAddresses(snap -> regs.getAddressesWithState(snap,
					state -> state == TraceMemoryState.KNOWN)));
	}

	boolean isRegisterKnown(Register register) {
		if (viewKnown == null) {
			return false;
		}
		AddressRange range = TraceRegisterUtils.rangeForRegister(register);
		return viewKnown.contains(range.getMinAddress(), range.getMaxAddress());
	}

	boolean isRegisterChanged(Register register) {
		if (previous.getThread() == null || current.getThread() == null) {
			return false;
		}
		if (previous.getTrace().getBaseLanguage() != current.getTrace().getBaseLanguage()) {
			return false;
		}
		if (!isRegisterKnown(register)) {
			return false;
		}
		TraceMemoryRegisterSpace curSpace = getRegisterMemorySpace(current, false);
		TraceMemoryRegisterSpace prevSpace = getRegisterMemorySpace(previous, false);
		if (prevSpace == null) {
			return false;
		}
		RegisterValue curRegVal = curSpace.getViewValue(current.getViewSnap(), register);
		RegisterValue prevRegVal = prevSpace.getViewValue(previous.getViewSnap(), register);
		return !Objects.equals(curRegVal, prevRegVal);
	}

	private boolean computeEditsEnabled() {
		if (!actionEnableEdits.isSelected()) {
			return false;
		}
		return canWriteTarget();
	}

	/**
	 * Gather general registers, the program counter, and the stack pointer
	 * 
	 * This excludes the context register
	 * 
	 * TODO: Several pspec files need adjustment to clean up "common registers"
	 * 
	 * @param cSpec the compiler spec
	 * @return the set of "common" registers
	 */
	public static LinkedHashSet<Register> collectCommonRegisters(CompilerSpec cSpec) {
		Language lang = cSpec.getLanguage();
		LinkedHashSet<Register> result = new LinkedHashSet<>();
		result.add(cSpec.getStackPointer());
		result.add(lang.getProgramCounter());
		for (Register reg : lang.getRegisters()) {
			//if (reg.getGroup() != null) {
			//	continue;
			//}
			if (reg.isProcessorContext()) {
				continue;
			}
			result.add(reg);
		}
		return result;
	}

	public LinkedHashSet<Register> computeDefaultRegisterSelection(TraceThread thread) {
		return collectCommonRegisters(thread.getTrace().getBaseCompilerSpec());
	}

	public LinkedHashSet<Register> computeDefaultRegisterFavorites(TraceThread thread) {
		LinkedHashSet<Register> favorites = new LinkedHashSet<>();
		CompilerSpec cSpec = thread.getTrace().getBaseCompilerSpec();
		favorites.add(cSpec.getLanguage().getProgramCounter());
		favorites.add(cSpec.getStackPointer());
		return favorites;
	}

	public LinkedHashSet<Register> computeDefaultRegistersOld(TraceThread thread) {
		LinkedHashSet<Register> viewKnown = new LinkedHashSet<>();
		/**
		 * NOTE: It is rare that this includes registers outside of those common to the view and
		 * target, but in case the user has manually populated such registers, this will ensure they
		 * are visible in the UI.
		 * 
		 * Also, in case the current thread is not live, we want the DB values to appear.
		 */
		viewKnown.addAll(collectBaseRegistersWithKnownValues(thread));
		Trace trace = thread.getTrace();
		TraceRecorder recorder = modelService.getRecorder(trace);
		if (recorder == null) {
			viewKnown.addAll(collectCommonRegisters(trace.getBaseCompilerSpec()));
			return viewKnown;
		}
		TargetThread targetThread = recorder.getTargetThread(thread);
		if (targetThread == null || !recorder.isRegisterBankAccessible(thread, 0)) {
			return viewKnown;
		}
		DebuggerRegisterMapper regMapper = recorder.getRegisterMapper(thread);
		if (regMapper == null) {
			return viewKnown;
		}
		for (Register onTarget : regMapper.getRegistersOnTarget()) {
			viewKnown.add(onTarget);
			viewKnown.addAll(onTarget.getChildRegisters());
		}
		return viewKnown;
	}

	protected static TraceMemoryRegisterSpace getRegisterMemorySpace(DebuggerCoordinates coords,
			boolean createIfAbsent) {
		TraceThread thread = coords.getThread();
		if (thread == null) {
			return null;
		}
		return coords.getTrace()
				.getMemoryManager()
				.getMemoryRegisterSpace(thread, coords.getFrame(), createIfAbsent);
	}

	protected TraceMemoryRegisterSpace getRegisterMemorySpace(boolean createIfAbsent) {
		return getRegisterMemorySpace(current, createIfAbsent);
	}

	protected TraceCodeRegisterSpace getRegisterCodeSpace(boolean createIfAbsent) {
		TraceThread curThread = current.getThread();
		if (curThread == null) {
			return null;
		}
		return current.getTrace()
				.getCodeManager()
				.getCodeRegisterSpace(curThread, current.getFrame(), createIfAbsent);
	}

	protected Set<Register> collectBaseRegistersWithKnownValues(TraceThread thread) {
		// TODO: Other registers may acquire known values.
		// TODO: How to best alert the user? Just add to view?
		TraceMemoryRegisterSpace mem =
			thread.getTrace().getMemoryManager().getMemoryRegisterSpace(thread, false);
		Set<Register> result = new LinkedHashSet<>();
		if (mem == null) {
			return result;
		}
		AddressSpace regSpace =
			thread.getTrace().getBaseLanguage().getAddressFactory().getRegisterSpace();
		AddressSet everKnown = new AddressSet();
		for (Entry<TraceAddressSnapRange, TraceMemoryState> entry : mem.getMostRecentStates(
			thread.getTrace().getTimeManager().getMaxSnap(),
			new AddressRangeImpl(regSpace.getMinAddress(), regSpace.getMaxAddress()))) {
			everKnown.add(entry.getKey().getRange());
		}

		for (Register reg : thread.getRegisters()) {
			if (!reg.isBaseRegister()) {
				continue;
			}
			AddressRange regRange = TraceRegisterUtils.rangeForRegister(reg);
			if (!everKnown.intersects(regRange.getMinAddress(), regRange.getMaxAddress())) {
				continue;
			}
			if (!reg.isBaseRegister()) {
				continue;
			}
			result.add(reg);
		}
		return result;
	}

	protected Set<Register> getSelectionFor(TraceThread thread) {
		synchronized (selectionByCSpec) {
			CompilerSpec cSpec = thread.getTrace().getBaseCompilerSpec();
			return selectionByCSpec.computeIfAbsent(cSpec,
				__ -> computeDefaultRegisterSelection(thread));
		}
	}

	protected Set<Register> getFavoritesFor(TraceThread thread) {
		synchronized (favoritesByCSpec) {
			CompilerSpec cSpec = thread.getTrace().getBaseCompilerSpec();
			return favoritesByCSpec.computeIfAbsent(cSpec,
				__ -> computeDefaultRegisterFavorites(thread));
		}
	}

	protected void setFavorite(Register register, boolean favorite) {
		Set<Register> favorites = getFavoritesFor(current.getThread());
		if (favorite) {
			favorites.add(register);
		}
		else {
			favorites.remove(register);
		}
	}

	public boolean isFavorite(Register register) {
		Set<Register> favorites = getFavoritesFor(current.getThread());
		return favorites.contains(register);
	}

	public CompletableFuture<Void> setSelectedRegistersAndLoad(
			Collection<Register> selectedRegisters) {
		Set<Register> selection = getSelectionFor(current.getThread());
		selection.clear();
		selection.addAll(new TreeSet<>(selectedRegisters));
		return loadRegistersAndValues();
	}

	public DebuggerRegistersProvider cloneAsDisconnected() {
		DebuggerRegistersProvider clone = plugin.createNewDisconnectedProvider();
		clone.coordinatesActivated(current); // This should also enact the same selection
		return clone;
	}

	protected void displaySelectedRegisters(Set<Register> selected) {
		List<Register> regs = currentTrace.getBaseLanguage().getRegisters();
		for (Iterator<Entry<Register, RegisterRow>> it = regMap.entrySet().iterator(); it
				.hasNext();) {
			Map.Entry<Register, RegisterRow> ent = it.next();
			if (!selected.contains(ent.getKey())) {
				regsTableModel.delete(ent.getValue());
				it.remove();
			}
		}

		for (Register reg : selected) {
			regMap.computeIfAbsent(reg, r -> {
				RegisterRow row = new RegisterRow(this, regs.indexOf(reg), reg);
				regsTableModel.add(row);
				return row;
			});
		}
	}

	protected CompletableFuture<Void> loadRegistersAndValues() {
		TraceThread curThread = current.getThread();
		if (curThread == null) {
			regsTableModel.clear();
			regMap.clear();
			return AsyncUtils.NIL;
		}
		Set<Register> selected = getSelectionFor(curThread);
		displaySelectedRegisters(selected);
		return loadValues();
	}

	protected CompletableFuture<Void> loadValues() {
		TraceThread curThread = current.getThread();
		if (curThread == null) {
			return AsyncUtils.NIL;
		}
		regsTableModel.fireTableDataChanged();
		//return AsyncUtils.NIL;
		// In case we need to read a non-zero frame
		return readTheseCoords.request();
	}

	private Set<Register> baseRegisters(Set<Register> regs) {
		return regs.stream().filter(Register::isBaseRegister).collect(Collectors.toSet());
	}

	protected CompletableFuture<Void> readRegistersIfLiveAndAccessible() {
		TraceRecorder recorder = current.getRecorder();
		if (recorder == null) {
			return AsyncUtils.NIL;
		}
		if (recorder.getSnap() != current.getSnap()) {
			return AsyncUtils.NIL;
		}
		if (current.getFrame() == 0) {
			// Should have been pushed by model. non-zero frames are poll-only
			return AsyncUtils.NIL;
		}
		TraceThread traceThread = current.getThread();
		TargetThread targetThread = recorder.getTargetThread(traceThread);
		if (targetThread == null) {
			return AsyncUtils.NIL;
		}
		Set<Register> toRead = new HashSet<>(baseRegisters(getSelectionFor(traceThread)));
		DebuggerRegisterMapper regMapper = recorder.getRegisterMapper(traceThread);
		if (regMapper == null) {
			Msg.error(this, "Target is live, but we haven't got a register mapper, yet");
			return AsyncUtils.NIL;
		}
		toRead.retainAll(regMapper.getRegistersOnTarget());
		TargetRegisterBank bank = recorder.getTargetRegisterBank(traceThread, current.getFrame());
		if (bank == null || !bank.isValid()) {
			Msg.error(this, "Current frame's bank does not exist");
			return AsyncUtils.NIL;
		}
		CompletableFuture<?> future =
			recorder.captureThreadRegisters(traceThread, current.getFrame(), toRead);
		return future.exceptionally(ex -> {
			ex = AsyncUtils.unwrapThrowable(ex);
			if (ex instanceof DebuggerModelAccessException) {
				String msg =
					"Could not read target registers for selected thread: " + ex.getMessage();
				Msg.info(this, msg);
				plugin.getTool().setStatusInfo(msg);
			}
			else {
				Msg.showError(this, getComponent(), "Read Target Registers",
					"Could not read target registers for selected thread", ex);
			}
			return ExceptionUtils.rethrow(ex);
		}).thenApply(__ -> null);
	}

	private void repaintTable() {
		if (regsTable != null) {
			regsTable.repaint();
		}
	}

	@AutoOptionConsumed(name = DebuggerResources.OPTION_NAME_COLORS_REGISTER_STALE)
	private void setRegisterStaleColor(Color color) {
		repaintTable();
	}

	@AutoOptionConsumed(name = DebuggerResources.OPTION_NAME_COLORS_REGISTER_STALE_SEL)
	private void setRegisterStaleSelColor(Color color) {
		repaintTable();
	}

	@AutoOptionConsumed(name = DebuggerResources.OPTION_NAME_COLORS_REGISTER_CHANGED)
	private void setRegisterChangesColor(Color color) {
		repaintTable();
	}

	@AutoOptionConsumed(name = DebuggerResources.OPTION_NAME_COLORS_REGISTER_CHANGED_SEL)
	private void setRegisterChangesSelColor(Color color) {
		repaintTable();
	}

	protected String formatAddressInfo(Address address) {
		return address.toString(); // TODO;
		// TODO: Examine static mapped programs, too
		/*Memory mem = program.getMemoryManager();
		MemoryBlock addrBlock = mem.getBlock(address);
		if (addrBlock == null) {
			return "<INVALID>";
		}
		Function function = program.getFunctionManager().getFunctionContaining(address);
		if (function != null) {
			Address entry = function.getEntryPoint();
			long diff = address.subtract(entry);
			if (diff < 0) {
				return function.getName() + "-" + (-diff);
			}
			if (diff > 0) {
				return function.getName() + "+" + diff;
			}
			return function.getName();
		}
		Data defData = program.getListing().getDefinedDataContaining(address);
		if (defData != null) {
			// Use existing mechanism
			return SymbolUtilities.getDynamicName(program, address);
		}
		// It is either undefined or an instruction outside a function
		SymbolTable table = program.getSymbolTable();
		Symbol primary = table.getPrimarySymbol(address);
		if (primary != null) {
			return primary.getName();
		}
		Symbol before = table.getSymbolIterator(address, false).next();
		if (before != null) {
			MemoryBlock symBlock = mem.getBlock(before.getAddress());
			if (addrBlock == symBlock) {
				long diff = address.subtract(before.getAddress());
				return before.getName() + "+" + diff;
			}
		}
		// TODO: Making an assumption about block name here. Generally true, but user can fuddle.
		String moduleName = addrBlock.getName().split(":")[0];
		return address.toString(moduleName + ":");*/
	}

	public void writeDataState(SaveState saveState) {
		if (isClone) {
			current.writeDataState(tool, saveState, KEY_DEBUGGER_COORDINATES);
		}
	}

	public void readDataState(SaveState saveState) {
		if (isClone) {
			coordinatesActivated(
				DebuggerCoordinates.readDataState(tool, saveState, KEY_DEBUGGER_COORDINATES, true));
		}
	}
}
