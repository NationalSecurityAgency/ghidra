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

import db.Transaction;
import docking.*;
import docking.action.*;
import docking.action.builder.ActionBuilder;
import docking.actions.PopupActionProvider;
import docking.widgets.table.*;
import docking.widgets.table.ColumnSortState.SortDirection;
import docking.widgets.table.DefaultEnumeratedColumnTableModel.EnumeratedTableColumn;
import generic.theme.GColor;
import ghidra.app.plugin.core.data.DataSettingsDialog;
import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.gui.DebuggerProvider;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.mapping.DebuggerRegisterMapper;
import ghidra.app.services.*;
import ghidra.app.services.DebuggerControlService.StateEditor;
import ghidra.async.AsyncLazyValue;
import ghidra.async.AsyncUtils;
import ghidra.base.widgets.table.DataTypeTableCellEditor;
import ghidra.dbg.error.DebuggerModelAccessException;
import ghidra.dbg.target.TargetRegisterBank;
import ghidra.dbg.target.TargetThread;
import ghidra.docking.settings.Settings;
import ghidra.framework.model.DomainObject;
import ghidra.framework.model.DomainObjectChangeRecord;
import ghidra.framework.options.AutoOptions;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Data;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.trace.model.*;
import ghidra.trace.model.Trace.*;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.listing.*;
import ghidra.trace.model.memory.*;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.util.TraceAddressSpace;
import ghidra.trace.util.TraceRegisterUtils;
import ghidra.util.*;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.data.DataTypeParser.AllowedDataTypes;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.GhidraTableFilterPanel;
import ghidra.util.task.TaskMonitor;

public class DebuggerRegistersProvider extends ComponentProviderAdapter
		implements DebuggerProvider, PopupActionProvider {
	private static final GColor COLOR_BORDER_DISCONNECTED =
		new GColor("color.border.provider.disconnected");
	private static final Color COLOR_FOREGROUND_STALE =
		new GColor("color.debugger.plugin.resources.register.stale");
	private static final Color COLOR_FOREGROUND_STALE_SEL =
		new GColor("color.debugger.plugin.resources.register.stale.selected");
	private static final Color COLOR_FOREGROUND_CHANGED =
		new GColor("color.debugger.plugin.resources.register.changed");
	private static final Color COLOR_FOREGROUND_CHANGED_SEL =
		new GColor("color.debugger.plugin.resources.register.changed.selected");

	private static final String KEY_DEBUGGER_COORDINATES = "DebuggerCoordinates";

	interface ClearRegisterType {
		String NAME = DebuggerResources.NAME_CLEAR_REGISTER_TYPE;
		String DESCRIPTION = DebuggerResources.DESCRIPTION_CLEAR_REGISTER_TYPE;

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME, ownerName)
					.description(DESCRIPTION);
		}
	}

	interface RegisterTypeSettings {
		String NAME = DebuggerResources.NAME_REGISTER_TYPE_SETTINGS;
		String DESCRIPTION = DebuggerResources.DESCRIPTION_REGISTER_TYPE_SETTINGS;
		String HELP_ANCHOR = "type_settings";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME, ownerName)
					.description(DESCRIPTION)
					.popupMenuPath(NAME)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	/**
	 * This only exists so that tests can access it
	 */
	protected static class RegisterDataSettingsDialog extends DataSettingsDialog {
		public RegisterDataSettingsDialog(Data data) {
			super(data);
		}

		@Override
		protected Settings getSettings() {
			return super.getSettings();
		}

		@Override
		protected void okCallback() {
			super.okCallback();
		}
	}

	protected enum RegisterTableColumns
		implements EnumeratedTableColumn<RegisterTableColumns, RegisterRow> {
		FAV("Fav", Boolean.class, RegisterRow::isFavorite, RegisterRow::setFavorite, //
				r -> true, SortDirection.DESCENDING),
		NUMBER("#", Integer.class, RegisterRow::getNumber),
		NAME("Name", String.class, RegisterRow::getName),
		VALUE("Value", BigInteger.class, RegisterRow::getValue, RegisterRow::setValue, //
				RegisterRow::isValueEditable, SortDirection.ASCENDING),
		TYPE("Type", DataType.class, RegisterRow::getDataType, RegisterRow::setDataType, //
				r -> true, SortDirection.ASCENDING),
		REPR("Repr", String.class, RegisterRow::getRepresentation, RegisterRow::setRepresentation, //
				RegisterRow::isRepresentationEditable, SortDirection.ASCENDING);

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
		public RegistersTableModel(PluginTool tool) {
			super(tool, "Registers", RegisterTableColumns.class);
		}

		@Override
		public List<RegisterTableColumns> defaultSortOrder() {
			return List.of(RegisterTableColumns.FAV, RegisterTableColumns.NUMBER);
		}

		@Override
		protected TableColumnDescriptor<RegisterRow> createTableColumnDescriptor() {
			TableColumnDescriptor<RegisterRow> descriptor = super.createTableColumnDescriptor();
			for (DebuggerRegisterColumnFactory factory : ClassSearcher
					.getInstances(DebuggerRegisterColumnFactory.class)) {
				descriptor.addHiddenColumn(factory.create());
			}
			return descriptor;
		}
	}

	protected static boolean sameCoordinates(DebuggerCoordinates a, DebuggerCoordinates b) {
		if (!Objects.equals(a.getPlatform(), b.getPlatform())) {
			return false; // subsumes trace
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

		private boolean isVisibleObjectsMode(AddressSpace space) {
			TraceObject container = current.getRegisterContainer();
			return container != null &&
				container.getCanonicalPath().toString().equals(space.getName());
		}

		private boolean isVisible(TraceAddressSpace space) {
			TraceThread curThread = current.getThread();
			if (curThread == null) {
				return false;
			}
			if (space.getAddressSpace().isOverlaySpace()) {
				return isVisibleObjectsMode(space.getAddressSpace());
			}
			if (!space.getAddressSpace().isRegisterSpace()) {
				return true; // Memory-mapped, visible no matter the active thread
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
			if (space.getAddressSpace().isMemorySpace()) {
				return current.getPlatform()
						.getLanguage()
						.getRegisterAddresses()
						.intersects(range.getX1(), range.getX2());
			}
			TraceProgramView view = current.getView();
			if (view == null || !view.getViewport().containsAnyUpper(range.getLifespan())) {
				return false;
			}
			// Probably not worth checking for occlusion here. Just a little refresh waste.
			return true;
		}

		private void refreshRange(AddressRange range) {
			TraceMemorySpace space = getRegisterMemorySpace(false);
			// ...   If I got an event for it, it ought to exist.
			assert space != null;

			// TODO: Just certain rows?
			regsTableModel.fireTableDataChanged();
		}

		private void objectRestored(DomainObjectChangeRecord rec) {
			coordinatesActivated(current.reFindThread());
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
				Lifespan oldSpan, Lifespan newSpan) {
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

		private void threadDestroyed(TraceThread thread, Lifespan oldSpan, Lifespan newSpan) {
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
					setForeground(COLOR_FOREGROUND_STALE_SEL);
				}
				else {
					setForeground(COLOR_FOREGROUND_STALE);
				}
			}
			else if (row.isChanged()) {
				if (data.isSelected()) {
					setForeground(COLOR_FOREGROUND_CHANGED_SEL);
				}
				else {
					setForeground(COLOR_FOREGROUND_CHANGED);
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
			try (Transaction tx = currentTrace.openTransaction("Resolve DataType")) {
				return currentTrace.getDataTypeManager().resolve(dataType, null);
			}
		}
	}

	final DebuggerRegistersPlugin plugin;
	private final Map<LanguageCompilerSpecPair, LinkedHashSet<Register>> selectionByCSpec;
	private final Map<LanguageCompilerSpecPair, LinkedHashSet<Register>> favoritesByCSpec;
	private final boolean isClone;

	DebuggerCoordinates previous = DebuggerCoordinates.NOWHERE;
	DebuggerCoordinates current = DebuggerCoordinates.NOWHERE;
	private AsyncLazyValue<Void> readTheseCoords =
		new AsyncLazyValue<>(this::readRegistersIfLiveAndAccessible); /* "read" past tense */
	private Trace currentTrace; // Copy for transition
	private TraceRecorder currentRecorder; // Copy for transition

	@AutoServiceConsumed
	private DebuggerTraceManagerService traceManager;
	@AutoServiceConsumed
	private DebuggerListingService listingService;
	@AutoServiceConsumed
	private DebuggerControlService controlService;
	@AutoServiceConsumed
	private MarkerService markerService; // TODO: Mark address types (separate plugin?)
	@SuppressWarnings("unused")
	private final AutoService.Wiring autoServiceWiring;

	@SuppressWarnings("unused")
	private final AutoOptions.Wiring autoOptionsWiring;

	private final TraceChangeListener traceChangeListener = new TraceChangeListener();
	private final RegAccessListener regAccessListener = new RegAccessListener();

	private JPanel mainPanel = new JPanel(new BorderLayout());

	final RegistersTableModel regsTableModel;
	GhidraTable regsTable;
	GhidraTableFilterPanel<RegisterRow> regsFilterPanel;
	Map<Register, RegisterRow> regMap = new HashMap<>();

	private final DebuggerAvailableRegistersDialog availableRegsDialog;

	DockingAction actionSelectRegisters;
	DockingAction actionCreateSnapshot;
	ToggleDockingAction actionEnableEdits;
	DockingAction actionClearDataType;
	DockingAction actionDataTypeSettings;

	DebuggerRegisterActionContext myActionContext;
	AddressSetView viewKnown;

	protected DebuggerRegistersProvider(final DebuggerRegistersPlugin plugin,
			Map<LanguageCompilerSpecPair, LinkedHashSet<Register>> selectionByCSpec,
			Map<LanguageCompilerSpecPair, LinkedHashSet<Register>> favoritesByCSpec,
			boolean isClone) {
		super(plugin.getTool(), DebuggerResources.TITLE_PROVIDER_REGISTERS, plugin.getName());
		this.plugin = plugin;

		regsTableModel = new RegistersTableModel(tool);

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
			mainPanel.setBorder(BorderFactory.createLineBorder(COLOR_BORDER_DISCONNECTED, 2));
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
		availableRegsDialog.dispose();

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
			if (evt.getValueIsAdjusting()) {
				return;
			}
			myActionContext = new DebuggerRegisterActionContext(this,
				regsFilterPanel.getSelectedItem(), regsTable);
			contextChanged();
		});
		regsTable.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (e.getClickCount() == 2 && e.getButton() == MouseEvent.BUTTON1) {
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
				address = space.getAddress(lv, true);
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
		Address address = (Address) data.getValue();
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
			actionCreateSnapshot = DebuggerResources.CloneWindowAction.builder(plugin)
					.enabledWhen(c -> current.getThread() != null)
					.onAction(c -> cloneWindowActivated())
					.buildAndInstallLocal(this);
		}
		actionEnableEdits = DebuggerResources.EnableEditsAction.builder(plugin)
				.enabledWhen(c -> current.getThread() != null)
				.onAction(c -> {
				})
				.buildAndInstallLocal(this);
		actionClearDataType = ClearRegisterType.builder(plugin)
				.enabledWhen(c -> current.getThread() != null)
				.keyBinding(KeyStroke.getKeyStroke(KeyEvent.VK_DELETE, 0))
				.onAction(c -> clearDataTypeActivated())
				.buildAndInstallLocal(this);
		actionDataTypeSettings = RegisterTypeSettings.builder(plugin)
				.withContext(DebuggerRegisterActionContext.class)
				.enabledWhen(this::contextHasSingleRegisterWithType)
				.onAction(this::dataTypeSettingsActivated)
				.buildAndInstallLocal(this);
	}

	private void selectRegistersActivated() {
		TracePlatform curPlatform = current.getPlatform();
		if (current.getThread() == null) {
			return;
		}
		availableRegsDialog.setLanguage(curPlatform.getLanguage());
		Set<Register> viewKnown = computeDefaultRegisterSelection(curPlatform);
		availableRegsDialog.setKnown(viewKnown);
		Set<Register> selection = getSelectionFor(curPlatform);
		// NOTE: Modifies selection in place
		availableRegsDialog.setSelection(selection);
		tool.showDialog(availableRegsDialog);
	}

	private void cloneWindowActivated() {
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

	private boolean contextHasSingleRegisterWithType(DebuggerRegisterActionContext ctx) {
		return ctx.getSelected() != null && ctx.getSelected().getData() != null;
	}

	private void dataTypeSettingsActivated(DebuggerRegisterActionContext ctx) {
		RegisterRow row = ctx.getSelected();
		if (row == null) {
			return;
		}
		Data data = row.getData();
		if (data == null) {
			return;
		}
		tool.showDialog(new RegisterDataSettingsDialog(data));
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

		prepareRegisterSpace();
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

	boolean canWriteRegister(Register register) {
		if (!isEditsEnabled()) {
			return false;
		}
		if (controlService == null) {
			return false;
		}
		StateEditor editor = controlService.createStateEditor(current);
		return editor.isRegisterEditable(register);
	}

	BigInteger getRegisterValue(Register register) {
		TraceMemorySpace regs = getRegisterMemorySpace(false);
		if (regs == null) {
			return BigInteger.ZERO;
		}
		return regs.getViewValue(current.getPlatform(), current.getViewSnap(), register)
				.getUnsignedValue();
	}

	void writeRegisterValue(Register register, BigInteger value) {
		writeRegisterValue(new RegisterValue(register, value));
	}

	void writeRegisterValue(RegisterValue rv) {
		if (controlService == null) {
			Msg.showError(this, getComponent(), "Edit Register", "No control service.");
			return;
		}
		StateEditor editor = controlService.createStateEditor(current);
		if (!editor.isRegisterEditable(rv.getRegister())) {
			Msg.showError(this, getComponent(), "Edit Register",
				"Neither the register nor any parent can be edited.");
			return;
		}

		CompletableFuture<Void> future = editor.setRegister(rv);
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
		return;
	}

	/**
	 * TODO: Make this smart enough to replace a component type when applicable? NOTE: Would require
	 * cloning the type to avoid effects elsewhere. Maybe just keep a dedicated data type for this
	 * register and modify it.... Well, that works until you consider changes in time....
	 */
	void writeRegisterDataType(Register register, DataType dataType) {
		try (Transaction tx = current.getTrace().openTransaction("Edit Register Type")) {
			if (dataType instanceof Pointer ptrType && register.getAddress().isRegisterAddress()) {
				// Because we're about to use the size, resolve it first
				ptrType = (Pointer) current.getTrace()
						.getDataTypeManager()
						.resolve(dataType, DataTypeConflictHandler.DEFAULT_HANDLER);
				/**
				 * TODO: This should be the current platform instead, but it's not clear how to do
				 * that. The PointerTypedef uses the program (taken from the MemBuffer) to lookup
				 * the configured address space by name. Might be better if MemBuffer/CodeUnit had
				 * getAddressFactory(). Still, I'd need guest-platform data units before I could
				 * override that meaningfully.
				 */
				/**
				 * AddressSpace space =
				 * current.getPlatform().getAddressFactory().getDefaultAddressSpace();
				 */
				AddressSpace space =
					current.getTrace().getBaseAddressFactory().getDefaultAddressSpace();
				dataType = new PointerTypedef(null, ptrType.getDataType(), ptrType.getLength(),
					ptrType.getDataTypeManager(), space);
			}
			TraceCodeSpace space = getRegisterMemorySpace(true).getCodeSpace(true);
			long snap = current.getViewSnap();
			TracePlatform platform = current.getPlatform();
			space.definedUnits()
					.clear(platform, Lifespan.at(snap), register, TaskMonitor.DUMMY);
			if (dataType != null) {
				space.definedData().create(platform, Lifespan.nowOn(snap), register, dataType);
			}
		}
		catch (CodeUnitInsertionException | CancelledException e) {
			throw new AssertionError(e);
		}
	}

	TraceData getRegisterData(Register register) {
		TraceCodeSpace space = getRegisterCodeSpace(false);
		if (space == null) {
			return null;
		}
		TracePlatform platform = current.getPlatform();
		long snap = current.getViewSnap();
		return space.definedData().getForRegister(platform, snap, register);
	}

	DataType getRegisterDataType(Register register) {
		TraceData data = getRegisterData(register);
		if (data == null) {
			return null;
		}
		return data.getDataType();
	}

	void writeRegisterValueRepresentation(Register register, String representation) {
		TraceData data = getRegisterData(register);
		if (data == null) {
			// isEditable should have been false
			tool.setStatusInfo("Register has no data type", true);
			return;
		}
		try {
			RegisterValue rv = TraceRegisterUtils.encodeValueRepresentationHackPointer(
				register, data, representation);
			writeRegisterValue(rv);
		}
		catch (DataTypeEncodeException e) {
			tool.setStatusInfo(e.getMessage(), true);
			return;
		}
	}

	boolean canWriteRegisterRepresentation(Register register) {
		if (!canWriteRegister(register)) {
			return false;
		}
		TraceData data = getRegisterData(register);
		if (data == null) {
			return false;
		}
		return data.getBaseDataType().isEncodable();
	}

	String getRegisterValueRepresentation(Register register) {
		TraceData data = getRegisterData(register);
		if (data == null) {
			return null;
		}
		return data.getDefaultValueRepresentation();
	}

	/**
	 * Ensure the register space exists and has been populated from register object values.
	 * 
	 * <p>
	 * TODO: I wish this were not necessary. Maybe I should create the space when register object
	 * values are populated.
	 */
	void prepareRegisterSpace() {
		if (current.getThread() != null &&
			current.getTrace().getObjectManager().getRootSchema() != null) {
			try (Transaction tx =
				current.getTrace().openTransaction("Create/initialize register space")) {
				getRegisterMemorySpace(true);
			}
		}
	}

	void recomputeViewKnown() {
		TracePlatform platform = current.getPlatform();
		if (platform == null) {
			viewKnown = null;
			return;
		}
		TraceProgramView view = current.getView();
		if (view == null) {
			viewKnown = null;
			return;
		}
		TraceMemoryManager mem = current.getTrace().getMemoryManager();
		AddressSetView viewKnownMem = view.getViewport()
				.unionedAddresses(snap -> mem.getAddressesWithState(snap,
					platform.mapGuestToHost(platform.getLanguage().getRegisterAddresses()),
					state -> state == TraceMemoryState.KNOWN));
		TraceMemorySpace regs = getRegisterMemorySpace(false);
		if (regs == null) {
			viewKnown = new AddressSet(viewKnownMem);
			return;
		}
		AddressSetView hostRegs =
			platform.mapGuestToHost(platform.getLanguage().getRegisterAddresses());
		AddressSetView overlayRegs =
			TraceRegisterUtils.getOverlaySet(regs.getAddressSpace(), hostRegs);
		AddressSetView viewKnownRegs = view.getViewport()
				.unionedAddresses(snap -> regs.getAddressesWithState(snap, overlayRegs,
					state -> state == TraceMemoryState.KNOWN));
		viewKnown = viewKnownRegs.union(viewKnownMem);
	}

	boolean isRegisterKnown(Register register) {
		if (viewKnown == null) {
			return false;
		}
		TraceMemorySpace regs = getRegisterMemorySpace(false);
		if (regs == null && register.getAddressSpace().isRegisterSpace()) {
			return false;
		}
		AddressRange range =
			current.getPlatform().getConventionalRegisterRange(regs.getAddressSpace(), register);
		return viewKnown.contains(range.getMinAddress(), range.getMaxAddress());
	}

	boolean isRegisterChanged(Register register) {
		if (previous.getThread() == null || current.getThread() == null) {
			return false;
		}
		if (previous.getPlatform().getLanguage() != current.getPlatform().getLanguage()) {
			return false;
		}
		if (!isRegisterKnown(register)) {
			return false;
		}
		TraceMemorySpace curSpace = getRegisterMemorySpace(current, false);
		TraceMemorySpace prevSpace = getRegisterMemorySpace(previous, false);
		if (prevSpace == null) {
			return false;
		}
		RegisterValue curRegVal =
			curSpace.getViewValue(current.getPlatform(), current.getViewSnap(), register);
		RegisterValue prevRegVal =
			prevSpace.getViewValue(current.getPlatform(), previous.getViewSnap(), register);
		return !Objects.equals(curRegVal, prevRegVal);
	}

	private boolean isEditsEnabled() {
		return actionEnableEdits.isSelected();
	}

	/**
	 * Gather general registers, the program counter, and the stack pointer
	 * 
	 * <p>
	 * This excludes the context register
	 * 
	 * <p>
	 * TODO: Several pspec files need adjustment to clean up "common registers"
	 * 
	 * @param cSpec the compiler spec
	 * @return the set of "common" registers
	 */
	public static LinkedHashSet<Register> collectCommonRegisters(CompilerSpec cSpec) {
		Language lang = cSpec.getLanguage();
		LinkedHashSet<Register> result = new LinkedHashSet<>();
		Register sp = cSpec.getStackPointer();
		if (sp != null) {
			result.add(sp);
		}
		Register pc = lang.getProgramCounter();
		if (pc != null) {
			result.add(pc);
		}
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

	public LinkedHashSet<Register> computeDefaultRegisterSelection(TracePlatform platform) {
		return collectCommonRegisters(platform.getCompilerSpec());
	}

	public LinkedHashSet<Register> computeDefaultRegisterFavorites(TracePlatform platform) {
		LinkedHashSet<Register> favorites = new LinkedHashSet<>();
		favorites.add(platform.getLanguage().getProgramCounter());
		favorites.add(platform.getCompilerSpec().getStackPointer());
		return favorites;
	}

	protected static TraceMemorySpace getRegisterMemorySpace(DebuggerCoordinates coords,
			boolean createIfAbsent) {
		TraceThread thread = coords.getThread();
		if (thread == null) {
			return null;
		}
		return coords.getTrace()
				.getMemoryManager()
				.getMemoryRegisterSpace(thread, coords.getFrame(), createIfAbsent);
	}

	protected TraceMemorySpace getRegisterMemorySpace(boolean createIfAbsent) {
		return getRegisterMemorySpace(current, createIfAbsent);
	}

	protected TraceCodeSpace getRegisterCodeSpace(boolean createIfAbsent) {
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
		TraceMemorySpace mem =
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

	protected static LanguageCompilerSpecPair getLangCSpecPair(TracePlatform platform) {
		return new LanguageCompilerSpecPair(platform.getLanguage().getLanguageID(),
			platform.getCompilerSpec().getCompilerSpecID());
	}

	protected Set<Register> getSelectionFor(TracePlatform platform) {
		synchronized (selectionByCSpec) {
			LanguageCompilerSpecPair lcsp = getLangCSpecPair(platform);
			return selectionByCSpec.computeIfAbsent(lcsp,
				__ -> computeDefaultRegisterSelection(platform));
		}
	}

	protected Set<Register> getFavoritesFor(TracePlatform platform) {
		synchronized (favoritesByCSpec) {
			LanguageCompilerSpecPair lcsp = getLangCSpecPair(platform);
			return favoritesByCSpec.computeIfAbsent(lcsp,
				__ -> computeDefaultRegisterFavorites(platform));
		}
	}

	protected void setFavorite(Register register, boolean favorite) {
		Set<Register> favorites = getFavoritesFor(current.getPlatform());
		if (favorite) {
			favorites.add(register);
		}
		else {
			favorites.remove(register);
		}
	}

	public boolean isFavorite(Register register) {
		Set<Register> favorites = getFavoritesFor(current.getPlatform());
		return favorites.contains(register);
	}

	public CompletableFuture<Void> setSelectedRegistersAndLoad(
			Collection<Register> selectedRegisters) {
		Set<Register> selection = getSelectionFor(current.getPlatform());
		selection.clear();
		selection.addAll(new TreeSet<>(selectedRegisters));
		return loadRegistersAndValues();
	}

	public RegisterRow getRegisterRow(Register register) {
		return regMap.get(register);
	}

	public void setSelectedRow(RegisterRow row) {
		regsFilterPanel.setSelectedItem(row);
	}

	public DebuggerRegistersProvider cloneAsDisconnected() {
		DebuggerRegistersProvider clone = plugin.createNewDisconnectedProvider();
		clone.coordinatesActivated(current); // This should also enact the same selection
		return clone;
	}

	protected void displaySelectedRegisters(Set<Register> selected) {
		List<Register> regs = current.getPlatform().getLanguage().getRegisters();
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
		if (current.getThread() == null) {
			regsTableModel.clear();
			regMap.clear();
			return AsyncUtils.NIL;
		}
		Set<Register> selected = getSelectionFor(current.getPlatform());
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

	protected CompletableFuture<?> readRegistersLegacy(TraceRecorder recorder,
			TraceThread traceThread, Set<Register> toRead) {
		DebuggerRegisterMapper regMapper = recorder.getRegisterMapper(traceThread);
		if (regMapper == null) {
			Msg.error(this, "Target is live, but we haven't got a register mapper, yet");
			return AsyncUtils.NIL;
		}
		toRead.retainAll(regMapper.getRegistersOnTarget());
		Set<TargetRegisterBank> banks =
			recorder.getTargetRegisterBanks(traceThread, current.getFrame());
		if (banks == null || banks.isEmpty()) {
			Msg.error(this, "Current frame's bank does not exist");
			return AsyncUtils.NIL;
		}
		// TODO: Should probably always be the host platform. I suspect it's ignored anyway.
		return recorder.captureThreadRegisters(current.getPlatform(), traceThread,
			current.getFrame(), toRead);
	}

	protected CompletableFuture<?> readRegistersObjectMode(TraceRecorder recorder,
			TraceThread traceThread, Set<Register> toRead) {
		return recorder.captureThreadRegisters(current.getPlatform(), traceThread,
			current.getFrame(), toRead);
	}

	protected CompletableFuture<Void> readRegistersIfLiveAndAccessible() {
		TraceRecorder recorder = current.getRecorder();
		if (recorder == null) {
			return AsyncUtils.NIL;
		}
		if (recorder.getSnap() != current.getSnap()) {
			return AsyncUtils.NIL;
		}
//		if (current.getFrame() == 0) {
//			// Should have been pushed by model. non-zero frames are poll-only
//			return AsyncUtils.NIL;
//		}
		TraceThread traceThread = current.getThread();
		TargetThread targetThread = recorder.getTargetThread(traceThread);
		if (targetThread == null) {
			return AsyncUtils.NIL;
		}

		Set<Register> toRead = new HashSet<>(baseRegisters(getSelectionFor(current.getPlatform())));

		CompletableFuture<?> future;
		if (current.getTrace().getObjectManager().getRootSchema() == null) {
			future = readRegistersLegacy(recorder, traceThread, toRead);
		}
		else {
			future = readRegistersObjectMode(recorder, traceThread, toRead);
		}
		return future.exceptionally(ex -> {
			ex = AsyncUtils.unwrapThrowable(ex);
			String msg = "Could not read target registers for selected thread: " + ex.getMessage();
			Msg.info(this, msg);
			plugin.getTool().setStatusInfo(msg);
			return ExceptionUtils.rethrow(ex);
		}).thenApply(__ -> null);
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
				DebuggerCoordinates.readDataState(tool, saveState, KEY_DEBUGGER_COORDINATES));
		}
	}

	public DebuggerCoordinates getCurrent() {
		return current;
	}
}
