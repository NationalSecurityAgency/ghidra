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
package ghidra.app.plugin.core.debug.gui.modules;

import java.awt.BorderLayout;
import java.awt.event.MouseEvent;
import java.math.BigInteger;
import java.net.URL;
import java.util.HashSet;
import java.util.Set;
import java.util.function.Function;

import javax.swing.*;
import javax.swing.table.TableColumn;
import javax.swing.table.TableColumnModel;

import com.google.common.collect.Range;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.DockingActionIf;
import docking.widgets.table.CustomToStringCellRenderer;
import docking.widgets.table.DefaultEnumeratedColumnTableModel.EnumeratedTableColumn;
import docking.widgets.table.GTable;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.gui.DebuggerProvider;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.*;
import ghidra.app.plugin.core.debug.utils.DebouncedRowWrappedEnumeratedColumnTableModel;
import ghidra.app.services.*;
import ghidra.framework.model.DomainObject;
import ghidra.framework.plugintool.AutoService;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.trace.model.Trace;
import ghidra.trace.model.Trace.TraceStaticMappingChangeType;
import ghidra.trace.model.TraceDomainObjectListener;
import ghidra.trace.model.modules.TraceStaticMapping;
import ghidra.trace.model.modules.TraceStaticMappingManager;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.util.MathUtilities;
import ghidra.util.Msg;
import ghidra.util.database.ObjectKey;
import ghidra.util.database.UndoableTransaction;
import ghidra.util.table.GhidraTableFilterPanel;

public class DebuggerStaticMappingProvider extends ComponentProviderAdapter
		implements DebuggerProvider {
	protected enum StaticMappingTableColumns
		implements EnumeratedTableColumn<StaticMappingTableColumns, StaticMappingRow> {
		DYNAMIC_ADDRESS("Dynamic Address", Address.class, StaticMappingRow::getTraceAddress),
		STATIC_URL("Static Program", URL.class, StaticMappingRow::getStaticProgramURL),
		STATIC_ADDRESS("Static Address", String.class, StaticMappingRow::getStaticAddress),
		LENGTH("Length", BigInteger.class, StaticMappingRow::getBigLength),
		SHIFT("Shift", Long.class, StaticMappingRow::getShift),
		LIFESPAN("Lifespan", Range.class, StaticMappingRow::getLifespan);

		private final String header;
		private final Class<?> cls;
		private final Function<StaticMappingRow, ?> getter;

		<T> StaticMappingTableColumns(String header, Class<T> cls,
				Function<StaticMappingRow, T> getter) {
			this.header = header;
			this.cls = cls;
			this.getter = getter;
		}

		@Override
		public Class<?> getValueClass() {
			return cls;
		}

		@Override
		public Object getValueOf(StaticMappingRow row) {
			return getter.apply(row);
		}

		@Override
		public String getHeader() {
			return header;
		}
	}

	protected static class MappingTableModel
			extends DebouncedRowWrappedEnumeratedColumnTableModel< //
					StaticMappingTableColumns, ObjectKey, StaticMappingRow, TraceStaticMapping> {

		public MappingTableModel() {
			super("Mappings", StaticMappingTableColumns.class, TraceStaticMapping::getObjectKey,
				StaticMappingRow::new);
		}
	}

	protected class ListenerForStaticMappingDisplay extends TraceDomainObjectListener {
		public ListenerForStaticMappingDisplay() {
			listenForUntyped(DomainObject.DO_OBJECT_RESTORED, e -> objectRestored());
			listenFor(TraceStaticMappingChangeType.ADDED, this::staticMappingAdded);
			listenFor(TraceStaticMappingChangeType.DELETED, this::staticMappingDeleted);
		}

		private void objectRestored() {
			loadMappings();
		}

		private void staticMappingAdded(TraceStaticMapping mapping) {
			mappingTableModel.addItem(mapping);
		}

		private void staticMappingDeleted(TraceStaticMapping mapping) {
			mappingTableModel.deleteItem(mapping);
		}
	}

	private final DebuggerStaticMappingPlugin plugin;

	private final DebuggerAddMappingDialog addMappingDialog;

	@AutoServiceConsumed
	private DebuggerStaticMappingService mappingService;
	// TODO: Use events to track selections? This can only work with the main listings.
	@AutoServiceConsumed
	private CodeViewerService codeViewerService;
	@AutoServiceConsumed
	private DebuggerListingService listingService;
	@AutoServiceConsumed
	private DebuggerTraceManagerService traceManager;
	@SuppressWarnings("unused")
	private final AutoService.Wiring autoWiring;

	private Trace currentTrace;

	private ListenerForStaticMappingDisplay listener = new ListenerForStaticMappingDisplay();

	protected final MappingTableModel mappingTableModel = new MappingTableModel();

	private JPanel mainPanel = new JPanel(new BorderLayout());
	protected GTable mappingTable;
	private GhidraTableFilterPanel<StaticMappingRow> mappingFilterPanel;

	DockingAction actionAdd;
	DockingAction actionRemove;
	DockingAction actionSelectCurrent;

	ActionContext myActionContext;

	public DebuggerStaticMappingProvider(final DebuggerStaticMappingPlugin plugin) {
		super(plugin.getTool(), DebuggerResources.TITLE_PROVIDER_MAPPINGS, plugin.getName(), null);
		this.plugin = plugin;

		this.addMappingDialog = new DebuggerAddMappingDialog();
		this.autoWiring = AutoService.wireServicesConsumed(plugin, this);

		setIcon(DebuggerResources.ICON_PROVIDER_MAPPINGS);
		setHelpLocation(DebuggerResources.HELP_PROVIDER_MAPPINGS);
		setWindowMenuGroup(DebuggerPluginPackage.NAME);

		buildMainPanel();
		setVisible(true);
		createActions();
	}

	@AutoServiceConsumed
	private void setMappingService(DebuggerStaticMappingService mappingService) {
		addMappingDialog.setMappingService(mappingService);
	}

	@Override
	public void addLocalAction(DockingActionIf action) {
		super.addLocalAction(action);
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		if (myActionContext == null) {
			return super.getActionContext(event);
		}
		return myActionContext;
	}

	private void loadMappings() {
		mappingTableModel.clear();
		if (currentTrace == null) {
			return;
		}
		TraceStaticMappingManager manager = currentTrace.getStaticMappingManager();
		mappingTableModel.addAllItems(manager.getAllEntries());
	}

	protected void buildMainPanel() {
		mappingTable = new GTable(mappingTableModel);
		mainPanel.add(new JScrollPane(mappingTable));
		mappingFilterPanel = new GhidraTableFilterPanel<>(mappingTable, mappingTableModel);
		mainPanel.add(mappingFilterPanel, BorderLayout.SOUTH);

		mappingTable.getSelectionModel().addListSelectionListener(evt -> {
			myActionContext = new DebuggerStaticMappingActionContext(this,
				mappingFilterPanel.getSelectedItems(), mappingTable);
			contextChanged();
		});

		TableColumnModel columnModel = mappingTable.getColumnModel();
		TableColumn dynAddrCol =
			columnModel.getColumn(StaticMappingTableColumns.DYNAMIC_ADDRESS.ordinal());
		dynAddrCol.setCellRenderer(CustomToStringCellRenderer.MONO_OBJECT);
		TableColumn statAddrCol =
			columnModel.getColumn(StaticMappingTableColumns.STATIC_ADDRESS.ordinal());
		statAddrCol.setCellRenderer(CustomToStringCellRenderer.MONO_OBJECT);
		TableColumn lengthCol = columnModel.getColumn(StaticMappingTableColumns.LENGTH.ordinal());
		// TODO: Get user column settings working. Still, should default to Hex
		lengthCol.setCellRenderer(CustomToStringCellRenderer.MONO_BIG_HEX);
		TableColumn shiftCol = columnModel.getColumn(StaticMappingTableColumns.SHIFT.ordinal());
		shiftCol.setCellRenderer(CustomToStringCellRenderer.MONO_LONG_HEX);
	}

	protected void createActions() {
		actionAdd = AddAction.builder(plugin)
				.description("Add Mapping from Listing Selections")
				.onAction(this::activatedAdd)
				.buildAndInstallLocal(this);
		actionRemove = RemoveAction.builder(plugin)
				.withContext(DebuggerStaticMappingActionContext.class)
				.enabledWhen(ctx -> !ctx.getSelectedMappings().isEmpty())
				.onAction(this::activatedRemove)
				.buildAndInstallLocal(this);
		actionSelectCurrent = SelectRowsAction.builder(plugin)
				.description("Select mappings by trace selection")
				.enabledWhen(ctx -> currentTrace != null)
				.onAction(this::activatedSelectCurrent)
				.buildAndInstallLocal(this);

		contextChanged();
	}

	private void activatedAdd(ActionContext ignore) {
		tool.showDialog(addMappingDialog);
		// Try to populate the dialog based on selection, if applicable

		if (codeViewerService == null || listingService == null) {
			return;
		}
		ProgramLocation progLoc = codeViewerService.getCurrentLocation();
		ProgramLocation traceLoc = listingService.getCurrentLocation();

		if (progLoc == null || traceLoc == null) {
			return;
		}

		ProgramSelection progSel = codeViewerService.getCurrentSelection();
		ProgramSelection traceSel = listingService.getCurrentSelection();

		if (progSel != null && progSel.getNumAddressRanges() > 1) {
			return;
		}
		if (traceSel != null && traceSel.getNumAddressRanges() > 1) {
			return;
		}

		long progLen = progSel == null ? 0 : progSel.getNumAddresses();
		long traceLen = traceSel == null ? 0 : traceSel.getNumAddresses();
		if (progLen == 0 && traceLen == 0) {
			return;
		}

		long length = progLen == 0 ? traceLen
				: traceLen == 0 ? progLen : MathUtilities.unsignedMin(progLen, traceLen);
		Address progStart = progLen != 0 ? progSel.getMinAddress() : progLoc.getAddress();
		Address traceStart = traceLen != 0 ? traceSel.getMinAddress() : traceLoc.getAddress();
		TraceProgramView view = (TraceProgramView) traceLoc.getProgram();

		try {
			addMappingDialog.setValues(progLoc.getProgram(), currentTrace, progStart, traceStart,
				length, Range.atLeast(view.getSnap()));
		}
		catch (AddressOverflowException e) {
			Msg.showError(this, null, "Add Mapping", "Error populating dialog");
		}
	}

	private void activatedRemove(DebuggerStaticMappingActionContext ctx) {
		// TODO: Action to adjust life span?
		// Note: provider displays mappings for all time, so delete means delete, not truncate
		try (UndoableTransaction tid =
			UndoableTransaction.start(currentTrace, "Remove Static Mappings", false)) {
			for (StaticMappingRow mapping : ctx.getSelectedMappings()) {
				mapping.getMapping().delete();
			}
			// TODO: Do I want all-or-nothing among all transactions?
			tid.commit();
		}
	}

	private void activatedSelectCurrent(ActionContext ignored) {
		if (listingService == null || traceManager == null || currentTrace == null) {
			return;
		}
		// TODO: Select from other listings?
		ProgramSelection progSel = listingService.getCurrentSelection();

		TraceStaticMappingManager mappingManager = currentTrace.getStaticMappingManager();
		if (progSel != null && !progSel.isEmpty()) {
			Set<TraceStaticMapping> mappingSel = new HashSet<>();
			for (AddressRange range : progSel) {
				mappingSel.addAll(mappingManager.findAllOverlapping(range,
					Range.singleton(traceManager.getCurrentSnap())));
			}
			setSelectedMappings(mappingSel);
			return;
		}
		ProgramLocation progLoc = listingService.getCurrentLocation();
		if (progLoc != null) {
			TraceStaticMapping mapping =
				mappingManager.findContaining(progLoc.getAddress(), traceManager.getCurrentSnap());
			if (mapping != null) {
				setSelectedMappings(Set.of(mapping));
				return;
			}
		}

		// TODO: Select none on error? Report the error? Other SelectRowsAction uses?
	}

	public void setSelectedMappings(Set<TraceStaticMapping> sel) {
		DebuggerResources.setSelectedRows(sel, StaticMappingRow::getMapping, mappingTable,
			mappingFilterPanel);
	}

	private void removeOldListeners() {
		if (currentTrace == null) {
			return;
		}
		currentTrace.removeListener(listener);
	}

	private void addNewListeners() {
		if (currentTrace == null) {
			return;
		}
		currentTrace.addListener(listener);
	}

	public void setTrace(Trace trace) {
		if (currentTrace == trace) {
			return;
		}
		removeOldListeners();
		currentTrace = trace;
		addNewListeners();
		loadMappings();

		addMappingDialog.setTrace(trace);
	}

	public void setProgram(Program program) {
		addMappingDialog.setProgram(program);
	}
}
