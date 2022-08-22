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
package ghidra.app.plugin.core.debug.gui.memory;

import java.awt.BorderLayout;
import java.awt.event.*;
import java.util.*;
import java.util.Map.Entry;
import java.util.function.BiConsumer;
import java.util.function.Function;
import java.util.stream.Collectors;

import javax.swing.*;
import javax.swing.table.TableColumn;
import javax.swing.table.TableColumnModel;

import com.google.common.collect.Range;

import docking.ActionContext;
import docking.WindowPosition;
import docking.action.*;
import docking.widgets.table.CustomToStringCellRenderer;
import docking.widgets.table.DefaultEnumeratedColumnTableModel.EnumeratedTableColumn;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.gui.DebuggerBlockChooserDialog;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.*;
import ghidra.app.plugin.core.debug.gui.modules.DebuggerModulesProvider;
import ghidra.app.plugin.core.debug.service.modules.MapRegionsBackgroundCommand;
import ghidra.app.plugin.core.debug.utils.DebouncedRowWrappedEnumeratedColumnTableModel;
import ghidra.app.services.*;
import ghidra.app.services.RegionMapProposal.RegionMapEntry;
import ghidra.framework.model.DomainObject;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.trace.model.Trace;
import ghidra.trace.model.Trace.TraceMemoryRegionChangeType;
import ghidra.trace.model.TraceDomainObjectListener;
import ghidra.trace.model.memory.TraceMemoryManager;
import ghidra.trace.model.memory.TraceMemoryRegion;
import ghidra.util.Msg;
import ghidra.util.database.ObjectKey;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.GhidraTableFilterPanel;

public class DebuggerRegionsProvider extends ComponentProviderAdapter {

	protected enum RegionTableColumns
		implements EnumeratedTableColumn<RegionTableColumns, RegionRow> {
		NAME("Name", String.class, RegionRow::getName, RegionRow::setName),
		LIFESPAN("Lifespan", Range.class, RegionRow::getLifespan),
		START("Start", Address.class, RegionRow::getMinAddress),
		END("End", Address.class, RegionRow::getMaxAddress),
		LENGTH("Length", Long.class, RegionRow::getLength),
		READ("Read", Boolean.class, RegionRow::isRead, RegionRow::setRead),
		WRITE("Write", Boolean.class, RegionRow::isWrite, RegionRow::setWrite),
		EXECUTE("Execute", Boolean.class, RegionRow::isExecute, RegionRow::setExecute),
		VOLATILE("Volatile", Boolean.class, RegionRow::isVolatile, RegionRow::setVolatile);

		private final String header;
		private final Function<RegionRow, ?> getter;
		private final BiConsumer<RegionRow, Object> setter;
		private final Class<?> cls;

		@SuppressWarnings("unchecked")
		<T> RegionTableColumns(String header, Class<T> cls, Function<RegionRow, T> getter,
				BiConsumer<RegionRow, T> setter) {
			this.header = header;
			this.cls = cls;
			this.getter = getter;
			this.setter = (BiConsumer<RegionRow, Object>) setter;
		}

		<T> RegionTableColumns(String header, Class<T> cls, Function<RegionRow, T> getter) {
			this(header, cls, getter, null);
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
		public boolean isEditable(RegionRow row) {
			return setter != null;
		}

		@Override
		public void setValueOf(RegionRow row, Object value) {
			setter.accept(row, value);
		}

		@Override
		public Object getValueOf(RegionRow row) {
			return getter.apply(row);
		}
	}

	protected static class RegionTableModel
			extends DebouncedRowWrappedEnumeratedColumnTableModel< //
					RegionTableColumns, ObjectKey, RegionRow, TraceMemoryRegion> {

		public RegionTableModel(PluginTool tool) {
			super(tool, "Regions", RegionTableColumns.class, TraceMemoryRegion::getObjectKey,
				RegionRow::new);
		}
	}

	protected static RegionRow getSelectedRegionRow(ActionContext context) {
		if (!(context instanceof DebuggerRegionActionContext)) {
			return null;
		}
		DebuggerRegionActionContext ctx = (DebuggerRegionActionContext) context;
		Set<RegionRow> regions = ctx.getSelectedRegions();
		if (regions.size() != 1) {
			return null;
		}
		return regions.iterator().next();
	}

	protected static Set<TraceMemoryRegion> getSelectedRegions(ActionContext context) {
		if (!(context instanceof DebuggerRegionActionContext)) {
			return null;
		}
		DebuggerRegionActionContext ctx = (DebuggerRegionActionContext) context;
		return ctx.getSelectedRegions()
				.stream()
				.map(r -> r.getRegion())
				.collect(Collectors.toSet());
	}

	private class RegionsListener extends TraceDomainObjectListener {
		public RegionsListener() {
			listenForUntyped(DomainObject.DO_OBJECT_RESTORED, e -> objectRestored());

			listenFor(TraceMemoryRegionChangeType.ADDED, this::regionAdded);
			listenFor(TraceMemoryRegionChangeType.CHANGED, this::regionChanged);
			listenFor(TraceMemoryRegionChangeType.LIFESPAN_CHANGED, this::regionChanged);
			listenFor(TraceMemoryRegionChangeType.DELETED, this::regionDeleted);
		}

		private void objectRestored() {
			loadRegions();
		}

		private void regionAdded(TraceMemoryRegion region) {
			regionTableModel.addItem(region);
		}

		private void regionChanged(TraceMemoryRegion region) {
			regionTableModel.updateItem(region);
		}

		private void regionDeleted(TraceMemoryRegion region) {
			regionTableModel.deleteItem(region);
		}
	}

	protected class SelectAddressesAction extends AbstractSelectAddressesAction {
		public static final String GROUP = DebuggerResources.GROUP_GENERAL;

		public SelectAddressesAction() {
			super(plugin);
			setDescription("Select addresses contained in regions");
			setToolBarData(new ToolBarData(ICON, GROUP));
			setPopupMenuData(new MenuData(new String[] { NAME }, GROUP));
			addLocalAction(this);
			setEnabled(false);
		}

		@Override
		public void actionPerformed(ActionContext context) {
			if (listingService == null) {
				return;
			}
			Set<TraceMemoryRegion> regions = getSelectedRegions(myActionContext);
			if (regions == null) {
				return;
			}
			AddressSet sel = new AddressSet();
			for (TraceMemoryRegion s : regions) {
				sel.add(s.getRange());
			}
			ProgramSelection ps = new ProgramSelection(sel);
			listingService.setCurrentSelection(ps);
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			Set<TraceMemoryRegion> sel = getSelectedRegions(myActionContext);
			return sel != null && !sel.isEmpty();
		}
	}

	private final DebuggerRegionsPlugin plugin;

	@AutoServiceConsumed
	private DebuggerStaticMappingService staticMappingService;
	@AutoServiceConsumed
	private DebuggerTraceManagerService traceManager;
	@AutoServiceConsumed
	private DebuggerListingService listingService;
	@AutoServiceConsumed
	ProgramManager programManager;
	@SuppressWarnings("unused")
	private final AutoService.Wiring autoServiceWiring;

	private Trace currentTrace;

	private final RegionsListener regionsListener = new RegionsListener();

	protected final RegionTableModel regionTableModel;
	protected GhidraTable regionTable;
	private GhidraTableFilterPanel<RegionRow> regionFilterPanel;

	private final JPanel mainPanel = new JPanel(new BorderLayout());

	// TODO: Lazy construction of these dialogs?
	private final DebuggerBlockChooserDialog blockChooserDialog;
	private final DebuggerRegionMapProposalDialog regionProposalDialog;

	private DebuggerRegionActionContext myActionContext;
	private Program currentProgram;
	private ProgramLocation currentLocation;

	DockingAction actionMapRegions;
	DockingAction actionMapRegionTo;
	DockingAction actionMapRegionsTo;

	SelectAddressesAction actionSelectAddresses;
	DockingAction actionSelectRows;
	ToggleDockingAction actionForceFullView;

	public DebuggerRegionsProvider(DebuggerRegionsPlugin plugin) {
		super(plugin.getTool(), DebuggerResources.TITLE_PROVIDER_REGIONS, plugin.getName(),
			DebuggerRegionActionContext.class);
		this.plugin = plugin;

		regionTableModel = new RegionTableModel(tool);

		setIcon(DebuggerResources.ICON_PROVIDER_REGIONS);
		setHelpLocation(DebuggerResources.HELP_PROVIDER_REGIONS);
		setWindowMenuGroup(DebuggerPluginPackage.NAME);

		buildMainPanel();

		this.autoServiceWiring = AutoService.wireServicesConsumed(plugin, this);

		blockChooserDialog = new DebuggerBlockChooserDialog(tool);
		regionProposalDialog = new DebuggerRegionMapProposalDialog(this);

		setDefaultWindowPosition(WindowPosition.BOTTOM);
		setVisible(true);
		createActions();
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		if (myActionContext == null) {
			return super.getActionContext(event);
		}
		return myActionContext;
	}

	private void loadRegions() {
		regionTableModel.clear();

		if (currentTrace == null) {
			return;
		}
		TraceMemoryManager memoryManager = currentTrace.getMemoryManager();
		regionTableModel.addAllItems(memoryManager.getAllRegions());
	}

	protected void buildMainPanel() {
		regionTable = new GhidraTable(regionTableModel);
		regionTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
		mainPanel.add(new JScrollPane(regionTable));
		regionFilterPanel = new GhidraTableFilterPanel<>(regionTable, regionTableModel);
		mainPanel.add(regionFilterPanel, BorderLayout.SOUTH);

		regionTable.getSelectionModel().addListSelectionListener(evt -> {
			myActionContext = new DebuggerRegionActionContext(this,
				regionFilterPanel.getSelectedItems(), regionTable);
			contextChanged();
		});
		// Note, ProgramTableModel will not work here, since that would navigate the "static" view
		regionTable.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (e.getClickCount() == 2) {
					navigateToSelectedRegion();
				}
			}
		});
		regionTable.addKeyListener(new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				if (e.getKeyCode() == KeyEvent.VK_ENTER) {
					navigateToSelectedRegion();
				}
			}
		});

		// TODO: Adjust default column widths?
		TableColumnModel columnModel = regionTable.getColumnModel();

		TableColumn startCol = columnModel.getColumn(RegionTableColumns.START.ordinal());
		startCol.setCellRenderer(CustomToStringCellRenderer.MONO_OBJECT);

		TableColumn endCol = columnModel.getColumn(RegionTableColumns.END.ordinal());
		endCol.setCellRenderer(CustomToStringCellRenderer.MONO_OBJECT);

		TableColumn lenCol = columnModel.getColumn(RegionTableColumns.LENGTH.ordinal());
		lenCol.setCellRenderer(CustomToStringCellRenderer.MONO_ULONG_HEX);

		final int small = 100;
		TableColumn rCol = columnModel.getColumn(RegionTableColumns.READ.ordinal());
		rCol.setPreferredWidth(small);
		TableColumn wCol = columnModel.getColumn(RegionTableColumns.WRITE.ordinal());
		wCol.setPreferredWidth(small);
		TableColumn eCol = columnModel.getColumn(RegionTableColumns.EXECUTE.ordinal());
		eCol.setPreferredWidth(small);
		TableColumn vCol = columnModel.getColumn(RegionTableColumns.VOLATILE.ordinal());
		vCol.setPreferredWidth(small);
	}

	protected void navigateToSelectedRegion() {
		if (listingService != null) {
			int selectedRow = regionTable.getSelectedRow();
			int selectedColumn = regionTable.getSelectedColumn();
			Object value = regionTable.getValueAt(selectedRow, selectedColumn);
			if (value instanceof Address) {
				listingService.goTo((Address) value, true);
			}
		}
	}

	protected void createActions() {
		actionMapRegions = MapRegionsAction.builder(plugin)
				.withContext(DebuggerRegionActionContext.class)
				.enabledWhen(this::isContextNonEmpty)
				.popupWhen(this::isContextNonEmpty)
				.onAction(this::activatedMapRegions)
				.buildAndInstallLocal(this);
		actionMapRegionTo = MapRegionToAction.builder(plugin)
				.withContext(DebuggerRegionActionContext.class)
				.enabledWhen(ctx -> currentProgram != null && ctx.getSelectedRegions().size() == 1)
				.popupWhen(ctx -> currentProgram != null && ctx.getSelectedRegions().size() == 1)
				.onAction(this::activatedMapRegionTo)
				.buildAndInstallLocal(this);
		actionMapRegionsTo = MapRegionsToAction.builder(plugin)
				.withContext(DebuggerRegionActionContext.class)
				.enabledWhen(ctx -> currentProgram != null && isContextNonEmpty(ctx))
				.popupWhen(ctx -> currentProgram != null && isContextNonEmpty(ctx))
				.onAction(this::activatedMapRegionsTo)
				.buildAndInstallLocal(this);
		actionSelectAddresses = new SelectAddressesAction();
		actionSelectRows = SelectRowsAction.builder(plugin)
				.description("Select regions by trace selection")
				.enabledWhen(ctx -> currentTrace != null)
				.onAction(this::activatedSelectCurrent)
				.buildAndInstallLocal(this);
		actionForceFullView = ForceFullViewAction.builder(plugin)
				.enabledWhen(ctx -> currentTrace != null)
				.onAction(this::activatedForceFullView)
				.buildAndInstallLocal(this);
		contextChanged();
	}

	private boolean isContextNonEmpty(DebuggerRegionActionContext ctx) {
		return !ctx.getSelectedRegions().isEmpty();
	}

	private static Set<TraceMemoryRegion> getSelectedRegions(DebuggerRegionActionContext ctx) {
		if (ctx == null) {
			return null;
		}
		return ctx.getSelectedRegions()
				.stream()
				.map(r -> r.getRegion())
				.collect(Collectors.toSet());
	}

	private void activatedMapRegions(DebuggerRegionActionContext ignored) {
		mapRegions(getSelectedRegions(myActionContext));
	}

	private void activatedMapRegionsTo(DebuggerRegionActionContext ignored) {
		Set<TraceMemoryRegion> sel = getSelectedRegions(myActionContext);
		if (sel == null || sel.isEmpty()) {
			return;
		}
		mapRegionsTo(sel);
	}

	private void activatedMapRegionTo(DebuggerRegionActionContext ignored) {
		Set<TraceMemoryRegion> sel = getSelectedRegions(myActionContext);
		if (sel == null || sel.size() != 1) {
			return;
		}
		mapRegionTo(sel.iterator().next());
	}

	protected void promptRegionProposal(Collection<RegionMapEntry> proposal) {
		if (proposal.isEmpty()) {
			Msg.showInfo(this, getComponent(), "Map Regions",
				"Could not formulate a propsal for any selection region." +
					" You may need to import and/or open the destination images first.");
			return;
		}
		Collection<RegionMapEntry> adjusted =
			regionProposalDialog.adjustCollection(getTool(), proposal);
		if (adjusted == null || staticMappingService == null) {
			return;
		}
		tool.executeBackgroundCommand(
			new MapRegionsBackgroundCommand(staticMappingService, adjusted), currentTrace);
	}

	protected void mapRegions(Set<TraceMemoryRegion> regions) {
		if (staticMappingService == null) {
			return;
		}
		Map<?, RegionMapProposal> map = staticMappingService.proposeRegionMaps(regions,
			List.of(programManager.getAllOpenPrograms()));
		Collection<RegionMapEntry> proposal = MapProposal.flatten(map.values());
		promptRegionProposal(proposal);
	}

	protected void mapRegionsTo(Set<TraceMemoryRegion> regions) {
		if (staticMappingService == null) {
			return;
		}
		Program program = currentProgram;
		if (program == null) {
			return;
		}
		RegionMapProposal map = staticMappingService.proposeRegionMap(regions, program);
		Collection<RegionMapEntry> proposal = map.computeMap().values();
		promptRegionProposal(proposal);
	}

	protected void mapRegionTo(TraceMemoryRegion region) {
		if (staticMappingService == null) {
			return;
		}
		ProgramLocation location = currentLocation;
		MemoryBlock block = computeBlock(location);
		if (block == null) {
			return;
		}
		RegionMapProposal map =
			staticMappingService.proposeRegionMap(region, location.getProgram(), block);
		promptRegionProposal(map.computeMap().values());
	}

	private void activatedSelectCurrent(ActionContext ignored) {
		if (listingService == null || traceManager == null || currentTrace == null) {
			return;
		}
		// TODO: Select from other listings?
		ProgramSelection progSel = listingService.getCurrentSelection();

		TraceMemoryManager memoryManager = currentTrace.getMemoryManager();
		if (progSel != null && !progSel.isEmpty()) {
			Set<TraceMemoryRegion> regSel = new HashSet<>();
			for (AddressRange range : progSel) {
				regSel.addAll(memoryManager.getRegionsIntersecting(
					Range.singleton(traceManager.getCurrentSnap()), range));
			}
			setSelectedRegions(regSel);
			return;
		}
		ProgramLocation progLoc = listingService.getCurrentLocation();
		if (progLoc != null) {
			TraceMemoryRegion reg = memoryManager.getRegionContaining(traceManager.getCurrentSnap(),
				progLoc.getAddress());
			if (reg != null) {
				setSelectedRegions(Set.of(reg));
				return;
			}
		}
	}

	private void activatedForceFullView(ActionContext ignored) {
		if (currentTrace == null) {
			return;
		}
		currentTrace.getProgramView()
				.getMemory()
				.setForceFullView(actionForceFullView.isSelected());
	}

	public void setSelectedRegions(Set<TraceMemoryRegion> sel) {
		DebuggerResources.setSelectedRows(sel, regionTableModel::getRow, regionTable,
			regionTableModel, regionFilterPanel);
	}

	public Collection<RegionRow> getSelectedRows() {
		return regionFilterPanel.getSelectedItems();
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}

	public void setProgram(Program program) {
		currentProgram = program;
		String name = (program == null ? "..." : program.getName());
		actionMapRegionTo.getPopupMenuData().setMenuItemName(MapRegionToAction.NAME_PREFIX + name);
		actionMapRegionsTo.getPopupMenuData()
				.setMenuItemName(MapRegionsToAction.NAME_PREFIX + name);
	}

	public static MemoryBlock computeBlock(ProgramLocation location) {
		return DebuggerModulesProvider.computeBlock(location);
	}

	public static String computeBlockName(ProgramLocation location) {
		return DebuggerModulesProvider.computeBlockName(location);
	}

	public void setLocation(ProgramLocation location) {
		currentLocation = location;
		String name = MapRegionToAction.NAME_PREFIX + computeBlockName(location);
		actionMapRegionTo.getPopupMenuData().setMenuItemName(name);
	}

	public void programClosed(Program program) {
		if (currentProgram == program) {
			currentProgram = null;
		}
	}

	public void setTrace(Trace trace) {
		if (currentTrace == trace) {
			return;
		}
		removeOldListeners();
		currentTrace = trace;
		addNewListeners();
		loadRegions();
		contextChanged();
	}

	@Override
	public void contextChanged() {
		super.contextChanged();
		if (currentTrace != null) {
			actionForceFullView.setSelected(currentTrace.getProgramView()
					.getMemory()
					.isForceFullView());
		}
	}

	private void removeOldListeners() {
		if (currentTrace == null) {
			return;
		}
		currentTrace.removeListener(regionsListener);
	}

	private void addNewListeners() {
		if (currentTrace == null) {
			return;
		}
		currentTrace.addListener(regionsListener);
	}

	public Entry<Program, MemoryBlock> askBlock(TraceMemoryRegion region, Program program,
			MemoryBlock block) {
		if (programManager == null) {
			Msg.warn(this, "No program manager!");
			return null;
		}
		return blockChooserDialog.chooseBlock(getTool(), region,
			List.of(programManager.getAllOpenPrograms()));
	}
}
