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
import java.awt.event.MouseEvent;
import java.util.*;
import java.util.Map.Entry;

import javax.swing.*;

import org.apache.commons.lang3.ArrayUtils;

import db.Transaction;
import docking.ActionContext;
import docking.WindowPosition;
import docking.action.*;
import docking.action.builder.ActionBuilder;
import docking.action.builder.ToggleActionBuilder;
import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.gui.DebuggerBlockChooserDialog;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.AbstractSelectAddressesAction;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.SelectRowsAction;
import ghidra.app.plugin.core.debug.gui.model.DebuggerObjectActionContext;
import ghidra.app.plugin.core.debug.gui.modules.DebuggerModulesProvider;
import ghidra.app.plugin.core.debug.service.modules.MapRegionsBackgroundCommand;
import ghidra.app.services.*;
import ghidra.app.services.RegionMapProposal.RegionMapEntry;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Trace;
import ghidra.trace.model.memory.TraceMemoryManager;
import ghidra.trace.model.memory.TraceMemoryRegion;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;

public class DebuggerRegionsProvider extends ComponentProviderAdapter {

	protected static boolean sameCoordinates(DebuggerCoordinates a, DebuggerCoordinates b) {
		if (!Objects.equals(a.getTrace(), b.getTrace())) {
			return false;
		}
		if (a.getSnap() != b.getSnap()) {
			return false;
		}
		if (!Objects.equals(a.getObject(), b.getObject())) {
			return false;
		}
		return true;
	}

	interface MapRegionsAction {
		String NAME = DebuggerResources.NAME_MAP_REGIONS;
		String DESCRIPTION = DebuggerResources.DESCRIPTION_MAP_REGIONS;
		String GROUP = DebuggerResources.GROUP_MAPPING;
		String HELP_ANCHOR = "map_regions";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME, ownerName)
					.description(DESCRIPTION)
					.popupMenuPath(NAME)
					.popupMenuGroup(GROUP)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	interface MapRegionToAction {
		String NAME_PREFIX = DebuggerResources.NAME_PREFIX_MAP_REGION_TO;
		String DESCRIPTION = DebuggerResources.DESCRIPTION_MAP_REGION_TO;
		String GROUP = DebuggerResources.GROUP_MAPPING;
		String HELP_ANCHOR = "map_region_to";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME_PREFIX, ownerName)
					.description(DESCRIPTION)
					.popupMenuPath(NAME_PREFIX + "...")
					.popupMenuGroup(GROUP)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	interface MapRegionsToAction {
		String NAME_PREFIX = DebuggerResources.NAME_PREFIX_MAP_REGIONS_TO;
		String DESCRIPTION = DebuggerResources.DESCRIPTION_MAP_REGIONS_TO;
		Icon ICON = DebuggerResources.ICON_MAP_SECTIONS;
		String GROUP = DebuggerResources.GROUP_MAPPING;
		String HELP_ANCHOR = "map_regions_to";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME_PREFIX, ownerName)
					.description(DESCRIPTION)
					.popupMenuPath(NAME_PREFIX + "...")
					.popupMenuGroup(GROUP)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	interface AddRegionAction {
		String NAME = "Add Region";
		String DESCRIPTION = "Manually add a region to the memory map";
		String GROUP = DebuggerResources.GROUP_MAINTENANCE;
		String HELP_ANCHOR = "add_region";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME, ownerName)
					.description(DESCRIPTION)
					.menuGroup(GROUP)
					.menuPath(NAME)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	interface DeleteRegionsAction {
		String NAME = "Delete Regions";
		String DESCRIPTION = "Delete one or more regions from the memory map";
		String GROUP = DebuggerResources.GROUP_MAINTENANCE;
		String HELP_ANCHOR = "delete_regions";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME, ownerName)
					.description(DESCRIPTION)
					.popupMenuGroup(GROUP)
					.popupMenuPath(NAME, "Yes, really. Delete them!")
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	interface ForceFullViewAction {
		String NAME = "Force Full View";
		String DESCRIPTION = "Ignore regions and fiew full address spaces";
		String GROUP = DebuggerResources.GROUP_GENERAL;
		String HELP_ANCHOR = "force_full_view";

		static ToggleActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ToggleActionBuilder(NAME, ownerName)
					.description(DESCRIPTION)
					.menuGroup(GROUP)
					.menuPath(NAME)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
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
			Set<TraceMemoryRegion> regions = getSelectedRegions(context);
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
			Set<TraceMemoryRegion> sel = getSelectedRegions(context);
			return sel != null && !sel.isEmpty();
		}
	}

	final DebuggerRegionsPlugin plugin;

	@AutoServiceConsumed
	ProgramManager programManager;
	@AutoServiceConsumed
	DebuggerListingService listingService;
	@AutoServiceConsumed
	private DebuggerStaticMappingService staticMappingService;
	@AutoServiceConsumed
	private DebuggerTraceManagerService traceManager;
	@SuppressWarnings("unused")
	private final AutoService.Wiring autoServiceWiring;

	private DebuggerCoordinates current = DebuggerCoordinates.NOWHERE;
	private Program currentProgram;
	private ProgramLocation currentLocation;

	private final JPanel mainPanel = new JPanel(new BorderLayout());

	DebuggerRegionsPanel panel;
	DebuggerLegacyRegionsPanel legacyPanel;

	// TODO: Lazy construction of these dialogs?
	private final DebuggerBlockChooserDialog blockChooserDialog;
	private final DebuggerRegionMapProposalDialog regionProposalDialog;
	private final DebuggerAddRegionDialog addRegionDialog;

	DockingAction actionMapRegions;
	DockingAction actionMapRegionTo;
	DockingAction actionMapRegionsTo;

	SelectAddressesAction actionSelectAddresses;
	DockingAction actionSelectRows;
	DockingAction actionAddRegion;
	DockingAction actionDeleteRegions;
	ToggleDockingAction actionForceFullView;

	public DebuggerRegionsProvider(DebuggerRegionsPlugin plugin) {
		super(plugin.getTool(), DebuggerResources.TITLE_PROVIDER_REGIONS, plugin.getName(),
			DebuggerRegionActionContext.class);
		this.plugin = plugin;

		setIcon(DebuggerResources.ICON_PROVIDER_REGIONS);
		setHelpLocation(DebuggerResources.HELP_PROVIDER_REGIONS);
		setWindowMenuGroup(DebuggerPluginPackage.NAME);

		buildMainPanel();

		this.autoServiceWiring = AutoService.wireServicesConsumed(plugin, this);

		blockChooserDialog = new DebuggerBlockChooserDialog(tool);
		regionProposalDialog = new DebuggerRegionMapProposalDialog(this);
		addRegionDialog = new DebuggerAddRegionDialog();

		setDefaultWindowPosition(WindowPosition.BOTTOM);
		setVisible(true);
		createActions();
	}

	void dispose() {
		blockChooserDialog.dispose();
		regionProposalDialog.dispose();
	}

	protected void buildMainPanel() {
		panel = new DebuggerRegionsPanel(this);
		mainPanel.add(panel);
		legacyPanel = new DebuggerLegacyRegionsPanel(this);
	}

	protected void createActions() {
		actionMapRegions = MapRegionsAction.builder(plugin)
				.enabledWhen(this::isContextNonEmpty)
				.popupWhen(this::isContextNonEmpty)
				.onAction(this::activatedMapRegions)
				.buildAndInstallLocal(this);
		actionMapRegionTo = MapRegionToAction.builder(plugin)
				.enabledWhen(ctx -> currentProgram != null && isContextSingleSelection(ctx))
				.popupWhen(ctx -> currentProgram != null && isContextSingleSelection(ctx))
				.onAction(this::activatedMapRegionTo)
				.buildAndInstallLocal(this);
		actionMapRegionsTo = MapRegionsToAction.builder(plugin)
				.enabledWhen(ctx -> currentProgram != null && isContextNonEmpty(ctx))
				.popupWhen(ctx -> currentProgram != null && isContextNonEmpty(ctx))
				.onAction(this::activatedMapRegionsTo)
				.buildAndInstallLocal(this);
		actionSelectAddresses = new SelectAddressesAction();
		actionSelectRows = SelectRowsAction.builder(plugin)
				.description("Select regions by dynamic selection")
				.enabledWhen(ctx -> current.getTrace() != null)
				.onAction(this::activatedSelectCurrent)
				.buildAndInstallLocal(this);
		actionAddRegion = AddRegionAction.builder(plugin)
				.enabledWhen(ctx -> current.getTrace() != null)
				.onAction(this::activatedAddRegion)
				.buildAndInstallLocal(this);
		actionDeleteRegions = DeleteRegionsAction.builder(plugin)
				.enabledWhen(this::isContextNonEmpty)
				.onAction(this::activatedDeleteRegions)
				.buildAndInstallLocal(this);
		actionForceFullView = ForceFullViewAction.builder(plugin)
				.enabledWhen(ctx -> current.getTrace() != null)
				.onAction(this::activatedForceFullView)
				.buildAndInstallLocal(this);
		contextChanged();
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		final ActionContext context;
		if (Trace.isLegacy(current.getTrace())) {
			context = legacyPanel.getActionContext();
		}
		else {
			context = panel.getActionContext();
		}
		if (context != null) {
			return context;
		}
		return super.getActionContext(event);
	}

	private boolean isContextNonEmpty(ActionContext context) {
		if (context instanceof DebuggerRegionActionContext legacyCtx) {
			return legacyPanel.isContextNonEmpty(legacyCtx);
		}
		else if (context instanceof DebuggerObjectActionContext ctx) {
			return DebuggerRegionsPanel.isContextNonEmpty(ctx);
		}
		return false;
	}

	private boolean isContextSingleSelection(ActionContext context) {
		Set<TraceMemoryRegion> sel = getSelectedRegions(context);
		return sel != null && sel.size() == 1;
	}

	private static Set<TraceMemoryRegion> getSelectedRegions(ActionContext context) {
		if (context instanceof DebuggerRegionActionContext legacyCtx) {
			return DebuggerLegacyRegionsPanel.getSelectedRegions(legacyCtx);
		}
		else if (context instanceof DebuggerObjectActionContext ctx) {
			return DebuggerRegionsPanel.getSelectedRegions(ctx);
		}
		return null;
	}

	private void activatedMapRegions(ActionContext context) {
		mapRegions(getSelectedRegions(context));
	}

	private void activatedMapRegionTo(ActionContext context) {
		Set<TraceMemoryRegion> sel = getSelectedRegions(context);
		if (sel == null || sel.size() != 1) {
			return;
		}
		mapRegionTo(sel.iterator().next());
	}

	private void activatedMapRegionsTo(ActionContext context) {
		Set<TraceMemoryRegion> sel = getSelectedRegions(context);
		if (sel == null || sel.isEmpty()) {
			return;
		}
		mapRegionsTo(sel);
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
			new MapRegionsBackgroundCommand(staticMappingService, adjusted), current.getTrace());
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
		if (listingService == null || traceManager == null || current.getTrace() == null) {
			return;
		}
		// TODO: Select from other listings?
		ProgramSelection progSel = listingService.getCurrentSelection();

		TraceMemoryManager memoryManager = current.getTrace().getMemoryManager();
		if (progSel != null && !progSel.isEmpty()) {
			Set<TraceMemoryRegion> regSel = new HashSet<>();
			for (AddressRange range : progSel) {
				regSel.addAll(memoryManager.getRegionsIntersecting(
					Lifespan.at(traceManager.getCurrentSnap()), range));
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

	private void activatedAddRegion(ActionContext ignored) {
		if (current.getTrace() == null) {
			return;
		}
		addRegionDialog.show(tool, current.getTrace(), current.getSnap());
	}

	private void activatedDeleteRegions(ActionContext ctx) {
		Set<TraceMemoryRegion> sel = getSelectedRegions(ctx);
		if (sel.isEmpty()) {
			return;
		}
		try (Transaction tx = current.getTrace().openTransaction("Delete regions")) {
			for (TraceMemoryRegion region : sel) {
				region.delete();
			}
		}
	}

	private void activatedForceFullView(ActionContext ignored) {
		if (current.getTrace() == null) {
			return;
		}
		current.getTrace()
				.getProgramView()
				.getMemory()
				.setForceFullView(actionForceFullView.isSelected());
	}

	public void setSelectedRegions(Set<TraceMemoryRegion> sel) {
		if (Trace.isLegacy(current.getTrace())) {
			legacyPanel.setSelectedRegions(sel);
		}
		else {
			panel.setSelectedRegions(sel);
		}
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

	@Override
	public void contextChanged() {
		super.contextChanged();
		if (current.getTrace() != null) {
			actionForceFullView.setSelected(current.getTrace()
					.getProgramView()
					.getMemory()
					.isForceFullView());
		}
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

	public void coordinatesActivated(DebuggerCoordinates coordinates) {
		if (sameCoordinates(current, coordinates)) {
			current = coordinates;
			return;
		}

		current = coordinates;

		if (Trace.isLegacy(coordinates.getTrace())) {
			panel.coordinatesActivated(DebuggerCoordinates.NOWHERE);
			legacyPanel.coordinatesActivated(coordinates);
			if (ArrayUtils.indexOf(mainPanel.getComponents(), legacyPanel) == -1) {
				mainPanel.remove(panel);
				mainPanel.add(legacyPanel);
				mainPanel.validate();
			}
		}
		else {
			legacyPanel.coordinatesActivated(DebuggerCoordinates.NOWHERE);
			panel.coordinatesActivated(coordinates);
			if (ArrayUtils.indexOf(mainPanel.getComponents(), panel) == -1) {
				mainPanel.remove(legacyPanel);
				mainPanel.add(panel);
				mainPanel.validate();
			}
		}
	}
}
