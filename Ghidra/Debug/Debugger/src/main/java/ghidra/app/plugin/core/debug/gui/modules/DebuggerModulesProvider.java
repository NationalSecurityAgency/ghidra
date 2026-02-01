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

import static ghidra.framework.main.DataTreeDialogType.OPEN;

import java.awt.event.MouseEvent;
import java.io.File;
import java.lang.invoke.MethodHandles;
import java.util.*;
import java.util.Map.Entry;
import java.util.stream.Collectors;

import javax.swing.*;

import docking.*;
import docking.action.*;
import docking.action.builder.*;
import docking.menu.ActionState;
import docking.menu.MultiStateDockingAction;
import docking.widgets.EventTrigger;
import docking.widgets.filechooser.GhidraFileChooser;
import generic.theme.GIcon;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.gui.DebuggerBlockChooserDialog;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.*;
import ghidra.app.plugin.core.debug.gui.action.ByModuleAutoMapSpec;
import ghidra.app.plugin.core.debug.service.modules.MapModulesBackgroundCommand;
import ghidra.app.plugin.core.debug.service.modules.MapSectionsBackgroundCommand;
import ghidra.app.services.*;
import ghidra.debug.api.action.AutoMapSpec;
import ghidra.debug.api.action.AutoMapSpec.AutoMapSpecConfigFieldCodec;
import ghidra.debug.api.model.DebuggerObjectActionContext;
import ghidra.debug.api.modules.*;
import ghidra.debug.api.modules.ModuleMapProposal.ModuleMapEntry;
import ghidra.debug.api.modules.SectionMapProposal.SectionMapEntry;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.framework.data.DomainObjectAdapterDB;
import ghidra.framework.main.AppInfo;
import ghidra.framework.main.DataTreeDialog;
import ghidra.framework.model.*;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.annotation.AutoConfigStateField;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.framework.plugintool.util.PluginException;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.trace.model.*;
import ghidra.trace.model.modules.*;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.trace.model.target.TraceObjectValue;
import ghidra.trace.util.TraceEvent;
import ghidra.trace.util.TraceEvents;
import ghidra.util.*;

public class DebuggerModulesProvider extends ComponentProviderAdapter
		implements DebuggerAutoMappingService {

	protected static final AutoConfigState.ClassHandler<DebuggerModulesProvider> CONFIG_STATE_HANDLER =
		AutoConfigState.wireHandler(DebuggerModulesProvider.class, MethodHandles.lookup());

	protected static final String NO_MODULES_PROPOSAL_SEL = """
			Could not formulate a proposal for any selected module. \
			You may need to import and/or open the destination images first.\
			""";

	protected static final String FMT_NO_MODULES_PROPOSAL_RETRY = """
			Could not formulate a proposal for program '%s' to trace '%s'. \
			The module may not be loaded yet, or the chosen image could be wrong.\
			""";

	protected static final String FMT_NO_MODULES_PROPOSAL_CURRENT = """
			Could not formulate a proposal from module '%s' to program '%s'.\
			""";

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

	interface MapIdenticallyAction {
		String NAME = DebuggerResources.NAME_MAP_IDENTICALLY;
		String DESCRIPTION = DebuggerResources.DESCRIPTION_MAP_IDENTICALLY;
		Icon ICON = DebuggerResources.ICON_MAP_IDENTICALLY;
		String GROUP = DebuggerResources.GROUP_MAPPING;
		String HELP_ANCHOR = "map_identically";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME, ownerName).description(DESCRIPTION)
					.toolBarIcon(ICON)
					.toolBarGroup(GROUP)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	interface MapManuallyAction {
		String NAME = DebuggerResources.NAME_MAP_MANUALLY;
		String DESCRIPTION = DebuggerResources.DESCRIPTION_MAP_MANUALLY;
		Icon ICON = DebuggerResources.ICON_MAP_MANUALLY;
		String GROUP = DebuggerResources.GROUP_MAPPING;
		String HELP_ANCHOR = "map_manually";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME, ownerName).description(DESCRIPTION)
					.toolBarIcon(ICON)
					.toolBarGroup(GROUP)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	interface MapModulesAction {
		String NAME = "Map Modules";
		String DESCRIPTION = DebuggerResources.DESCRIPTION_MAP_MODULES;
		String GROUP = DebuggerResources.GROUP_MAPPING;
		String HELP_ANCHOR = "map_modules";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME, ownerName).description(DESCRIPTION)
					.popupMenuPath(NAME)
					.popupMenuGroup(GROUP)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	interface MapModuleToAction {
		String NAME_PREFIX = DebuggerResources.NAME_PREFIX_MAP_MODULE_TO;
		String DESCRIPTION = DebuggerResources.DESCRIPTION_MAP_MODULE_TO;
		String GROUP = DebuggerResources.GROUP_MAPPING;
		String HELP_ANCHOR = "map_module_to";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME_PREFIX, ownerName).description(DESCRIPTION)
					.popupMenuPath(NAME_PREFIX + "...")
					.popupMenuGroup(GROUP)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	interface MapSectionsAction {
		String NAME = DebuggerResources.NAME_MAP_SECTIONS;
		String DESCRIPTION = DebuggerResources.DESCRIPTION_MAP_SECTIONS;
		String GROUP = DebuggerResources.GROUP_MAPPING;
		String HELP_ANCHOR = "map_sections";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME, ownerName).description(DESCRIPTION)
					.popupMenuPath(NAME)
					.popupMenuGroup(GROUP)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	interface MapSectionToAction {
		String NAME_PREFIX = DebuggerResources.NAME_PREFIX_MAP_SECTION_TO;
		String DESCRIPTION = DebuggerResources.DESCRIPTION_MAP_SECTION_TO;
		String GROUP = DebuggerResources.GROUP_MAPPING;
		String HELP_ANCHOR = "map_section_to";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME_PREFIX, ownerName).description(DESCRIPTION)
					.popupMenuPath(NAME_PREFIX + "...")
					.popupMenuGroup(GROUP)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	interface MapSectionsToAction {
		String NAME_PREFIX = DebuggerResources.NAME_PREFIX_MAP_SECTIONS_TO;
		String DESCRIPTION = DebuggerResources.DESCRIPTION_MAP_SECTIONS_TO;
		String GROUP = DebuggerResources.GROUP_MAPPING;
		String HELP_ANCHOR = "map_sections_to";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME_PREFIX, ownerName).description(DESCRIPTION)
					.popupMenuPath(NAME_PREFIX + "...")
					.popupMenuGroup(GROUP)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	interface AutoMapAction {
		String NAME = "Auto-Map Target Memory";
		Icon ICON = DebuggerResources.ICON_MAP_AUTO;
		String DESCRIPTION = "Automatically map dynamic memory to static counterparts";
		String GROUP = DebuggerResources.GROUP_MAPPING;
		String HELP_ANCHOR = "auto_map";

		static MultiStateActionBuilder<AutoMapSpec> builder(Plugin owner) {
			String ownerName = owner.getName();
			MultiStateActionBuilder<AutoMapSpec> builder =
				new MultiStateActionBuilder<AutoMapSpec>(NAME, ownerName)
						.description(DESCRIPTION)
						.toolBarGroup(GROUP)
						.toolBarIcon(ICON)
						.useCheckboxForIcons(true)
						.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
			for (AutoMapSpec spec : AutoMapSpec.allSpecs().values()) {
				builder.addState(spec.getMenuName(), spec.getMenuIcon(), spec);
			}
			return builder;
		}
	}

	interface ImportMissingModuleAction {
		String NAME = "Import Missing Module";
		String DESCRIPTION = "Import the missing module from disk";
		Icon ICON = DebuggerResources.ICON_IMPORT;
		String HELP_ANCHOR = "import_missing_module";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME, ownerName)
					.description(DESCRIPTION)
					.toolBarIcon(ICON)
					.popupMenuIcon(ICON)
					.popupMenuPath(NAME)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	interface MapMissingModuleAction {
		String NAME = "Map Missing Module";
		String DESCRIPTION = "Map the missing module to an existing import";
		Icon ICON = DebuggerResources.ICON_MAP_MODULES;
		String HELP_ANCHOR = "map_missing_module";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME, ownerName)
					.description(DESCRIPTION)
					.toolBarIcon(ICON)
					.popupMenuIcon(ICON)
					.popupMenuPath(NAME)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	interface MapMissingProgramRetryAction {
		String NAME = "Retry Map Missing Program";
		String DESCRIPTION = "Retry mapping the missing program by finding its module";
		Icon ICON = DebuggerResources.ICON_MAP_AUTO;
		String HELP_ANCHOR = "map_missing_program_retry";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME, ownerName)
					.description(DESCRIPTION)
					.toolBarIcon(ICON)
					.popupMenuIcon(ICON)
					.popupMenuPath(NAME)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	interface MapMissingProgramToCurrentAction {
		String NAME = "Map Missing Program to Current Module";
		String DESCRIPTION = "Map the missing program to the current module";
		Icon ICON = DebuggerResources.ICON_MAP_MODULES;
		String HELP_ANCHOR = "map_missing_program_current";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME, ownerName)
					.description(DESCRIPTION)
					.toolBarIcon(ICON)
					.popupMenuIcon(ICON)
					.popupMenuPath(NAME)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	interface MapMissingProgramIdenticallyAction {
		String NAME = "Map Missing Program Identically";
		String DESCRIPTION = "Map the missing program to its trace identically";
		Icon ICON = DebuggerResources.ICON_MAP_IDENTICALLY;
		String HELP_ANCHOR = "map_missing_program_identically";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME, ownerName)
					.description(DESCRIPTION)
					.toolBarIcon(ICON)
					.popupMenuIcon(ICON)
					.popupMenuPath(NAME)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	interface ShowSectionsTableAction {
		String NAME = "Show Sections Table";
		Icon ICON = new GIcon("icon.debugger.modules.table.sections");
		String DESCRIPTION = "Toggle display fo the Sections Table pane";
		String GROUP = DebuggerResources.FilterAction.GROUP;
		String ORDER = "1";
		String HELP_ANCHOR = "show_sections_table";

		static ToggleActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ToggleActionBuilder(NAME, ownerName)
					.description(DESCRIPTION)
					.toolBarIcon(ICON)
					.toolBarGroup(GROUP, ORDER)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	protected static class AutoMapState extends TraceDomainObjectListener
			implements TransactionListener {

		private final PluginTool tool;
		private final Trace trace;
		private final AutoMapSpec spec;
		private volatile boolean couldHaveChanged = true;
		private volatile String infosLastTime = "";

		public AutoMapState(PluginTool tool, Trace trace, AutoMapSpec spec) {
			this.tool = tool;
			this.trace = trace;
			this.spec = spec;
			for (TraceEvent<?, ?> type : spec.getChangeTypes()) {
				listenFor(type, this::changed);
			}

			listenFor(TraceEvents.VALUE_CREATED, this::valueCreated);
			listenForUntyped(DomainObjectEvent.RESTORED, this::objectRestored);

			trace.addListener(this);
			trace.addTransactionListener(this);
		}

		public void dispose() {
			trace.removeListener(this);
			trace.removeTransactionListener(this);
		}

		private void changed() {
			couldHaveChanged = true;
		}

		private void valueCreated(TraceObjectValue value) {
			couldHaveChanged = true;
		}

		private void objectRestored(DomainObjectChangeRecord rec) {
			couldHaveChanged = true;
		}

		@Override
		public void transactionStarted(DomainObjectAdapterDB domainObj, TransactionInfo tx) {
		}

		@Override
		public void transactionEnded(DomainObjectAdapterDB domainObj) {
			checkAutoMap();
		}

		@Override
		public void undoStackChanged(DomainObjectAdapterDB domainObj) {
		}

		@Override
		public void undoRedoOccurred(DomainObjectAdapterDB domainObj) {
		}

		private void checkAutoMap() {
			if (!couldHaveChanged) {
				return;
			}
			couldHaveChanged = false;
			DebuggerTraceManagerService traceManager =
				tool.getService(DebuggerTraceManagerService.class);
			if (traceManager == null) {
				return;
			}
			DebuggerCoordinates current = traceManager.getCurrentFor(trace);
			long snap = current.getSnap();
			String infosThisTime = spec.getInfoForObjects(trace, snap);
			if (Objects.equals(infosThisTime, infosLastTime)) {
				return;
			}
			infosLastTime = infosThisTime;

			spec.runTask(tool, trace, snap);
		}

		public void forceMap() {
			couldHaveChanged = true;
			infosLastTime = "";
			checkAutoMap();
		}
	}

	protected static Set<TraceModule> getSelectedModules(ActionContext context) {
		if (context instanceof DebuggerObjectActionContext ctx) {
			return DebuggerModulesPanel.getSelectedModulesFromContext(ctx);
		}
		return Set.of();
	}

	protected static Set<TraceSection> getSelectedSections(ActionContext context,
			boolean allowExpansion) {
		if (context instanceof DebuggerObjectActionContext ctx) {
			return DebuggerModulesPanel.getSelectedSectionsFromContext(ctx);
		}
		return Set.of();
	}

	protected static AddressSetView getSelectedAddresses(ActionContext context) {
		if (context instanceof DebuggerObjectActionContext ctx) {
			return DebuggerModulesPanel.getSelectedAddressesFromContext(ctx);
		}
		return null;
	}

	protected class SelectAddressesAction extends AbstractSelectAddressesAction {
		public static final String GROUP = DebuggerResources.GROUP_GENERAL;

		public SelectAddressesAction() {
			super(plugin);
			setDescription("Select addresses contained in modules or sections");
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

			AddressSetView sel = getSelectedAddresses(context);
			if (sel == null || sel.isEmpty()) {
				return;
			}

			sel = sel.intersect(traceManager.getCurrentView().getMemory());
			ProgramSelection ps = new ProgramSelection(sel);
			listingService.setCurrentSelection(ps);
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			return isContextNonEmpty(context);
		}
	}

	protected class ImportFromFileSystemAction extends AbstractImportFromFileSystemAction {
		public static final String GROUP = DebuggerResources.GROUP_GENERAL;

		public ImportFromFileSystemAction() {
			super(plugin);
			setPopupMenuData(new MenuData(new String[] { NAME }, GROUP));
			tool.addAction(this);
			setEnabled(true);
		}

		@Override
		public void actionPerformed(ActionContext context) {
			if (importerService == null) {
				return;
			}
			Set<TraceModule> modules = getSelectedModules(context);
			if (modules == null || modules.size() != 1) {
				return;
			}
			TraceModule mod = modules.iterator().next();
			importModuleFromFileSystem(mod);
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			try {
				Set<TraceModule> sel = getSelectedModules(context);
				return importerService != null && sel != null && sel.size() == 1;
			}
			catch (TraceClosedException e) {
				return false;
			}
		}
	}

	protected class ForCleanupMappingChangeListener
			implements DebuggerStaticMappingChangeListener {
		@Override
		public void mappingsChanged(Set<Trace> affectedTraces, Set<Program> affectedPrograms) {
			Swing.runIfSwingOrRunLater(() -> cleanMissingProgramMessages(null, null));
		}
	}

	final DebuggerModulesPlugin plugin;

	//@AutoServiceConsumed via method
	private DebuggerStaticMappingService staticMappingService;
	@AutoServiceConsumed
	private DebuggerTraceManagerService traceManager;
	@AutoServiceConsumed
	DebuggerListingService listingService;
	@AutoServiceConsumed
	private DebuggerConsoleService consoleService;
	@AutoServiceConsumed
	ProgramManager programManager;
	@AutoServiceConsumed
	private GoToService goToService;
	@AutoServiceConsumed
	private FileImporterService importerService;
	@SuppressWarnings("unused")
	private final AutoService.Wiring autoServiceWiring;

	private final JSplitPane mainPanel = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
	private final int defaultDividerSize = mainPanel.getDividerSize();

	DebuggerModulesPanel modulesPanel;
	DebuggerSectionsPanel sectionsPanel;

	// LATER?: Lazy construction of these dialogs?
	private final DebuggerBlockChooserDialog blockChooserDialog;
	private final DebuggerModuleMapProposalDialog moduleProposalDialog;
	private final DebuggerSectionMapProposalDialog sectionProposalDialog;

	DebuggerCoordinates current = DebuggerCoordinates.NOWHERE;
	private Program currentProgram;
	private ProgramLocation currentLocation;

	private ActionContext myActionContext;

	DockingAction actionMapIdentically;
	DockingAction actionMapManually;
	DockingAction actionMapModules;
	DockingAction actionMapModuleTo;
	DockingAction actionMapSections;
	DockingAction actionMapSectionTo;
	DockingAction actionMapSectionsTo;

	MultiStateDockingAction<AutoMapSpec> actionAutoMap;
	private final AutoMapSpec defaultAutoMapSpec =
		AutoMapSpec.fromConfigName(ByModuleAutoMapSpec.CONFIG_NAME);

	@AutoConfigStateField(codec = AutoMapSpecConfigFieldCodec.class)
	AutoMapSpec autoMapSpec = defaultAutoMapSpec;
	@AutoConfigStateField
	boolean showSectionsTable = true;
	@AutoConfigStateField
	boolean filterSectionsByModules = false;

	private final Map<Trace, AutoMapState> autoMapStateByTrace = new WeakHashMap<>();

	DockingAction actionImportMissingModule;
	DockingAction actionMapMissingModule;

	DockingAction actionMapMissingProgramRetry;
	DockingAction actionMapMissingProgramToCurrent;
	DockingAction actionMapMissingProgramIdentically;

	protected final ForCleanupMappingChangeListener mappingChangeListener =
		new ForCleanupMappingChangeListener();

	SelectAddressesAction actionSelectAddresses;
	ImportFromFileSystemAction actionImportFromFileSystem;
	ToggleDockingAction actionShowSectionsTable;
	ToggleDockingAction actionFilterSectionsByModules;
	DockingAction actionSelectCurrent;

	public DebuggerModulesProvider(final DebuggerModulesPlugin plugin) {
		super(plugin.getTool(), DebuggerResources.TITLE_PROVIDER_MODULES, plugin.getName(), null);
		this.plugin = plugin;

		setIcon(DebuggerResources.ICON_PROVIDER_MODULES);
		setHelpLocation(DebuggerResources.HELP_PROVIDER_MODULES);
		setWindowMenuGroup(DebuggerPluginPackage.NAME);

		buildMainPanel();

		this.autoServiceWiring = AutoService.wireServicesConsumed(plugin, this);

		blockChooserDialog = new DebuggerBlockChooserDialog(tool);
		moduleProposalDialog = new DebuggerModuleMapProposalDialog(this);
		sectionProposalDialog = new DebuggerSectionMapProposalDialog(this);

		setDefaultWindowPosition(WindowPosition.LEFT);
		setVisible(true);
		createActions();
	}

	private void importModuleFromFileSystem(TraceModule module) {
		GhidraFileChooser chooser = new GhidraFileChooser(getComponent());
		chooser.setSelectedFile(new File(module.getName(current.getSnap())));
		File file = chooser.getSelectedFile();
		chooser.dispose();
		if (file == null) { // Perhaps cancelled
			return;
		}
		Project activeProject = Objects.requireNonNull(AppInfo.getActiveProject());
		DomainFolder root = activeProject.getProjectData().getRootFolder();
		importerService.importFile(root, file);
	}

	void addResolutionActionMaybe(DebuggerConsoleService consoleService, DockingActionIf action) {
		if (action != null) {
			consoleService.addResolutionAction(action);
		}
	}

	void removeResolutionActionMaybe(DebuggerConsoleService consoleService,
			DockingActionIf action) {
		if (action != null) {
			consoleService.removeResolutionAction(action);
		}
	}

	@AutoServiceConsumed
	private void setConsoleService(DebuggerConsoleService consoleService) {
		if (consoleService != null) {
			addResolutionActionMaybe(consoleService, actionImportMissingModule);
			addResolutionActionMaybe(consoleService, actionMapMissingModule);
			addResolutionActionMaybe(consoleService, actionMapMissingProgramRetry);
			addResolutionActionMaybe(consoleService, actionMapMissingProgramToCurrent);
			addResolutionActionMaybe(consoleService, actionMapMissingProgramIdentically);
		}
	}

	protected void dispose() {
		for (AutoMapState state : autoMapStateByTrace.values()) {
			state.dispose();
		}

		if (consoleService != null) {
			removeResolutionActionMaybe(consoleService, actionImportMissingModule);
			removeResolutionActionMaybe(consoleService, actionMapMissingModule);
			removeResolutionActionMaybe(consoleService, actionMapMissingProgramRetry);
			removeResolutionActionMaybe(consoleService, actionMapMissingProgramToCurrent);
			removeResolutionActionMaybe(consoleService, actionMapMissingProgramIdentically);
		}

		blockChooserDialog.dispose();
		moduleProposalDialog.dispose();
		sectionProposalDialog.dispose();
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		if (myActionContext == null) {
			return super.getActionContext(event);
		}
		return myActionContext;
	}

	protected boolean isFilterSectionsByModules() {
		return filterSectionsByModules;
	}

	void modulesPanelContextChanged() {
		myActionContext = modulesPanel.getActionContext();
		if (isFilterSectionsByModules()) {
			sectionsPanel.reload();
		}
		contextChanged();
	}

	void sectionsPanelContextChanged() {
		myActionContext = sectionsPanel.getActionContext();
		contextChanged();
	}

	protected void buildMainPanel() {
		mainPanel.setContinuousLayout(true);

		modulesPanel = new DebuggerModulesPanel(this);
		mainPanel.setLeftComponent(modulesPanel);

		sectionsPanel = new DebuggerSectionsPanel(this);
		mainPanel.setRightComponent(sectionsPanel);

		mainPanel.setResizeWeight(0.5);
	}

	protected void createActions() {
		actionMapIdentically = MapIdenticallyAction.builder(plugin)
				.enabledWhen(ctx -> currentProgram != null && current.getTrace() != null)
				.onAction(this::activatedMapIdentically)
				.buildAndInstallLocal(this);
		actionMapManually = MapManuallyAction.builder(plugin)
				.enabled(true)
				.onAction(this::activatedMapManually)
				.buildAndInstallLocal(this);
		actionMapModules = MapModulesAction.builder(plugin)
				.enabledWhen(ctx -> isContextHasModules(ctx) && isContextNotForcedSingle(ctx))
				.popupWhen(ctx -> isContextHasModules(ctx) && isContextNotForcedSingle(ctx))
				.onAction(this::activatedMapModules)
				.buildAndInstall(tool);
		actionMapModuleTo = MapModuleToAction.builder(plugin)
				.enabledWhen(ctx -> currentProgram != null && getSelectedModules(ctx).size() == 1)
				.popupWhen(ctx -> currentProgram != null && getSelectedModules(ctx).size() == 1)
				.onAction(this::activatedMapModuleTo)
				.buildAndInstall(tool);
		actionMapSections = MapSectionsAction.builder(plugin)
				.enabledWhen(ctx -> isContextHasSections(ctx) && isContextNotForcedSingle(ctx))
				.popupWhen(ctx -> isContextHasSections(ctx) && isContextNotForcedSingle(ctx))
				.onAction(this::activatedMapSections)
				.buildAndInstall(tool);
		actionMapSectionTo = MapSectionToAction.builder(plugin)
				.enabledWhen(
					ctx -> currentProgram != null && getSelectedSections(ctx, false).size() == 1)
				.popupWhen(
					ctx -> currentProgram != null && getSelectedSections(ctx, false).size() == 1)
				.onAction(this::activatedMapSectionTo)
				.buildAndInstall(tool);
		actionMapSectionsTo = MapSectionsToAction.builder(plugin)
				.enabledWhen(ctx -> currentProgram != null && isContextSectionsOfOneModule(ctx))
				.popupWhen(ctx -> currentProgram != null && isContextSectionsOfOneModule(ctx))
				.onAction(this::activatedMapSectionsTo)
				.buildAndInstall(tool);

		actionAutoMap = AutoMapAction.builder(plugin)
				.onActionStateChanged(this::changedAutoMapSpec)
				.buildAndInstallLocal(this);
		actionAutoMap.setCurrentActionStateByUserData(defaultAutoMapSpec);

		actionImportMissingModule = ImportMissingModuleAction.builder(plugin)
				.withContext(DebuggerMissingModuleActionContext.class)
				.onAction(this::activatedImportMissingModule)
				.build();
		actionMapMissingModule = MapMissingModuleAction.builder(plugin)
				.withContext(DebuggerMissingModuleActionContext.class)
				.onAction(this::activatedMapMissingModule)
				.build();

		actionMapMissingProgramRetry = MapMissingProgramRetryAction.builder(plugin)
				.withContext(DebuggerMissingProgramActionContext.class)
				.onAction(this::activatedMapMissingProgramRetry)
				.build();
		actionMapMissingProgramToCurrent = MapMissingProgramToCurrentAction.builder(plugin)
				.withContext(DebuggerMissingProgramActionContext.class)
				.enabledWhen(this::isEnabledMapMissingProgramToCurrent)
				.onAction(this::activatedMapMissingProgramToCurrent)
				.build();
		actionMapMissingProgramIdentically = MapMissingProgramIdenticallyAction.builder(plugin)
				.withContext(DebuggerMissingProgramActionContext.class)
				.onAction(this::activatedMapMissingProgramIdentically)
				.build();

		actionSelectAddresses = new SelectAddressesAction();
		actionImportFromFileSystem = new ImportFromFileSystemAction();
		actionShowSectionsTable = ShowSectionsTableAction.builder(plugin)
				.onAction(this::toggledShowSectionsTable)
				.selected(showSectionsTable)
				.buildAndInstallLocal(this);
		actionFilterSectionsByModules = FilterAction.builder(plugin)
				.description("Filter sections to those in selected modules")
				.helpLocation(new HelpLocation(plugin.getName(), "filter_by_module"))
				.onAction(this::toggledFilter)
				.buildAndInstallLocal(this);
		actionSelectCurrent = SelectRowsAction.builder(plugin)
				.enabledWhen(ctx -> current.getTrace() != null)
				.description("Select modules and sections by dynamic selection")
				.onAction(this::activatedSelectCurrent)
				.buildAndInstallLocal(this);

		contextChanged();
	}

	private boolean isContextHasModules(ActionContext context) {
		return !getSelectedModules(context).isEmpty();
	}

	private boolean isContextHasSections(ActionContext context) {
		return !getSelectedSections(context, false).isEmpty();
	}

	private boolean isContextNonEmpty(ActionContext context) {
		if (context instanceof DebuggerModuleActionContext ctx) {
			return !ctx.getSelectedModules().isEmpty();
		}
		if (context instanceof DebuggerSectionActionContext ctx) {
			return !ctx.getSelectedSections(false, current.getSnap()).isEmpty();
		}
		if (context instanceof DebuggerObjectActionContext ctx) {
			return !ctx.getObjectValues().isEmpty();
		}
		return false;
	}

	private boolean isContextNotForcedSingle(ActionContext context) {
		if (context instanceof DebuggerModuleActionContext ctx) {
			return !ctx.isForcedSingle();
		}
		if (context instanceof DebuggerSectionActionContext ctx) {
			return !ctx.isForcedSingle();
		}
		return true;
	}

	private boolean isContextSectionsOfOneModule(ActionContext context) {
		Set<TraceSection> sel = getSelectedSections(context, false);
		if (sel == null || sel.isEmpty()) {
			return false;
		}
		try {
			return sel.stream().map(TraceSection::getModule).distinct().count() == 1;
		}
		catch (Exception e) {
			Msg.error(this, "Could not check section selection context: " + e);
			return false;
		}
	}

	private void activatedMapIdentically(ActionContext ignored) {
		if (currentProgram == null || current.getTrace() == null) {
			return;
		}
		try {
			staticMappingService.addIdentityMapping(current.getTrace(), currentProgram,
				Lifespan.nowOn(traceManager.getCurrentSnap()), true);
		}
		catch (TraceConflictedMappingException e) {
			Msg.showError(this, null, "Map Identically", e.getMessage());
		}
	}

	private void activatedMapManually(ActionContext ignored) {
		ComponentProvider provider =
			tool.getComponentProvider(DebuggerResources.TITLE_PROVIDER_MAPPINGS);
		if (provider != null) {
			tool.showComponentProvider(provider, true);
			return;
		}
		try {
			tool.addPlugin(DebuggerStaticMappingPlugin.class.getName());
		}
		catch (PluginException e) {
			Msg.showError(this, mainPanel, MapManuallyAction.NAME,
				"DebuggerStaticMappingPlugin could not be enabled", e);
			return;
		}
		provider = tool.getComponentProvider(DebuggerResources.TITLE_PROVIDER_MAPPINGS);
		assert provider != null;
		tool.showComponentProvider(provider, true);
	}

	private void activatedMapModules(ActionContext context) {
		Set<TraceModule> sel = getSelectedModules(context);
		if (sel == null || sel.isEmpty()) {
			return;
		}
		mapModules(sel);
	}

	private void activatedMapModuleTo(ActionContext context) {
		Set<TraceModule> sel = getSelectedModules(context);
		if (sel == null || sel.size() != 1) {
			return;
		}
		mapModuleTo(sel.iterator().next());
	}

	private void activatedMapSections(ActionContext context) {
		Set<TraceSection> sel = getSelectedSections(context, true);
		if (sel == null || sel.isEmpty()) {
			return;
		}
		mapSections(sel);
	}

	private void activatedMapSectionsTo(ActionContext context) {
		Set<TraceSection> sel = getSelectedSections(context, true);
		if (sel == null || sel.isEmpty()) {
			return;
		}
		mapSectionsTo(sel);
	}

	private void activatedMapSectionTo(ActionContext context) {
		Set<TraceSection> sel = getSelectedSections(context, false);
		if (sel == null || sel.size() != 1) {
			return;
		}
		mapSectionTo(sel.iterator().next());
	}

	private void changedAutoMapSpec(ActionState<AutoMapSpec> newState, EventTrigger trigger) {
		doSetAutoMapSpec(newState.getUserData());
	}

	private void doSetAutoMapSpec(AutoMapSpec autoMapSpec) {
		this.autoMapSpec = autoMapSpec;

		Trace trace = current.getTrace();
		if (trace == null) {
			return;
		}
		AutoMapState state = autoMapStateByTrace.remove(trace);
		if (state != null && state.spec.equals(autoMapSpec)) {
			autoMapStateByTrace.put(trace, state);
		}
		else {
			state.dispose();
			autoMapStateByTrace.put(trace, new AutoMapState(tool, trace, autoMapSpec));
		}
	}

	private void activatedImportMissingModule(DebuggerMissingModuleActionContext context) {
		if (importerService == null) {
			Msg.error(this, "Import service is not present");
		}
		importModuleFromFileSystem(context.getModule());
	}

	private void activatedMapMissingModule(DebuggerMissingModuleActionContext context) {
		mapModuleTo(context.getModule());
	}

	private void activatedMapMissingProgramRetry(DebuggerMissingProgramActionContext context) {
		if (staticMappingService == null) {
			return;
		}

		Program program = context.getProgram();
		Trace trace = context.getTrace();
		long snap = traceManager.getCurrentFor(trace).getSnap();

		Map<TraceModule, ModuleMapProposal> map = staticMappingService.proposeModuleMaps(
			trace.getModuleManager().getAllModules(), snap, List.of(program));
		Collection<ModuleMapEntry> proposal = MapProposal.flatten(map.values());
		promptModuleProposal(proposal, FMT_NO_MODULES_PROPOSAL_RETRY.formatted(
			trace.getDomainFile().getName(), program.getDomainFile().getName()));
	}

	private boolean isEnabledMapMissingProgramToCurrent(
			DebuggerMissingProgramActionContext context) {
		if (staticMappingService == null || traceManager == null || listingService == null) {
			return false;
		}
		ProgramLocation loc = listingService.getCurrentLocation();
		if (loc == null) {
			return false;
		}
		if (!(loc.getProgram() instanceof TraceProgramView view)) {
			return false;
		}
		Trace trace = context.getTrace();
		if (view.getTrace() != trace) {
			return false;
		}

		long snap = traceManager.getCurrentFor(trace).getSnap();
		Address address = loc.getAddress();
		return !trace.getModuleManager().getModulesAt(snap, address).isEmpty();
	}

	private void activatedMapMissingProgramToCurrent(DebuggerMissingProgramActionContext context) {
		if (staticMappingService == null || traceManager == null || listingService == null) {
			return;
		}

		Trace trace = context.getTrace();
		long snap = traceManager.getCurrentFor(trace).getSnap();
		Address address = listingService.getCurrentLocation().getAddress();

		TraceModule module = trace.getModuleManager().getModulesAt(snap, address).iterator().next();

		Program program = context.getProgram();
		ModuleMapProposal proposal =
			staticMappingService.proposeModuleMap(module, snap, program);
		Map<TraceModule, ModuleMapEntry> map = proposal.computeMap();
		promptModuleProposal(map.values(), FMT_NO_MODULES_PROPOSAL_CURRENT.formatted(
			module.getName(snap), program.getDomainFile().getName()));
	}

	private void activatedMapMissingProgramIdentically(
			DebuggerMissingProgramActionContext context) {
		if (staticMappingService == null) {
			return;
		}

		Trace trace = context.getTrace();
		long snap = traceManager == null ? 0 : traceManager.getCurrentFor(trace).getSnap();

		try {
			staticMappingService.addIdentityMapping(trace, context.getProgram(),
				Lifespan.nowOn(snap), true);
		}
		catch (TraceConflictedMappingException e) {
			Msg.showError(this, null, "Map Identically", e.getMessage());
		}
	}

	private void toggledShowSectionsTable(ActionContext ignored) {
		setShowSectionsTable(actionShowSectionsTable.isSelected());
	}

	public void setShowSectionsTable(boolean showSectionsTable) {
		if (this.showSectionsTable == showSectionsTable) {
			return;
		}
		doSetShowSectionsTable(showSectionsTable);
	}

	protected void doSetShowSectionsTable(boolean showSectionsTable) {
		this.showSectionsTable = showSectionsTable;
		actionShowSectionsTable.setSelected(showSectionsTable);
		mainPanel.setDividerSize(showSectionsTable ? defaultDividerSize : 0);
		sectionsPanel.setVisible(showSectionsTable);
		mainPanel.resetToPreferredSizes();
	}

	private void toggledFilter(ActionContext ignored) {
		setFilterSectionsByModules(actionFilterSectionsByModules.isSelected());
	}

	public void setFilterSectionsByModules(boolean filterSectionsByModules) {
		if (this.filterSectionsByModules == filterSectionsByModules) {
			return;
		}
		doSetFilterSectionsByModules(filterSectionsByModules);
	}

	protected void doSetFilterSectionsByModules(boolean filterSectionsByModules) {
		this.filterSectionsByModules = filterSectionsByModules;
		actionFilterSectionsByModules.setSelected(filterSectionsByModules);
		sectionsPanel.setFilteredBySelectedModules(filterSectionsByModules);
	}

	private void activatedSelectCurrent(ActionContext ignored) {
		if (listingService == null || traceManager == null || current.getTrace() == null) {
			return;
		}

		long snap = current.getSnap();
		ProgramSelection progSel = listingService.getCurrentSelection();
		TraceModuleManager moduleManager = current.getTrace().getModuleManager();
		if (progSel != null && !progSel.isEmpty()) {
			Set<TraceModule> modSel = new HashSet<>();
			Set<TraceSection> sectionSel = new HashSet<>();
			for (AddressRange range : progSel) {
				for (TraceModule module : moduleManager
						.getModulesIntersecting(Lifespan.at(snap), range)) {
					if (module.getSections(snap).isEmpty()) {
						modSel.add(module);
					}
				}
				for (TraceSection section : moduleManager
						.getSectionsIntersecting(Lifespan.at(snap), range)) {
					sectionSel.add(section);
					modSel.add(section.getModule());
				}
			}
			setSelectedModules(modSel);
			setSelectedSections(sectionSel);
			return;
		}
		ProgramLocation progLoc = listingService.getCurrentLocation();
		if (progLoc != null) {
			Address address = progLoc.getAddress();
			Set<TraceSection> sectionsAt =
				Set.copyOf(moduleManager.getSectionsAt(traceManager.getCurrentSnap(), address));
			if (!sectionsAt.isEmpty()) {
				Set<TraceModule> modulesAt =
					sectionsAt.stream().map(TraceSection::getModule).collect(Collectors.toSet());
				setSelectedModules(modulesAt);
				setSelectedSections(sectionsAt);
				return;
			}
			TraceModule bestModule = null;
			for (TraceModule module : moduleManager
					.getLoadedModules(traceManager.getCurrentSnap())) {
				Address base = module.getBase(snap);
				if (base == null || base.getAddressSpace() != address.getAddressSpace()) {
					continue;
				}
				if (bestModule == null) {
					bestModule = module;
					continue;
				}
				if (base.compareTo(address) > 0) {
					continue;
				}
				if (base.compareTo(bestModule.getBase(snap)) <= 0) {
					continue;
				}
				bestModule = module;
			}
			if (bestModule == null) {
				setSelectedModules(Set.of());
				return;
			}
			if (bestModule.getSections(snap).isEmpty()) {
				setSelectedModules(Set.of(bestModule));
				return;
			}
		}
	}

	protected void promptModuleProposal(Collection<ModuleMapEntry> proposal, String emptyMsg) {
		if (proposal.isEmpty()) {
			Msg.showInfo(this, getComponent(), "Map Modules", emptyMsg);
			return;
		}
		Collection<ModuleMapEntry> adjusted =
			moduleProposalDialog.adjustCollection(getTool(), proposal);
		if (adjusted == null || staticMappingService == null) {
			return;
		}
		tool.executeBackgroundCommand(
			new MapModulesBackgroundCommand(staticMappingService, adjusted), current.getTrace());
	}

	protected void mapModules(Set<TraceModule> modules) {
		if (staticMappingService == null) {
			return;
		}
		Map<TraceModule, ModuleMapProposal> map =
			staticMappingService.proposeModuleMaps(modules, current.getSnap(),
				List.of(programManager.getAllOpenPrograms()));
		Collection<ModuleMapEntry> proposal = MapProposal.flatten(map.values());
		promptModuleProposal(proposal, NO_MODULES_PROPOSAL_SEL);
	}

	protected void mapModuleTo(TraceModule module) {
		if (staticMappingService == null) {
			return;
		}
		Program program = currentProgram;
		if (program == null) {
			return;
		}
		ModuleMapProposal proposal =
			staticMappingService.proposeModuleMap(module, current.getSnap(), program);
		Map<TraceModule, ModuleMapEntry> map = proposal.computeMap();
		promptModuleProposal(map.values(), NO_MODULES_PROPOSAL_SEL);
	}

	protected void promptSectionProposal(Collection<SectionMapEntry> proposal) {
		if (proposal.isEmpty()) {
			Msg.showInfo(this, getComponent(), "Map Sections",
				"Could not formulate a proposal for any selected section." +
					" You may need to import and/or open the destination images first.");
			return;
		}
		Collection<SectionMapEntry> adjusted =
			sectionProposalDialog.adjustCollection(getTool(), proposal);
		if (adjusted == null || staticMappingService == null) {
			return;
		}
		tool.executeBackgroundCommand(
			new MapSectionsBackgroundCommand(staticMappingService, adjusted), current.getTrace());
	}

	protected void mapSections(Set<TraceSection> sections) {
		if (staticMappingService == null) {
			return;
		}
		Set<TraceModule> modules =
			sections.stream().map(TraceSection::getModule).collect(Collectors.toSet());
		Map<?, SectionMapProposal> map =
			staticMappingService.proposeSectionMaps(modules, current.getSnap(),
				List.of(programManager.getAllOpenPrograms()));
		Collection<SectionMapEntry> proposal = MapProposal.flatten(map.values());
		Collection<SectionMapEntry> filtered = proposal.stream()
				.filter(e -> sections.contains(e.getSection()))
				.collect(Collectors.toSet());
		promptSectionProposal(filtered);
	}

	protected void mapSectionsTo(Set<TraceSection> sections) {
		if (staticMappingService == null) {
			return;
		}
		Program program = currentProgram;
		if (program == null) {
			return;
		}
		Set<TraceModule> modules =
			sections.stream().map(TraceSection::getModule).collect(Collectors.toSet());
		if (modules.size() != 1) {
			return;
		}
		TraceModule module = modules.iterator().next();
		SectionMapProposal map =
			staticMappingService.proposeSectionMap(module, current.getSnap(), program);
		Collection<SectionMapEntry> proposal = map.computeMap().values();
		Collection<SectionMapEntry> filtered = proposal.stream()
				.filter(e -> sections.contains(e.getSection()))
				.collect(Collectors.toSet());
		promptSectionProposal(filtered);
	}

	protected void mapSectionTo(TraceSection section) {
		if (staticMappingService == null) {
			return;
		}
		ProgramLocation location = currentLocation;
		MemoryBlock block = computeBlock(location);
		if (block == null) {
			return;
		}
		SectionMapProposal map = staticMappingService.proposeSectionMap(section, current.getSnap(),
			location.getProgram(), block);
		promptSectionProposal(map.computeMap().values());
	}

	protected Set<MemoryBlock> collectBlocksInOpenPrograms() {
		Set<MemoryBlock> result = new HashSet<>();
		for (Program p : programManager.getAllOpenPrograms()) {
			if (p instanceof Trace) {
				continue;
			}
			result.addAll(List.of(p.getMemory().getBlocks()));
		}
		return result;
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}

	public void setProgram(Program program) {
		currentProgram = program;
		String name;
		if (program != null) {
			DomainFile df = program.getDomainFile();
			if (df != null) {
				name = df.getName();
			}
			else {
				name = program.getName();
			}
		}
		else {
			name = "...";
		}
		actionMapModuleTo.getPopupMenuData().setMenuItemName(MapModuleToAction.NAME_PREFIX + name);
		actionMapSectionsTo.getPopupMenuData()
				.setMenuItemName(MapSectionsToAction.NAME_PREFIX + name);
	}

	public static MemoryBlock computeBlock(ProgramLocation location) {
		if (location == null) {
			return null;
		}
		Program program = location.getProgram();
		if (program == null) {
			return null;
		}
		Address addr = location.getAddress();
		if (addr == null) {
			return null;
		}
		return program.getMemory().getBlock(addr);
	}

	public static String computeBlockName(ProgramLocation location) {
		MemoryBlock block = computeBlock(location);
		if (block == null) {
			return "...";
		}
		Program program = location.getProgram();
		String name = program.getName();
		DomainFile df = program.getDomainFile();
		if (df != null) {
			name = df.getName();
		}
		return name + ":" + block.getName();
	}

	public void setLocation(ProgramLocation location) {
		currentLocation = location;
		String name = MapSectionToAction.NAME_PREFIX + computeBlockName(location);
		actionMapSectionTo.getPopupMenuData().setMenuItemName(name);
	}

	public void programOpened(Program program) {
		AutoMapState mapState = autoMapStateByTrace.get(current.getTrace());
		// TODO: All open traces, or just the current one?
		if (mapState == null) {
			// Could be, e.g., current is NOWHERE
			return;
		}
		// TODO: Debounce this?
		mapState.forceMap();
	}

	public void programClosed(Program program) {
		if (currentProgram == program) {
			currentProgram = null;
		}
		cleanMissingProgramMessages(null, program);
	}

	public void traceOpened(Trace trace) {
		autoMapStateByTrace.computeIfAbsent(trace, t -> new AutoMapState(tool, trace, autoMapSpec));
	}

	public void traceClosed(Trace trace) {
		AutoMapState state = autoMapStateByTrace.remove(trace);
		if (state != null) {
			state.dispose();
		}
		cleanMissingProgramMessages(trace, null);
	}

	public void coordinatesActivated(DebuggerCoordinates coordinates) {
		if (sameCoordinates(current, coordinates)) {
			current = coordinates;
			return;
		}

		Trace newTrace = coordinates.getTrace();
		boolean changeTrace = current.getTrace() != newTrace;
		if (changeTrace) {
			myActionContext = null;
		}
		current = coordinates;

		AutoMapState amState = autoMapStateByTrace.get(newTrace);
		if (amState != null) {
			// Can't just set field directly. Want GUI update.
			setAutoMapSpec(amState.spec);
		}

		modulesPanel.coordinatesActivated(coordinates);
		sectionsPanel.coordinatesActivated(coordinates);

		contextChanged();
	}

	public void setSelectedModules(Set<TraceModule> sel) {
		modulesPanel.setSelectedModules(sel);
	}

	public void setSelectedSections(Set<TraceSection> sel) {
		sectionsPanel.setSelectedSections(sel);
	}

	private DataTreeDialog getProgramChooserDialog() {

		DomainFileFilter filter = df -> Program.class.isAssignableFrom(df.getDomainObjectClass());

		return new DataTreeDialog(null, "Map Module to Program", OPEN, filter);
	}

	public DomainFile askProgram(Program program) {
		DataTreeDialog dialog = getProgramChooserDialog();
		if (program != null) {
			dialog.selectDomainFile(program.getDomainFile());
		}
		tool.showDialog(dialog);
		return dialog.getDomainFile();
	}

	public Entry<Program, MemoryBlock> askBlock(TraceSection section, Program program,
			MemoryBlock block) {
		if (programManager == null) {
			Msg.warn(this, "No program manager!");
			return null;
		}
		return blockChooserDialog.chooseBlock(getTool(), section, current.getSnap(),
			List.of(programManager.getAllOpenPrograms()));
	}

	@Override
	public void setAutoMapSpec(AutoMapSpec spec) {
		actionAutoMap.setCurrentActionStateByUserData(spec);
	}

	@Override
	public AutoMapSpec getAutoMapSpec() {
		return autoMapSpec;
	}

	@Override
	public AutoMapSpec getAutoMapSpec(Trace trace) {
		AutoMapState state = autoMapStateByTrace.get(trace);
		return state == null ? autoMapSpec : state.spec;
	}

	public void writeConfigState(SaveState saveState) {
		CONFIG_STATE_HANDLER.writeConfigState(this, saveState);
	}

	public void readConfigState(SaveState saveState) {
		CONFIG_STATE_HANDLER.readConfigState(this, saveState);
		actionAutoMap.setCurrentActionStateByUserData(autoMapSpec);
		doSetFilterSectionsByModules(filterSectionsByModules);
		doSetShowSectionsTable(showSectionsTable);
	}

	protected boolean shouldKeepMessage(DebuggerMissingProgramActionContext ctx, Trace closedTrace,
			Program closedProgram) {
		Trace trace = ctx.getTrace();
		if (trace == closedTrace) {
			return false;
		}
		if (!traceManager.getOpenTraces().contains(trace)) {
			return false;
		}
		Program program = ctx.getProgram();
		if (program == closedProgram) {
			return false;
		}
		if (programManager != null &&
			!Arrays.asList(programManager.getAllOpenPrograms()).contains(program)) {
			return false;
		}

		// Only do mapping probe on mapping changed events
		if (closedTrace != null || closedProgram != null) {
			return true;
		}

		TraceProgramView view = traceManager.getCurrentFor(trace).getView();
		Address probe = ctx.getMappingProbeAddress();
		ProgramLocation dyn = staticMappingService.getDynamicLocationFromStatic(view,
			new ProgramLocation(program, probe));
		if (dyn != null) {
			return false;
		}
		return true;
	}

	protected void cleanMissingProgramMessages(Trace closedTrace, Program closedProgram) {
		if (traceManager == null || consoleService == null) {
			return;
		}
		for (ActionContext ctx : consoleService.getActionContexts()) {
			if (!(ctx instanceof DebuggerMissingProgramActionContext mpCtx)) {
				continue;
			}
			if (!shouldKeepMessage(mpCtx, closedTrace, closedProgram)) {
				consoleService.removeFromLog(mpCtx);
			}
		}
	}

	@AutoServiceConsumed
	private void setStaticMappingService(DebuggerStaticMappingService staticMappingService) {
		if (this.staticMappingService != null) {
			this.staticMappingService.removeChangeListener(mappingChangeListener);
		}
		this.staticMappingService = staticMappingService;
		if (this.staticMappingService != null) {
			this.staticMappingService.addChangeListener(mappingChangeListener);
		}
	}
}
