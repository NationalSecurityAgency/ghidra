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
package ghidra.app.plugin.core.debug.service.modules;

import java.lang.invoke.MethodHandles;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.swing.Icon;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.ToggleDockingAction;
import docking.action.builder.ActionBuilder;
import docking.action.builder.ToggleActionBuilder;
import ghidra.app.context.ProgramLocationActionContext;
import ghidra.app.events.*;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.event.*;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.utils.ProgramURLUtils;
import ghidra.app.services.*;
import ghidra.app.services.DebuggerStaticMappingService.MappedAddressRange;
import ghidra.debug.api.modules.*;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.framework.model.DomainFile;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.annotation.AutoConfigStateField;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.trace.model.Trace;
import ghidra.trace.model.modules.*;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.*;

@PluginInfo(
	shortDescription = "Debugger static synchronization",
	description = """
			Synchronizes the static and dynamic listings (and other components) where the module \
			map is known""",
	category = PluginCategoryNames.DEBUGGER,
	packageName = DebuggerPluginPackage.NAME,
	status = PluginStatus.RELEASED,
	eventsConsumed = {
		ProgramOpenedPluginEvent.class, // For auto-open log cleanup
		ProgramActivatedPluginEvent.class,
		ProgramLocationPluginEvent.class,
		ProgramSelectionPluginEvent.class,
		// NOTE: Don't sync highlight
		TraceActivatedPluginEvent.class,
		TraceLocationPluginEvent.class,
		TraceSelectionPluginEvent.class,
	},
	eventsProduced = {
		ProgramLocationPluginEvent.class,
		ProgramSelectionPluginEvent.class,
		TraceLocationPluginEvent.class,
		TraceSelectionPluginEvent.class,
	},
	servicesRequired = {
		DebuggerStaticMappingService.class,
	})
public class DynamicStaticSynchronizationPlugin extends Plugin {

	interface SyncLocationsAction {
		String NAME = "Synchronize Static and Dynamic Locations";
		String DESCRIPTION = "Automatically synchronize the static and dynamic listings' cursors";
		String HELP_ANCHOR = "sync_locations";

		static ToggleActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ToggleActionBuilder(NAME, ownerName)
					.description(DESCRIPTION)
					.menuPath(DebuggerPluginPackage.NAME, "Synchronization", NAME)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	interface SyncSelectionsAction {
		String NAME = "Synchronize Static and Dynamic Selections";
		String DESCRIPTION =
			"Automatically synchronize the static and dynamic listings' selections";
		String HELP_ANCHOR = "sync_selections";

		static ToggleActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ToggleActionBuilder(NAME, ownerName)
					.description(DESCRIPTION)
					.menuPath(DebuggerPluginPackage.NAME, "Synchronization", NAME)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	interface TransferSelectionDynamicToStaticAction {
		String NAME = "Transfer Dynamic Selection to Static";
		String DESCRIPTION = "Change the static selection to match the dynamic selection";
		String HELP_ANCHOR = "transfer_selection_dynamic_to_static";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME, ownerName)
					.description(DESCRIPTION)
					.menuPath(DebuggerPluginPackage.NAME, "Synchronization", NAME)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	interface TransferSelectionStaticToDynamicAction {
		String NAME = "Transfer Static Selection to Dynamic";
		String DESCRIPTION = "Change the dynamic seleciton to mathc the static selection";
		String HELP_ANCHOR = "transfer_selection_static_to_dynamic";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME, ownerName)
					.description(DESCRIPTION)
					.menuPath(DebuggerPluginPackage.NAME, "Synchronization", NAME)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	interface OpenProgramAction {
		String NAME = "Open Program";
		Icon ICON = DebuggerResources.ICON_PROGRAM;
		String DESCRIPTION = "Open the program";
		String HELP_ANCHOR = "open_program";

		static ActionBuilder builder(Plugin owner) {
			String ownerName = owner.getName();
			return new ActionBuilder(NAME, ownerName)
					.description(DESCRIPTION)
					.toolBarIcon(ICON)
					.helpLocation(new HelpLocation(ownerName, HELP_ANCHOR));
		}
	}

	protected static final AutoConfigState.ClassHandler<DynamicStaticSynchronizationPlugin> CONFIG_STATE_HANDLER =
		AutoConfigState.wireHandler(DynamicStaticSynchronizationPlugin.class,
			MethodHandles.lookup());

	/**
	 * NOTE: We thought about having this respect the current (possible disconnected) provider, but
	 * whatever we send will get reflected back into the connected provider, anyway. Not sure which
	 * will be more confusing, so we'll just go with "only the main/connected" viewers for now.
	 * 
	 * @param ctx the context, ignored
	 * @return true if a static selection is present
	 */
	private boolean hasDynamicSelection(ProgramLocationActionContext ctx) {
		return currentDynamicSelection != null && !currentDynamicSelection.isEmpty();
	}

	private boolean hasStaticSelection(ProgramLocationActionContext ctx) {
		return currentStaticSelection != null && !currentStaticSelection.isEmpty();
	}

	protected class ForStaticSyncMappingChangeListener
			implements DebuggerStaticMappingChangeListener {
		@Override
		public void mappingsChanged(Set<Trace> affectedTraces, Set<Program> affectedPrograms) {
			Swing.runIfSwingOrRunLater(() -> {
				if (currentDynamic.getView() == null) {
					return;
				}
				if (!affectedTraces.contains(currentDynamic.getTrace())) {
					return;
				}
				cleanMissingModuleMessages(affectedTraces);
				if (isSyncLocations()) {
					doSendLocationFromStable();
				}
				if (isSyncSelections()) {
					doSendSelectionFromStable();
				}
			});

			/**
			 * TODO: Remove "missing" entry in modules dialog, if present? There's some nuance here,
			 * because the trace presenting the mapping may not be the same as the trace that missed
			 * the module originally. I'm tempted to just leave it and let the user remove it.
			 */
		}
	}

	protected ToggleDockingAction actionSyncLocations;
	protected ToggleDockingAction actionSyncSelections;
	protected DockingAction actionTransferSelectionDynamicToStatic;
	protected DockingAction actionTransferSelectionStaticToDynamic;

	protected DockingAction actionOpenProgram;

	@AutoConfigStateField
	private boolean syncLocations = true;
	@AutoConfigStateField
	private boolean syncSelections = true;

	// @AutoServiceConsumed via method
	private DebuggerStaticMappingService mappingService;
	@AutoServiceConsumed
	private DebuggerTraceManagerService traceManager;
	@AutoServiceConsumed
	private DebuggerConsoleService consoleService;
	@AutoServiceConsumed
	private ProgramManager programManager;
	@AutoServiceConsumed
	private FileImporterService importerService;
	@SuppressWarnings("unused")
	private final AutoService.Wiring autoServiceWiring;

	protected final ForStaticSyncMappingChangeListener mappingChangeListener =
		new ForStaticSyncMappingChangeListener();

	enum StablePoint {
		STATIC, DYNAMIC;
	}

	private StablePoint stablePoint;
	private DebuggerCoordinates currentDynamic = DebuggerCoordinates.NOWHERE;
	private ProgramLocation currentDynamicLocation;
	private ProgramSelection currentDynamicSelection;
	private Program currentStatic;
	private ProgramLocation currentStaticLocation;
	private ProgramSelection currentStaticSelection;

	public DynamicStaticSynchronizationPlugin(PluginTool tool) {
		super(tool);
		this.autoServiceWiring = AutoService.wireServicesProvidedAndConsumed(this);

		createActions();
	}

	@Override
	protected void dispose() {
		super.dispose();
		if (consoleService != null) {
			if (actionOpenProgram != null) {
				consoleService.removeResolutionAction(actionOpenProgram);
			}
		}
	}

	@AutoServiceConsumed
	private void setMappingService(DebuggerStaticMappingService mappingService) {
		if (this.mappingService != null) {
			this.mappingService.removeChangeListener(mappingChangeListener);
		}
		this.mappingService = mappingService;
		if (this.mappingService != null) {
			this.mappingService.addChangeListener(mappingChangeListener);
			if (isSyncLocations()) {
				doSendLocationFromStable();
			}
			if (isSyncSelections()) {
				doSendSelectionFromStable();
			}
		}
	}

	@AutoServiceConsumed
	private void setConsoleService(DebuggerConsoleService consoleService) {
		if (consoleService != null) {
			if (actionOpenProgram != null) {
				consoleService.addResolutionAction(actionOpenProgram);
			}
		}
	}

	protected void createActions() {
		actionSyncLocations = SyncLocationsAction
				.builder(this)
				.enabled(true)
				.selected(true)
				.onAction(ctx -> doSetSyncLocations(actionSyncLocations.isSelected()))
				.buildAndInstall(tool);
		actionSyncSelections = SyncSelectionsAction
				.builder(this)
				.enabled(true)
				.selected(true)
				.onAction(ctx -> doSetSyncSelections(actionSyncSelections.isSelected()))
				.buildAndInstall(tool);
		actionTransferSelectionDynamicToStatic = TransferSelectionDynamicToStaticAction
				.builder(this)
				.withContext(ProgramLocationActionContext.class)
				.enabledWhen(this::hasDynamicSelection)
				.onAction(this::activatedTransferSelectionDynamicToStatic)
				.buildAndInstall(tool);
		actionTransferSelectionStaticToDynamic = TransferSelectionStaticToDynamicAction
				.builder(this)
				.withContext(ProgramLocationActionContext.class)
				.enabledWhen(this::hasStaticSelection)
				.onAction(this::activatedTransferSelectionStaticToDynamic)
				.buildAndInstall(tool);

		actionOpenProgram = OpenProgramAction.builder(this)
				.withContext(DebuggerOpenProgramActionContext.class)
				.onAction(this::activatedOpenProgram)
				.build();
	}

	protected void doSetSyncLocations(boolean sync) {
		this.syncLocations = sync;
		if (isSyncLocations()) {
			doSendLocationFromStable();
		}
	}

	protected void doSetSyncSelections(boolean sync) {
		this.syncSelections = sync;
		if (isSyncSelections()) {
			doSendSelectionFromStable();
		}
	}

	protected void displayMapError(String from, String to) {
		tool.setStatusInfo("No selected addresses in " + from + " are mappable to " + to +
			". Check your module list and static mappings.", true);
	}

	private void activatedTransferSelectionDynamicToStatic(ActionContext ctx) {
		stablePoint = StablePoint.DYNAMIC;
		ProgramSelection result = doSendSelectionDynamicToStatic();
		if (result != null && result.isEmpty()) {
			displayMapError("the dynamic view", "the static listing");
		}
	}

	private void activatedTransferSelectionStaticToDynamic(ActionContext ctx) {
		stablePoint = StablePoint.STATIC;
		ProgramSelection result = doSendSelectionStaticToDynamic();
		if (result != null && result.isEmpty()) {
			displayMapError("the static listing", "the dynamic view");
		}
	}

	private void activatedOpenProgram(DebuggerOpenProgramActionContext context) {
		programManager.openProgram(context.getDomainFile(), DomainFile.DEFAULT_VERSION,
			ProgramManager.OPEN_CURRENT);
	}

	private void doSendLocationFromStable() {
		switch (stablePoint) {
			case null -> {
			}
			case STATIC -> doSendLocationStaticToDynamic();
			case DYNAMIC -> doSendLocationDynamicToStatic();
		}
	}

	private void doSendSelectionFromStable() {
		switch (stablePoint) {
			case null -> {
			}
			case STATIC -> doSendSelectionStaticToDynamic();
			case DYNAMIC -> doSendSelectionDynamicToStatic();
		}
	}

	private void doSendLocationStaticToDynamic() {
		if (mappingService == null || currentStaticLocation == null) {
			return;
		}
		TraceProgramView view = currentDynamic.getView(); // NB. Used for snap (don't want emuSnap)
		if (view == null) {
			return;
		}
		ProgramLocation dynamicLoc =
			mappingService.getDynamicLocationFromStatic(view, currentStaticLocation);
		if (dynamicLoc == null) {
			return;
		}
		firePluginEvent(new TraceLocationPluginEvent(getName(), dynamicLoc));
	}

	private void doSendLocationDynamicToStatic() {
		if (mappingService == null || currentDynamicLocation == null) {
			return;
		}
		/**
		 * Is there any reason to try to open the module if we're not syncing listings? I don't
		 * think so.
		 */
		doCheckCurrentModuleMissing();
		TraceProgramView view = currentDynamic.getView();
		if (view == null) {
			return;
		}
		ProgramLocation staticLoc =
			mappingService.getStaticLocationFromDynamic(currentDynamicLocation);
		if (staticLoc == null) {
			return;
		}
		firePluginEvent(
			new ProgramLocationPluginEvent(getName(), staticLoc, staticLoc.getProgram()));
	}

	private ProgramSelection doSendSelectionStaticToDynamic() {
		if (mappingService == null || currentStatic == null || currentStaticSelection == null) {
			return null;
		}
		TraceProgramView view = currentDynamic.getView();
		if (view == null) {
			return null;
		}
		AddressSet dynamicAddrs =
			mappingService.getOpenMappedViews(currentStatic, currentStaticSelection)
					.entrySet()
					.stream()
					.filter(e -> e.getKey().getTrace() == view.getTrace())
					.filter(e -> e.getKey().getSpan().contains(currentDynamic.getSnap()))
					.flatMap(e -> e.getValue().stream())
					.map(r -> r.getDestinationAddressRange())
					.collect(AddressCollectors.toAddressSet());
		ProgramSelection dynamicSel = new ProgramSelection(dynamicAddrs);
		firePluginEvent(new TraceSelectionPluginEvent(getName(), dynamicSel, view));
		return dynamicSel;
	}

	private ProgramSelection doSendSelectionDynamicToStatic() {
		if (mappingService == null || currentStatic == null || currentDynamicSelection == null) {
			return null;
		}
		TraceProgramView view = currentDynamic.getView();
		if (view == null) {
			return null;
		}
		Collection<MappedAddressRange> ranges = mappingService
				.getOpenMappedViews(view.getTrace(), currentDynamicSelection,
					currentDynamic.getSnap())
				.get(currentStatic);
		AddressSet staticAddrs = ranges == null
				? null
				: ranges.stream()
						.map(r -> r.getDestinationAddressRange())
						.collect(AddressCollectors.toAddressSet());
		ProgramSelection staticSel = new ProgramSelection(staticAddrs);
		firePluginEvent(new ProgramSelectionPluginEvent(getName(), staticSel, currentStatic));
		return staticSel;
	}

	@Override
	public void processEvent(PluginEvent event) {
		switch (event) {
			case ProgramOpenedPluginEvent ev -> programOpened(ev);
			case ProgramActivatedPluginEvent ev -> programActivated(ev);
			case ProgramLocationPluginEvent ev -> staticLocationChanged(ev);
			case ProgramSelectionPluginEvent ev -> staticSelectionChanged(ev);
			case TraceActivatedPluginEvent ev -> coordinatesActivated(ev);
			case TraceLocationPluginEvent ev -> dynamicLocationChanged(ev);
			case TraceSelectionPluginEvent ev -> dynamicSelectionChanged(ev);
			default -> {
			}
		}
	}

	private void programOpened(ProgramOpenedPluginEvent event) {
		DomainFile df = event.getProgram().getDomainFile();
		DebuggerOpenProgramActionContext ctx = new DebuggerOpenProgramActionContext(df);
		if (consoleService != null) {
			consoleService.removeFromLog(ctx);
		}
	}

	private void programActivated(ProgramActivatedPluginEvent event) {
		currentStatic = event.getActiveProgram();
	}

	private void staticLocationChanged(ProgramLocationPluginEvent event) {
		currentStaticLocation = event.getLocation();
		stablePoint = StablePoint.STATIC;
		if (isSyncLocations()) {
			doSendLocationStaticToDynamic();
		}
	}

	private void staticSelectionChanged(ProgramSelectionPluginEvent event) {
		currentStaticSelection = event.getSelection();
		stablePoint = StablePoint.STATIC;
		if (isSyncSelections()) {
			doSendSelectionStaticToDynamic();
		}
	}

	private void coordinatesActivated(TraceActivatedPluginEvent event) {
		currentDynamic = event.getActiveCoordinates();
	}

	private void dynamicLocationChanged(TraceLocationPluginEvent event) {
		currentDynamicLocation = event.getLocation();
		stablePoint = StablePoint.DYNAMIC;
		if (isSyncLocations()) {
			doSendLocationDynamicToStatic();
		}
	}

	private void dynamicSelectionChanged(TraceSelectionPluginEvent event) {
		currentDynamicSelection = event.getSelection();
		stablePoint = StablePoint.DYNAMIC;
		if (isSyncSelections()) {
			doSendSelectionDynamicToStatic();
		}
	}

	public void setSyncLocations(boolean sync) {
		actionSyncLocations.setSelected(sync);
		doSetSyncLocations(sync);
	}

	public boolean isSyncLocations() {
		return syncLocations;
	}

	public void setSyncSelections(boolean sync) {
		actionSyncSelections.setSelected(sync);
		doSetSyncSelections(sync);
	}

	public boolean isSyncSelections() {
		return syncSelections;
	}

	@Override
	public void readConfigState(SaveState saveState) {
		CONFIG_STATE_HANDLER.readConfigState(this, saveState);
		actionSyncLocations.setSelected(syncLocations);
		actionSyncSelections.setSelected(syncSelections);
	}

	protected void doTryOpenProgram(DomainFile df, int version, int state) {
		DebuggerOpenProgramActionContext ctx = new DebuggerOpenProgramActionContext(df);
		if (consoleService != null && consoleService.logContains(ctx)) {
			return;
		}
		if (df.canRecover()) {
			if (consoleService != null) {
				consoleService.log(DebuggerResources.ICON_MODULES, "<html>Program <b>" +
					HTMLUtilities.escapeHTML(df.getPathname()) +
					"</b> has recovery data. It must be opened manually.</html>", ctx);
			}
			return;
		}
		new TaskLauncher(new Task("Open " + df, true, false, false) {
			@Override
			public void run(TaskMonitor monitor) throws CancelledException {
				Program program = null;
				try {
					program = (Program) df.getDomainObject(this, false, false, monitor);
					programManager.openProgram(program, state);
				}
				catch (VersionException e) {
					if (consoleService != null) {
						consoleService.log(DebuggerResources.ICON_MODULES, "<html>Program <b>" +
							HTMLUtilities.escapeHTML(df.getPathname()) +
							"</b> was created with a different version of Ghidra." +
							" It must be opened manually.</html>", ctx);
					}
					return;
				}
				catch (Exception e) {
					if (consoleService != null) {
						consoleService.log(DebuggerResources.ICON_LOG_ERROR, "<html>Program <b>" +
							HTMLUtilities.escapeHTML(df.getPathname()) +
							"</b> could not be opened: " + e + ". Try opening it manually.</html>",
							ctx);
					}
					return;
				}
				finally {
					if (program != null) {
						program.release(this);
					}
				}
			}
		}, tool.getToolFrame());
	}

	protected boolean isMapped(AddressRange range) {
		if (range == null) {
			return false;
		}
		return mappingService.getStaticLocationFromDynamic(
			new ProgramLocation(currentDynamic.getView(), range.getMinAddress())) != null;
	}

	protected void cleanMissingModuleMessages(Set<Trace> affectedTraces) {
		if (consoleService == null) {
			return;
		}
		nextCtx: for (ActionContext ctx : consoleService.getActionContexts()) {
			if (!(ctx instanceof DebuggerMissingModuleActionContext mmCtx)) {
				continue;
			}
			TraceModule module = mmCtx.getModule();
			if (!affectedTraces.contains(module.getTrace())) {
				continue;
			}
			long snap = traceManager.getCurrentFor(module.getTrace()).getSnap();
			if (isMapped(module.getRange(snap))) {
				consoleService.removeFromLog(mmCtx);
				continue;
			}
			for (TraceSection section : module.getSections(snap)) {
				if (isMapped(section.getRange(snap))) {
					consoleService.removeFromLog(mmCtx);
					continue nextCtx;
				}
			}
		}
	}

	protected void doCheckCurrentModuleMissing() {
		Trace trace = currentDynamic.getTrace();
		if (trace == null) {
			return;
		}
		ProgramLocation loc = currentDynamicLocation;
		if (loc == null) { // Redundant?
			return;
		}
		AddressSpace space = loc.getAddress().getAddressSpace();
		if (space == null) {
			return; // Is this NO_ADDRESS or something?
		}
		if (mappingService == null) {
			return;
		}
		ProgramLocation mapped = mappingService.getStaticLocationFromDynamic(loc);
		if (mapped != null) {
			// No need to import what is already mapped and open
			return;
		}

		long snap = currentDynamic.getSnap();
		Address address = loc.getAddress();
		TraceStaticMapping mapping = trace.getStaticMappingManager().findContaining(address, snap);
		if (mapping != null) {
			DomainFile df = ProgramURLUtils.getDomainFileFromOpenProject(tool.getProject(),
				mapping.getStaticProgramURL());
			if (df != null) {
				doTryOpenProgram(df, DomainFile.DEFAULT_VERSION, ProgramManager.OPEN_CURRENT);
			}
		}

		Set<TraceModule> missing = new HashSet<>();
		Set<DomainFile> toOpen = new HashSet<>();
		TraceModuleManager modMan = trace.getModuleManager();
		Collection<TraceModule> modules = Stream.concat(
			modMan.getModulesAt(snap, address).stream().filter(m -> m.getSections(snap).isEmpty()),
			modMan.getSectionsAt(snap, address).stream().map(s -> s.getModule()))
				.collect(Collectors.toSet());

		// Attempt to open probable matches. All others, list to import
		for (TraceModule mod : modules) {
			DomainFile match = mappingService.findBestModuleProgram(space, mod, snap);
			if (match == null) {
				missing.add(mod);
			}
			else {
				toOpen.add(match);
			}
		}
		if (programManager != null && !toOpen.isEmpty()) {
			for (DomainFile df : toOpen) {
				// Do not presume a goTo is about to happen. There are no mappings, yet.
				doTryOpenProgram(df, DomainFile.DEFAULT_VERSION, ProgramManager.OPEN_VISIBLE);
			}
		}

		if (importerService == null || consoleService == null) {
			return;
		}

		for (TraceModule mod : missing) {
			consoleService.log(DebuggerResources.ICON_LOG_ERROR,
				"<html>The module <b><tt>" + HTMLUtilities.escapeHTML(mod.getName(snap)) +
					"</tt></b> was not found in the project</html>",
				new DebuggerMissingModuleActionContext(mod));
		}
		/**
		 * Once the programs are opened, including those which are successfully imported, the
		 * automatic mapper should take effect, eventually invoking callbacks to our mapping change
		 * listener.
		 */
	}
}
