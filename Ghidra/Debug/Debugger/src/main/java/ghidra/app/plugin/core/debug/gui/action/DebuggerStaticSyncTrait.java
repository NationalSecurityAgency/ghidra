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
package ghidra.app.plugin.core.debug.gui.action;

import java.lang.invoke.MethodHandles;
import java.util.Collection;
import java.util.Set;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.ToggleDockingAction;
import docking.widgets.EventTrigger;
import ghidra.app.context.ProgramLocationActionContext;
import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.*;
import ghidra.app.services.DebuggerStaticMappingChangeListener;
import ghidra.app.services.DebuggerStaticMappingService;
import ghidra.app.services.DebuggerStaticMappingService.MappedAddressRange;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.annotation.AutoConfigStateField;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.program.model.address.AddressCollectors;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.trace.model.Trace;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.util.Msg;
import ghidra.util.Swing;

public class DebuggerStaticSyncTrait {
	protected static final AutoConfigState.ClassHandler<DebuggerStaticSyncTrait> CONFIG_STATE_HANDLER =
		AutoConfigState.wireHandler(DebuggerStaticSyncTrait.class, MethodHandles.lookup());

	private static boolean dynamicHasSelection(ProgramLocationActionContext ctx) {
		if (ctx == null) {
			return false;
		}
		ProgramSelection sel = ctx.getSelection();
		if (sel == null || sel.isEmpty()) {
			return false;
		}
		return true;
	}

	protected class ForStaticSyncMappingChangeListener
			implements DebuggerStaticMappingChangeListener {
		@Override
		public void mappingsChanged(Set<Trace> affectedTraces, Set<Program> affectedPrograms) {
			Swing.runIfSwingOrRunLater(() -> {
				if (current.getView() == null) {
					return;
				}
				if (!affectedTraces.contains(current.getTrace())) {
					return;
				}
				doAutoSyncCursorIntoStatic(currentDynamicLocation);
				// TODO: Remember last sync direction, or just always take dyn->static
				doAutoSyncSelectionIntoStatic(current.getView(), currentDynamicSelection);
			});

			/**
			 * TODO: Remove "missing" entry in modules dialog, if present? There's some nuance here,
			 * because the trace presenting the mapping may not be the same as the trace that missed
			 * the module originally. I'm tempted to just leave it and let the user remove it.
			 */
		}
	}

	protected ToggleDockingAction actionAutoSyncCursorWithStaticListing;
	protected ToggleDockingAction actionAutoSyncSelectionWithStaticListing;
	protected DockingAction actionSyncSelectionIntoStaticListing;
	protected DockingAction actionSyncSelectionFromStaticListing;

	@AutoConfigStateField
	private boolean autoSyncCursorWithStaticListing;
	@AutoConfigStateField
	private boolean autoSyncSelectionWithStaticListing;

	private final PluginTool tool;
	private final Plugin plugin;
	private final ComponentProvider provider;
	private final boolean isAutoSyncAllowed;

	//@AutoServiceConsumed via method
	private DebuggerStaticMappingService mappingService;
	@SuppressWarnings("unused")
	private final AutoService.Wiring autoServiceWiring;

	private DebuggerCoordinates current = DebuggerCoordinates.NOWHERE;
	private ProgramLocation currentDynamicLocation;
	private ProgramSelection currentDynamicSelection;

	private Program currentStaticProgram;
	private ProgramLocation currentStaticLocation;
	private ProgramSelection currentStaticSelection;

	protected final ForStaticSyncMappingChangeListener mappingChangeListener =
		new ForStaticSyncMappingChangeListener();

	public DebuggerStaticSyncTrait(PluginTool tool, Plugin plugin, ComponentProvider provider,
			boolean isAutoSyncAllowed) {
		this.tool = tool;
		this.plugin = plugin;
		this.provider = provider;
		this.isAutoSyncAllowed = isAutoSyncAllowed;

		this.autoServiceWiring = AutoService.wireServicesConsumed(plugin, this);

		this.autoSyncCursorWithStaticListing = isAutoSyncAllowed;
		this.autoSyncSelectionWithStaticListing = isAutoSyncAllowed;
	}

	@AutoServiceConsumed
	private void setMappingService(DebuggerStaticMappingService mappingService) {
		if (this.mappingService != null) {
			this.mappingService.removeChangeListener(mappingChangeListener);
		}
		this.mappingService = mappingService;
		if (this.mappingService != null) {
			this.mappingService.addChangeListener(mappingChangeListener);
			doAutoSyncCursorIntoStatic(currentDynamicLocation);
		}
	}

	public ToggleDockingAction installAutoSyncCursorWithStaticListingAction() {
		return actionAutoSyncCursorWithStaticListing = AutoSyncCursorWithStaticListingAction
				.builder(plugin)
				.enabled(true)
				.selected(true)
				.onAction(ctx -> doSetAutoSyncCursorWithStaticListing(
					actionAutoSyncCursorWithStaticListing.isSelected()))
				.buildAndInstallLocal(provider);
	}

	public ToggleDockingAction installAutoSyncSelectionWithStaticListingAction() {
		return actionAutoSyncSelectionWithStaticListing = AutoSyncSelectionWithStaticListingAction
				.builder(plugin)
				.enabled(true)
				.selected(true)
				.onAction(ctx -> doSetAutoSyncSelectionWithStaticListing(
					actionAutoSyncSelectionWithStaticListing.isSelected()))
				.buildAndInstallLocal(provider);
	}

	public DockingAction installSyncSelectionIntoStaticListingAction() {
		return actionSyncSelectionIntoStaticListing = SyncSelectionIntoStaticListingAction
				.builder(plugin)
				.withContext(ProgramLocationActionContext.class)
				.enabledWhen(ctx -> dynamicHasSelection(ctx))
				.onAction(this::activatedSyncSelectionIntoStatic)
				.buildAndInstallLocal(provider);
	}

	public DockingAction installSyncSelectionFromStaticListingAction() {
		return actionSyncSelectionFromStaticListing = SyncSelectionFromStaticListingAction
				.builder(plugin)
				.withContext(ProgramLocationActionContext.class)
				.enabledWhen(ctx -> staticHasSelection(ctx))
				.onAction(this::activatedSyncSelectionFromStatic)
				.buildAndInstallLocal(provider);
	}

	private boolean staticHasSelection(ActionContext ctx) {
		return currentStaticSelection != null && !currentStaticSelection.isEmpty();
	}

	protected void activatedSyncSelectionIntoStatic(ProgramLocationActionContext ctx) {
		ProgramSelection result = doSyncSelectionIntoStatic(ctx.getProgram(), ctx.getSelection());
		if (result != null && result.isEmpty()) {
			displayMapError("the dynamic view", "the static listing");
		}
	}

	protected void activatedSyncSelectionFromStatic(ActionContext ctx) {
		ProgramSelection result = doSyncSelectionFromStatic();
		if (result != null && result.isEmpty()) {
			displayMapError("the static listing", "the dynamic view");
		}
	}

	protected void doSyncCursorIntoStatic(ProgramLocation location) {
		if (location == null || mappingService == null) {
			return;
		}
		ProgramLocation staticLoc = mappingService.getStaticLocationFromDynamic(location);
		if (staticLoc == null) {
			return;
		}
		staticGoTo(staticLoc);
	}

	protected void doSyncCursorFromStatic() {
		TraceProgramView view = current.getView(); // NB. Used for snap (don't want emuSnap)
		if (currentStaticLocation == null || view == null || mappingService == null) {
			return;
		}
		ProgramLocation dynamicLoc =
			mappingService.getDynamicLocationFromStatic(view, currentStaticLocation);
		if (dynamicLoc == null) {
			return;
		}
		dynamicGoTo(dynamicLoc);
	}

	public void doAutoSyncCursorIntoStatic(ProgramLocation location) {
		if (!isAutoSyncCursorWithStaticListing()) {
			return;
		}
		doSyncCursorIntoStatic(location);
	}

	public void doAutoSyncCursorFromStatic() {
		if (!isAutoSyncCursorWithStaticListing()) {
			return;
		}
		doSyncCursorFromStatic();
	}

	protected void doSetAutoSyncCursorWithStaticListing(boolean sync) {
		this.autoSyncCursorWithStaticListing = sync;
		provider.contextChanged();
		doAutoSyncCursorIntoStatic(currentDynamicLocation);
	}

	protected void doSetAutoSyncSelectionWithStaticListing(boolean sync) {
		this.autoSyncSelectionWithStaticListing = sync;
		provider.contextChanged();
		doAutoSyncSelectionIntoStatic(current.getView(), currentDynamicSelection);
	}

	protected ProgramSelection doSyncSelectionIntoStatic(Program program, ProgramSelection sel) {
		if (program == null || sel == null || currentStaticProgram == null ||
			mappingService == null) {
			return null;
		}
		TraceProgramView view = (TraceProgramView) program;
		Collection<MappedAddressRange> ranges =
			mappingService.getOpenMappedViews(view.getTrace(), sel, view.getSnap())
					.get(currentStaticProgram);
		AddressSet mapped;
		if (ranges == null) {
			mapped = new AddressSet();
		}
		else {
			mapped = ranges.stream()
					.map(r -> r.getDestinationAddressRange())
					.collect(AddressCollectors.toAddressSet());
		}
		ProgramSelection result = new ProgramSelection(mapped);
		staticSelect(currentStaticProgram, result);
		return result;
	}

	protected ProgramSelection doSyncSelectionFromStatic() {
		TraceProgramView view = current.getView();
		if (view == null || currentStaticProgram == null || currentStaticSelection == null ||
			mappingService == null) {
			return null;
		}
		AddressSet mapped =
			mappingService.getOpenMappedViews(currentStaticProgram, currentStaticSelection)
					.entrySet()
					.stream()
					.filter(e -> e.getKey().getTrace() == current.getTrace())
					.filter(e -> e.getKey().getSpan().contains(current.getSnap()))
					.flatMap(e -> e.getValue().stream())
					.map(r -> r.getDestinationAddressRange())
					.collect(AddressCollectors.toAddressSet());
		ProgramSelection result = new ProgramSelection(mapped);
		dynamicSelect(view, result);
		return result;
	}

	protected void doAutoSyncSelectionIntoStatic(Program program, ProgramSelection selection) {
		if (isAutoSyncSelectionWithStaticListing()) {
			doSyncSelectionIntoStatic(program, selection);
		}
	}

	protected void doAutoSyncSelectionFromStatic() {
		if (isAutoSyncSelectionWithStaticListing()) {
			doSyncSelectionFromStatic();
		}
	}

	protected void displayMapError(String from, String to) {
		tool.setStatusInfo("No selected addresses in " + from + " are mappable to " + to +
			". Check your module list and static mappings.", true);
	}

	public void goToCoordinates(DebuggerCoordinates coordinates) {
		this.current = coordinates;
	}

	public void dynamicProgramLocationChanged(ProgramLocation location, EventTrigger trigger) {
		currentDynamicLocation = location;
		if (trigger != EventTrigger.GUI_ACTION) {
			return;
		}
		doAutoSyncCursorIntoStatic(location);
	}

	public void dynamicSelectionChanged(Program program, ProgramSelection selection,
			EventTrigger trigger) {
		currentDynamicSelection = selection;
		provider.contextChanged();
		if (trigger != EventTrigger.GUI_ACTION) {
			return;
		}
		doAutoSyncSelectionIntoStatic(program, selection);
	}

	public void staticProgramActivated(Program program) {
		currentStaticProgram = program;
	}

	public void staticProgramLocationChanged(ProgramLocation location) {
		currentStaticLocation = location;
		doAutoSyncCursorFromStatic();
	}

	public void staticProgramSelectionChanged(Program program, ProgramSelection selection) {
		if (program != currentStaticProgram) {
			Msg.warn(this, "Got selection change for not the current static program");
			return;
		}
		currentStaticProgram = program;
		currentStaticSelection = selection;
		provider.contextChanged();
		doAutoSyncSelectionFromStatic();
	}

	public void setAutoSyncCursorWithStaticListing(boolean sync) {
		actionAutoSyncCursorWithStaticListing.setSelected(sync);
		doSetAutoSyncCursorWithStaticListing(sync);
	}

	public boolean isAutoSyncCursorWithStaticListing() {
		return autoSyncCursorWithStaticListing;
	}

	public void setAutoSyncSelectionWithStaticListing(boolean sync) {
		actionAutoSyncSelectionWithStaticListing.setSelected(sync);
		doSetAutoSyncSelectionWithStaticListing(sync);
	}

	public boolean isAutoSyncSelectionWithStaticListing() {
		return autoSyncSelectionWithStaticListing;
	}

	public void readConfigState(SaveState saveState) {
		CONFIG_STATE_HANDLER.readConfigState(this, saveState);

		if (isAutoSyncAllowed) {
			if (actionAutoSyncCursorWithStaticListing != null) {
				actionAutoSyncCursorWithStaticListing.setSelected(autoSyncCursorWithStaticListing);
			}
			if (actionAutoSyncSelectionWithStaticListing != null) {
				actionAutoSyncSelectionWithStaticListing
						.setSelected(autoSyncSelectionWithStaticListing);
			}
		}
		else {
			autoSyncCursorWithStaticListing = false;
			autoSyncSelectionWithStaticListing = false;
		}
	}

	protected void staticGoTo(ProgramLocation location) {
		// listener method
	}

	protected void staticSelect(Program program, ProgramSelection selection) {
		// listener method
	}

	protected void dynamicGoTo(ProgramLocation location) {
		// listener method
	}

	protected void dynamicSelect(Program program, ProgramSelection selection) {
		// listener method
	}
}
