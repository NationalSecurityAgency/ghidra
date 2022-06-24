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
package ghidra.app.plugin.core.debug.gui.editing;

import docking.menu.ActionState;
import docking.menu.MultiStateDockingAction;
import docking.widgets.EventTrigger;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.debug.*;
import ghidra.app.plugin.core.debug.event.TraceActivatedPluginEvent;
import ghidra.app.plugin.core.debug.event.TraceClosedPluginEvent;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.EditModeAction;
import ghidra.app.services.DebuggerStateEditingService;
import ghidra.app.services.DebuggerStateEditingService.StateEditingMode;
import ghidra.app.services.DebuggerStateEditingService.StateEditingModeChangeListener;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.trace.model.Trace;

@PluginInfo(
	shortDescription = "Debugger machine-state Editing GUI",
	description = "GUI to edit target, trace, and/or emulation machine state",
	category = PluginCategoryNames.DEBUGGER,
	packageName = DebuggerPluginPackage.NAME,
	status = PluginStatus.RELEASED,
	eventsConsumed = {
		TraceActivatedPluginEvent.class,
		TraceClosedPluginEvent.class,
	},
	servicesRequired = {
		DebuggerStateEditingService.class,
	})
public class DebuggerStateEditingPlugin extends AbstractDebuggerPlugin {

	private final StateEditingModeChangeListener listenerForModeChanges = this::modeChanged;

	protected DebuggerCoordinates current = DebuggerCoordinates.NOWHERE;

	protected MultiStateDockingAction<StateEditingMode> actionEditMode;

	// @AutoServiceConsumed // via method
	private DebuggerStateEditingService editingService;

	public DebuggerStateEditingPlugin(PluginTool tool) {
		super(tool);

		createActions();
	}

	protected void createActions() {
		actionEditMode = EditModeAction.builder(this)
				.enabled(false)
				.enabledWhen(c -> current.getTrace() != null)
				.onActionStateChanged(this::activateEditMode)
				.buildAndInstall(tool);
	}

	protected void activateEditMode(ActionState<StateEditingMode> state, EventTrigger trigger) {
		if (current.getTrace() == null) {
			return;
		}
		if (editingService == null) {
			return;
		}
		editingService.setCurrentMode(current.getTrace(), state.getUserData());
		// TODO: Limit selectable modes?
		// No sense showing Write Target, if the trace can never be live, again....
	}

	private void modeChanged(Trace trace, StateEditingMode mode) {
		if (current.getTrace() == trace) {
			refreshActionMode();
		}
	}

	protected void coordinatesActivated(DebuggerCoordinates coords) {
		current = coords;
		refreshActionMode();
		// tool.contextChanged(null);
	}

	private StateEditingMode computeCurrentEditingMode() {
		if (editingService == null) {
			return StateEditingMode.READ_ONLY;
		}
		if (current.getTrace() == null) {
			return StateEditingMode.READ_ONLY;
		}
		return editingService.getCurrentMode(current.getTrace());
	}

	private void refreshActionMode() {
		actionEditMode.setCurrentActionStateByUserData(computeCurrentEditingMode());
	}

	protected void traceClosed(Trace trace) {
		if (current.getTrace() == trace) {
			current = DebuggerCoordinates.NOWHERE;
		}
		refreshActionMode();
		// tool.contextChanged(null);
	}

	@AutoServiceConsumed
	protected void setEditingService(DebuggerStateEditingService editingService) {
		if (this.editingService != null) {
			this.editingService.removeModeChangeListener(listenerForModeChanges);
		}
		this.editingService = editingService;
		if (this.editingService != null) {
			this.editingService.addModeChangeListener(listenerForModeChanges);
		}
		refreshActionMode();
	}

	@Override
	public void processEvent(PluginEvent event) {
		super.processEvent(event);
		if (event instanceof TraceActivatedPluginEvent) {
			TraceActivatedPluginEvent ev = (TraceActivatedPluginEvent) event;
			coordinatesActivated(ev.getActiveCoordinates());
		}
		else if (event instanceof TraceClosedPluginEvent) {
			TraceClosedPluginEvent ev = (TraceClosedPluginEvent) event;
			traceClosed(ev.getTrace());
		}
	}
}
