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
package ghidra.app.plugin.core.debug.gui.control;

import java.util.stream.Collectors;

import docking.ActionContext;
import docking.action.ToolBarData;
import docking.menu.ActionState;
import docking.menu.MultiStateDockingAction;
import docking.widgets.EventTrigger;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.debug.api.control.ControlMode;
import ghidra.util.HelpLocation;

class ControlModeAction extends MultiStateDockingAction<ControlMode> {
	public static final String NAME = "Control Mode";
	public static final String DESCRIPTION = "Choose what to control and edit in dynamic views";
	public static final String GROUP = DebuggerResources.GROUP_CONTROL;
	public static final String HELP_ANCHOR = "control_mode";

	private final DebuggerControlPlugin plugin;

	public ControlModeAction(DebuggerControlPlugin plugin) {
		super(NAME, plugin.getName());
		this.plugin = plugin;
		setDescription(DESCRIPTION);
		setToolBarData(new ToolBarData(DebuggerResources.ICON_BLANK, GROUP, ""));
		setHelpLocation(new HelpLocation(getOwner(), HELP_ANCHOR));
		setActionStates(ControlMode.ALL.stream()
				.map(m -> new ActionState<>(m.name, m.icon, m))
				.collect(Collectors.toList()));
		setEnabled(false);
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		return plugin.current.getTrace() != null;
	}

	@Override
	protected boolean isStateEnabled(ActionState<ControlMode> state) {
		return state.getUserData().isSelectable(plugin.current);
	}

	@Override
	public void actionStateChanged(ActionState<ControlMode> newActionState,
			EventTrigger trigger) {
		plugin.activateControlMode(newActionState, trigger);
	}
}
