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
package ghidra.app.plugin.core.debug.service.emulation;

import static ghidra.app.plugin.core.debug.service.emulation.DebuggerEmulationServicePlugin.*;

import docking.ActionContext;
import docking.action.*;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;

public class TopEmulateAction extends AbstractEmulateAction {
	private String configName;

	public TopEmulateAction(DebuggerEmulationServicePlugin plugin, String configName,
			Program program) {
		this.configName = configName;
		super(plugin, "Re-emulate", program);
	}

	@Override
	MenuData computeMenuData() {
		String title = "Re-emulate %s".formatted(getProgramName(program));
		DockingActionIf action = plugin.getAction(configName);
		if (action instanceof AbstractEmulateAction eaction) {
			title = "Re-" + eaction.getCompressedPath();
		}
		return new MenuData(new String[] { title }, DebuggerResources.ICON_EMULATE, "0: top");
	}

	@Override
	String getTopGroup(Program currentProgram) {
		return "0";
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		DockingActionIf action = plugin.getAction(configName);
		return action != null ? action.isEnabledForContext(context) : false;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		DockingActionIf action = plugin.getAction(configName);
		if (action != null) {
			action.actionPerformed(context);
		}
	}

	@Override
	public HelpLocation getHelpLocation() {
		DockingActionIf action = plugin.getAction(configName);
		if (action instanceof DockingAction daction) {
			return daction.getHelpLocation();
		}
		return null;
	}
}
