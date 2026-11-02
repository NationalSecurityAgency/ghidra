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

import java.util.List;

import docking.ActionContext;
import docking.action.MenuData;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.framework.options.SaveState;
import ghidra.program.model.listing.Program;
import ghidra.trace.model.Trace;
import ghidra.util.HelpLocation;

public class EmulateTargetAction extends AbstractEmulateAction {

	public EmulateTargetAction(DebuggerEmulationServicePlugin plugin, Program program) {
		super(plugin, plugin.EMULATE_TARGET, program);
	}

	@Override
	MenuData computeMenuData() {
		return new MenuData(
			prependMenuPath("Emulate %s ...".formatted(getProgramName(program)),
				List.of(" using debugger target")),
			DebuggerResources.ICON_EMULATE, DebuggerResources.GROUP_GENERAL, 0, "a2");
	}

	@Override
	String getTopGroup(Program currentProgram) {
		return "1";
	}

	@Override
	String getTopOrder(Program currentProgram) {
		return program == currentProgram ? "1" : "2";
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		DebuggerTraceManagerService traceManager = plugin.getTraceManager();
		return traceManager != null && traceManager.getCurrentTrace() != null;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		SaveState state = new SaveState();
		plugin.writeProgramLaunchConfig(program, this.getName(), state);

		DebuggerTraceManagerService traceManager = plugin.getTraceManager();
		Trace trace = traceManager.getCurrentTrace();
		traceManager.activateTrace(trace);
		plugin.tryEmulatorFromMode(trace);
	}

	@Override
	public HelpLocation getHelpLocation() {
		return new HelpLocation(plugin.getName(), "emulate_target");
	}
}
