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

import java.io.IOException;
import java.util.List;

import docking.ActionContext;
import docking.action.MenuData;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.framework.options.SaveState;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.trace.model.Trace;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;

public class EmulateProgramAction extends AbstractEmulateAction {

	public EmulateProgramAction(DebuggerEmulationServicePlugin plugin) {
		super(plugin, plugin.EMULATE_PROGRAM);
	}

	public EmulateProgramAction(DebuggerEmulationServicePlugin plugin, Program program) {
		super(plugin, plugin.EMULATE_PROGRAM, program);
	}

	@Override
	MenuData computeMenuData() {
		if (program == null) {
			return new MenuData(
				prependMenuPath("Emulate from cursor", List.of()),
				DebuggerResources.ICON_EMULATE, DebuggerResources.GROUP_GENERAL, 0, "a1");
		}
		return new MenuData(
			prependMenuPath("Emulate %s ...".formatted(getProgramName(program)),
				List.of(" from cursor (new trace)")),
			DebuggerResources.ICON_EMULATE, DebuggerResources.GROUP_GENERAL, 0, "a1");
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
		// To avoid confusion of "forked from trace," only permit action from static context
		if (program == null || program instanceof TraceProgramView) {
			return false;
		}
		return true;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		SaveState state = new SaveState();
		plugin.writeProgramLaunchConfig(program, this.getName(), state);
		Trace trace = null;
		try {
			Address currentAddress = getCurrentAddress();
			trace = ProgramEmulationUtils.launchEmulationTrace(program, currentAddress, this);
			DebuggerTraceManagerService traceManager = plugin.getTraceManager();
			traceManager.openTrace(trace);
			traceManager.activateTrace(trace);
			plugin.tryEmulatorFromMode(trace);
		}
		catch (IOException e) {
			Msg.showError(this, null, this.getDescription(),
				"Could not create trace for emulation", e);
		}
		finally {
			if (trace != null) {
				trace.release(this);
			}
		}
	}

	@Override
	public HelpLocation getHelpLocation() {
		return new HelpLocation(plugin.getName(), "emulate_program");
	}
}
