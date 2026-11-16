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

import java.util.List;

import docking.ActionContext;
import docking.action.MenuData;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.gui.emulation.DebuggerEmulateFunctionDialog;
import ghidra.app.services.CodeViewerService;
import ghidra.framework.options.SaveState;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.util.HelpLocation;

public class EmulateFunctionAction extends AbstractEmulateAction {

	public EmulateFunctionAction(DebuggerEmulationServicePlugin plugin) {
		super(plugin, plugin.EMULATE_FUNCTION);
	}

	public EmulateFunctionAction(DebuggerEmulationServicePlugin plugin, Program program) {
		super(plugin, plugin.EMULATE_FUNCTION, program);
	}

	@Override
	MenuData computeMenuData() {
		CodeViewerService service = tool.getService(CodeViewerService.class);
		String current = "current function";
		if (service != null) {
			ProgramLocation loc = service.getCurrentLocation();
			if (loc != null) {
				FunctionManager functionManager = loc.getProgram().getFunctionManager();
				Function f = functionManager.getFunctionContaining(loc.getAddress());
				if (f != null) {
					current = f.getName();
				}
			}
		}
		return new MenuData(
			prependMenuPath("Emulate %s".formatted(current), List.of()),
			DebuggerResources.ICON_EMULATE, DebuggerResources.GROUP_GENERAL, 0, "a3");
	}

	@Override
	String getTopGroup(Program currentProgram) {
		return "1";
	}

	@Override
	String getTopOrder(Program currentProgram) {
		return "3";
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		Address address = getCurrentAddress();
		if (program == null || program instanceof TraceProgramView || address == null) {
			return false;
		}
		Function function = program.getFunctionManager().getFunctionContaining(address);
		if (function == null) {
			return false;
		}
		return true;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		SaveState state = new SaveState();
		plugin.writeProgramLaunchConfig(program, this.getName(), state);
		Address address = getCurrentAddress();
		if (program == null || address == null) {
			return;
		}
		Function function = program.getFunctionManager().getFunctionContaining(address);
		if (function == null) {
			return;
		}
		tool.showDialog(new DebuggerEmulateFunctionDialog(tool, function));
	}

	@Override
	public HelpLocation getHelpLocation() {
		return new HelpLocation(plugin.getName(), "emulate_function");
	}
}
