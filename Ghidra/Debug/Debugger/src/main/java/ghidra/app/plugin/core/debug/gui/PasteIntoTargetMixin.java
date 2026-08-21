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
package ghidra.app.plugin.core.debug.gui;

import java.util.concurrent.*;

import ghidra.app.services.DebuggerConsoleService;
import ghidra.app.services.DebuggerControlService;
import ghidra.app.services.DebuggerControlService.StateEditor;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.util.Msg;

public interface PasteIntoTargetMixin {
	default boolean doHasEnoughSpace(Program program, Address address, int byteCount) {
		/**
		 * I don't care about code units. Just check that it's within the physical bounds and valid
		 * memory (considering Force Full View). FFV is handled within the trace view's memory.
		 */
		final Address end;
		try {
			end = address.addNoWrap(byteCount - 1);
		}
		catch (AddressOverflowException e) {
			return false;
		}
		AddressSetView range = new AddressSet(address, end);
		if (!program.getMemory().intersect(range).equals(range)) {
			return false;
		}
		return true;
	}

	default boolean doPasteBytes(PluginTool tool, DebuggerControlService controlService,
			DebuggerConsoleService consoleService, DebuggerCoordinates current,
			ProgramLocation location, byte[] bytes) {
		if (!(location.getProgram() instanceof TraceProgramView view)) {
			tool.setStatusInfo("Not a trace?", true);
			return false;
		}
		StateEditor editor = controlService.createStateEditor(current);
		try {
			editor.setVariable(location.getByteAddress(), bytes)
					.get(1, TimeUnit.SECONDS);
			return true;
		}
		catch (InterruptedException | ExecutionException | TimeoutException e) {
			if (consoleService == null) {
				Msg.showError(this, null, "Paste Error",
					"Couldn't paste into " + location.getProgram(),
					e);
			}
			else {
				consoleService.log(DebuggerResources.ICON_LOG_ERROR,
					"Couldn't paste into " + view, e);
			}
			return false;
		}
	}
}
