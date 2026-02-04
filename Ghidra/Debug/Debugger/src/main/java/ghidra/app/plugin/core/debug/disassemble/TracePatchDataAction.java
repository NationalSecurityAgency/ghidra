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
package ghidra.app.plugin.core.debug.disassemble;

import java.util.concurrent.*;

import ghidra.app.plugin.core.assembler.PatchDataAction;
import ghidra.app.services.DebuggerControlService;
import ghidra.app.services.DebuggerControlService.StateEditor;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.trace.model.listing.TraceData;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

public class TracePatchDataAction extends PatchDataAction {
	protected final DebuggerDisassemblerPlugin plugin;

	public TracePatchDataAction(DebuggerDisassemblerPlugin plugin) {
		super(plugin);
		this.plugin = plugin;
	}

	@Override
	protected boolean isApplicableToUnit(CodeUnit cu) {
		return super.isApplicableToUnit(cu) && cu instanceof TraceData;
	}

	class PatchDataCommand extends BackgroundCommand<TraceProgramView> {
		private final byte[] encoded;

		public PatchDataCommand(byte[] encoded) {
			this.encoded = encoded;
		}

		@Override
		public boolean applyTo(TraceProgramView view, TaskMonitor monitor) {
			DebuggerControlService controlService = tool.getService(DebuggerControlService.class);
			if (controlService == null) {
				return true;
			}
			StateEditor editor = controlService.createStateEditor(view);
			Address address = getAddress();

			try {
				editor.setVariable(address, encoded).get(1, TimeUnit.SECONDS);
				// Let the trace do everything regarding existing units
				return true;
			}
			catch (InterruptedException | ExecutionException | TimeoutException e) {
				setStatusMsg("Couldn't patch: " + e);
				Msg.error(this, "Couldn't patch", e);
				return false;
			}
		}
	}

	@Override
	protected void applyPatch(AddressRange rng, byte[] encoded)
			throws MemoryAccessException, CodeUnitInsertionException {
		if (!(getProgram() instanceof TraceProgramView view)) {
			return;
		}
		PatchDataCommand patch = new PatchDataCommand(encoded);
		patch.run(tool, view);
	}
}
