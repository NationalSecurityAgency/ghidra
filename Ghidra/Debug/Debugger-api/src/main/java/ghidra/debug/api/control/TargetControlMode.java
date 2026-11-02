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
package ghidra.debug.api.control;

import java.util.concurrent.CompletableFuture;

import generic.theme.GIcon;
import ghidra.debug.api.target.Target;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemoryAccessException;

public class TargetControlMode extends ControlMode {

	public TargetControlMode() {
		super("Target", new GIcon("icon.debugger.control.mode.rw.target"), new GIcon(
			"icon.debugger.control.mode.ro.target"));
	}

	@Override
	public boolean isTarget() {
		return true;
	}

	@Override
	public boolean followsPresent() {
		return true;
	}

	@Override
	public boolean canEdit(DebuggerCoordinates coordinates) {
		return isEditEnabled && coordinates.isAliveAndPresent();
	}

	@Override
	public boolean isVariableEditable(DebuggerCoordinates coordinates, Address address,
			int length) {
		if (!canEdit(coordinates)) {
			return false;
		}
		Target target = coordinates.getTarget();
		return target.isVariableExists(platformFor(coordinates, address),
			coordinates.getThread(), coordinates.getFrame(), address, length);
	}

	@Override
	public CompletableFuture<Void> setVariable(PluginTool tool,
			DebuggerCoordinates coordinates, Address address, byte[] data) {
		if (!isEditEnabled) {
			return CompletableFuture.failedFuture(new MemoryAccessException("Read-only mode"));
		}
		Target target = coordinates.getTarget();
		if (target == null) {
			return CompletableFuture
					.failedFuture(new MemoryAccessException("Trace has no live target"));
		}
		if (!coordinates.isAliveAndPresent()) {
			return CompletableFuture
					.failedFuture(new MemoryAccessException("View is not the present"));
		}
		return target.writeVariableAsync(platformFor(coordinates, address),
			coordinates.getThread(), coordinates.getFrame(), address, data);
	}

	@Override
	public boolean useEmulatedBreakpoints() {
		return false;
	}

	@Override
	public boolean isSelectable(DebuggerCoordinates coordinates) {
		return coordinates.isAlive();
	}

	@Override
	public ControlMode getAlternative(DebuggerCoordinates coordinates) {
		return EMULATOR;
	}
}
