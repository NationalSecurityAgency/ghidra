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

import java.nio.ByteBuffer;
import java.util.concurrent.CompletableFuture;

import db.Transaction;
import generic.theme.GIcon;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.trace.model.Trace;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.memory.TraceMemoryOperations;
import ghidra.trace.model.memory.TraceMemorySpace;
import ghidra.trace.model.thread.TraceThread;

public class TraceControlMode extends ControlMode {

	public TraceControlMode() {
		super("Trace", new GIcon("icon.debugger.control.mode.rw.trace"), new GIcon(
			"icon.debugger.control.mode.ro.trace"));
	}

	@Override
	public boolean isTarget() {
		return false;
	}

	@Override
	public boolean followsPresent() {
		return false;
	}

	@Override
	public boolean canEdit(DebuggerCoordinates coordinates) {
		return isEditEnabled && coordinates.getTrace() != null;
	}

	@Override
	public boolean isVariableEditable(DebuggerCoordinates coordinates, Address address,
			int length) {
		if (!canEdit(coordinates)) {
			return false;
		}
		return address.isMemoryAddress() || coordinates.getThread() != null;
	}

	@Override
	public CompletableFuture<Void> setVariable(PluginTool tool,
			DebuggerCoordinates coordinates, Address guestAddress, byte[] data) {
		if (!isEditEnabled) {
			return CompletableFuture.failedFuture(new MemoryAccessException("Read-only mode"));
		}
		Trace trace = coordinates.getTrace();
		TracePlatform platform = platformFor(coordinates, guestAddress);
		long snap = coordinates.getViewSnap();
		Address hostAddress = platform.mapGuestToHost(guestAddress);
		if (hostAddress == null) {
			throw new IllegalArgumentException(
				"Guest address " + guestAddress + " is not mapped");
		}
		TraceMemoryOperations memOrRegs;
		Address overlayAddress;
		try (Transaction _ = trace.openTransaction("Edit Variable")) {
			if (hostAddress.isRegisterAddress()) {
				TraceThread thread = coordinates.getThread();
				if (thread == null) {
					throw new IllegalArgumentException("Register edits require a thread.");
				}
				TraceMemorySpace regs = trace.getMemoryManager()
						.getMemoryRegisterSpace(thread, coordinates.getFrame(),
							true);
				memOrRegs = regs;
				overlayAddress = regs.getAddressSpace().getOverlayAddress(hostAddress);
			}
			else {
				memOrRegs = trace.getMemoryManager();
				overlayAddress = hostAddress;
			}
			if (memOrRegs.putBytes(snap, overlayAddress,
				ByteBuffer.wrap(data)) != data.length) {
				return CompletableFuture.failedFuture(new MemoryAccessException());
			}
		}
		return CompletableFuture.completedFuture(null);
	}

	@Override
	public boolean useEmulatedBreakpoints() {
		return true;
	}

}
