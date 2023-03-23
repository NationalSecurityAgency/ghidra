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
package ghidra.app.plugin.core.debug.service.emulation.data;

import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

import ghidra.app.services.TraceRecorder;
import ghidra.framework.plugintool.PluginTool;
import ghidra.pcode.exec.trace.data.DefaultPcodeTraceRegistersAccess;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.trace.model.TraceTimeViewport;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.Msg;

/**
 * The default data-and-debugger access shim for session registers
 */
public class DefaultPcodeDebuggerRegistersAccess extends DefaultPcodeTraceRegistersAccess
		implements PcodeDebuggerRegistersAccess, InternalPcodeDebuggerDataAccess {

	protected final PluginTool tool;
	protected final TraceRecorder recorder;

	/**
	 * Construct a shim
	 * 
	 * @param tool the tool controlling the session
	 * @param recorder the target's recorder
	 * @param platform the associated platform, having the same trace as the recorder
	 * @param snap the associated snap
	 * @param thread the associated thread whose registers to access
	 * @param frame the associated frame, or 0 if not applicable
	 * @param viewport the viewport, set to the same snapshot
	 */
	protected DefaultPcodeDebuggerRegistersAccess(PluginTool tool, TraceRecorder recorder,
			TracePlatform platform, long snap, TraceThread thread, int frame,
			TraceTimeViewport viewport) {
		super(platform, snap, thread, frame, viewport);
		this.tool = tool;
		this.recorder = recorder;
	}

	@Override
	public boolean isLive() {
		return InternalPcodeDebuggerDataAccess.super.isLive();
	}

	@Override
	public PluginTool getTool() {
		return tool;
	}

	@Override
	public TraceRecorder getRecorder() {
		return recorder;
	}

	@Override
	public CompletableFuture<Boolean> readFromTargetRegisters(AddressSetView guestView) {
		if (guestView.isEmpty() || !isLive()) {
			return CompletableFuture.completedFuture(false);
		}
		Set<Register> toRead = new HashSet<>();
		Language language = platform.getLanguage();
		for (AddressRange guestRng : guestView) {
			Register register =
				language.getRegister(guestRng.getMinAddress().getPhysicalAddress(),
					(int) guestRng.getLength());
			if (register == null) {
				Msg.error(this, "Could not figure register for " + guestRng);
			}
			else if (!recorder.getRegisterMapper(thread)
					.getRegistersOnTarget()
					.contains(register)) {
				Msg.warn(this, "Register not recognized by target: " + register);
			}
			else {
				toRead.add(register);
			}
		}
		return recorder.captureThreadRegisters(platform, thread, 0, toRead)
				.thenCompose(__ -> recorder.getTarget().getModel().flushEvents())
				.thenCompose(__ -> recorder.flushTransactions())
				.thenAccept(__ -> platform.getTrace().flushEvents())
				.thenApply(__ -> true);
	}

	@Override
	public CompletableFuture<Boolean> writeTargetRegister(Address address, byte[] data) {
		if (!isLive()) {
			return CompletableFuture.completedFuture(false);
		}
		return recorder.writeRegister(platform, thread, frame, address.getPhysicalAddress(), data)
				.thenCompose(__ -> recorder.getTarget().getModel().flushEvents())
				.thenCompose(__ -> recorder.flushTransactions())
				.thenAccept(__ -> platform.getTrace().flushEvents())
				.thenApply(__ -> true);
	}

	// No need to override getPropertyAccess. Registers are not static mapped.
}
