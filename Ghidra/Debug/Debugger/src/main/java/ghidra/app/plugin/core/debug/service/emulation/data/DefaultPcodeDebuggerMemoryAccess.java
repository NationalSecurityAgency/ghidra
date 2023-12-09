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

import java.util.Objects;
import java.util.concurrent.CompletableFuture;

import ghidra.app.plugin.core.debug.utils.AbstractMappedMemoryBytesVisitor;
import ghidra.app.services.DebuggerStaticMappingService;
import ghidra.app.services.DebuggerStaticMappingService.MappedAddressRange;
import ghidra.debug.api.emulation.PcodeDebuggerMemoryAccess;
import ghidra.debug.api.target.Target;
import ghidra.framework.plugintool.PluginTool;
import ghidra.generic.util.datastruct.SemisparseByteArray;
import ghidra.pcode.exec.trace.data.DefaultPcodeTraceMemoryAccess;
import ghidra.pcode.exec.trace.data.PcodeTracePropertyAccess;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.trace.model.TraceTimeViewport;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

/**
 * The default data-and-debugger-access shim for session memory
 */
public class DefaultPcodeDebuggerMemoryAccess extends DefaultPcodeTraceMemoryAccess
		implements PcodeDebuggerMemoryAccess, InternalPcodeDebuggerDataAccess {

	protected final PluginTool tool;
	protected final Target target;

	/**
	 * Construct a shim
	 * 
	 * @param tool the tool controlling the session
	 * @param target the target
	 * @param platform the associated platform, having the same trace as the recorder
	 * @param snap the associated snap
	 * @param viewport the viewport, set to the same snapshot
	 */
	protected DefaultPcodeDebuggerMemoryAccess(PluginTool tool, Target target,
			TracePlatform platform, long snap, TraceTimeViewport viewport) {
		super(platform, snap, viewport);
		this.tool = Objects.requireNonNull(tool);
		this.target = target;
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
	public Target getTarget() {
		return target;
	}

	@Override
	public CompletableFuture<Boolean> readFromTargetMemory(AddressSetView guestView) {
		if (!isLive()) {
			return CompletableFuture.completedFuture(false);
		}
		AddressSetView hostView = platform.mapGuestToHost(guestView);
		return target.readMemoryAsync(hostView, TaskMonitor.DUMMY).thenApply(__ -> true);
	}

	@Override
	public CompletableFuture<Boolean> writeTargetMemory(Address address, byte[] data) {
		if (!isLive()) {
			return CompletableFuture.completedFuture(false);
		}
		return target.writeMemoryAsync(address, data).thenApply(__ -> true);
	}

	@Override
	public boolean readFromStaticImages(SemisparseByteArray bytes, AddressSetView guestView) {
		// TODO: Expand to block? DON'T OVERWRITE KNOWN!
		DebuggerStaticMappingService mappingService =
			tool.getService(DebuggerStaticMappingService.class);
		if (mappingService == null) {
			return false;
		}

		try {
			return new AbstractMappedMemoryBytesVisitor(mappingService, new byte[4096]) {
				@Override
				protected int read(Memory memory, Address addr, byte[] dest, int size)
						throws MemoryAccessException {
					int read = super.read(memory, addr, dest, size);
					if (read < size) {
						Msg.warn(this,
							String.format("  Partial read of %s. Wanted %d bytes. Got %d.",
								addr, size, read));
					}
					return read;
				}

				@Override
				protected boolean visitRange(Program program, AddressRange progRng,
						MappedAddressRange mappedRng) throws MemoryAccessException {
					Msg.debug(this,
						"Filling in unknown trace memory in emulator using mapped image: " +
							program + ": " + progRng);
					return super.visitRange(program, progRng, mappedRng);
				}

				@Override
				protected void visitData(Address hostAddr, byte[] data, int size) {
					Address guestAddr = platform.mapHostToGuest(hostAddr);
					bytes.putData(guestAddr.getOffset(), data, 0, size);
				}
			}.visit(platform.getTrace(), snap, platform.mapGuestToHost(guestView));
		}
		catch (MemoryAccessException e) {
			throw new AssertionError(e);
		}
	}

	@Override
	public <T> PcodeTracePropertyAccess<T> getPropertyAccess(String name, Class<T> type) {
		return new DefaultPcodeDebuggerPropertyAccess<>(this, name, type);
	}
}
