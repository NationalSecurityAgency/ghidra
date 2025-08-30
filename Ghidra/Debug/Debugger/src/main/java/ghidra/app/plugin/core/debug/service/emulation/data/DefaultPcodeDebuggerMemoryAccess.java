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
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.pcode.exec.PcodeExecutorStatePiece;
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

	protected final ServiceProvider provider;
	protected final Target target;

	/**
	 * Construct a shim
	 * 
	 * @param provider the service provider (usually the tool)
	 * @param target the target
	 * @param platform the associated platform, having the same trace as the recorder
	 * @param snap the associated snap
	 * @param viewport the viewport, set to the same snapshot
	 */
	protected DefaultPcodeDebuggerMemoryAccess(ServiceProvider provider, Target target,
			TracePlatform platform, long snap, TraceTimeViewport viewport) {
		super(platform, snap, viewport);
		this.provider = Objects.requireNonNull(provider);
		this.target = target;
	}

	@Override
	public boolean isLive() {
		return InternalPcodeDebuggerDataAccess.super.isLive();
	}

	@Override
	public ServiceProvider getServiceProvider() {
		return provider;
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
	public AddressSetView readFromStaticImages(PcodeExecutorStatePiece<byte[], byte[]> piece,
			AddressSetView guestView) {
		// NOTE: If we expand to block, DON'T OVERWRITE KNOWN!
		DebuggerStaticMappingService mappingService =
			provider.getService(DebuggerStaticMappingService.class);
		if (mappingService == null) {
			return guestView;
		}

		AddressSet remains = new AddressSet(guestView);
		try {
			boolean result = new AbstractMappedMemoryBytesVisitor(mappingService, new byte[4096]) {
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
					piece.setVarInternal(guestAddr.getAddressSpace(), guestAddr.getOffset(), size,
						data);
					remains.delete(guestAddr, guestAddr.add(size));
				}
			}.visit(platform.getTrace(), snap, platform.mapGuestToHost(guestView));
			return result ? remains : guestView;
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
