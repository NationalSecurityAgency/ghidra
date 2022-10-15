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

import java.util.Collection;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;

import ghidra.app.services.DebuggerStaticMappingService;
import ghidra.app.services.DebuggerStaticMappingService.MappedAddressRange;
import ghidra.app.services.TraceRecorder;
import ghidra.framework.plugintool.PluginTool;
import ghidra.generic.util.datastruct.SemisparseByteArray;
import ghidra.pcode.exec.trace.data.DefaultPcodeTraceMemoryAccess;
import ghidra.pcode.exec.trace.data.PcodeTracePropertyAccess;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.trace.model.Trace;
import ghidra.trace.model.TraceTimeViewport;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.util.MathUtilities;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

/**
 * The default data-and-debugger-access shim for session memory
 */
public class DefaultPcodeDebuggerMemoryAccess extends DefaultPcodeTraceMemoryAccess
		implements PcodeDebuggerMemoryAccess, InternalPcodeDebuggerDataAccess {

	protected final PluginTool tool;
	protected final TraceRecorder recorder;

	/**
	 * Construct a shim
	 * 
	 * @param tool the tool controlling the session
	 * @param recorder the target's recorder
	 * @param platform the associated platform, having the same trace as the recorder
	 * @param snap the associated snap
	 * @param viewport the viewport, set to the same snapshot
	 */
	protected DefaultPcodeDebuggerMemoryAccess(PluginTool tool, TraceRecorder recorder,
			TracePlatform platform, long snap, TraceTimeViewport viewport) {
		super(platform, snap, viewport);
		this.tool = Objects.requireNonNull(tool);
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
	public CompletableFuture<Boolean> readFromTargetMemory(AddressSetView guestView) {
		if (!isLive()) {
			return CompletableFuture.completedFuture(false);
		}
		AddressSetView hostView = platform.mapGuestToHost(guestView);
		return recorder.readMemoryBlocks(hostView, TaskMonitor.DUMMY)
				.thenCompose(__ -> recorder.getTarget().getModel().flushEvents())
				.thenCompose(__ -> recorder.flushTransactions())
				.thenAccept(__ -> platform.getTrace().flushEvents())
				.thenApply(__ -> true);
	}

	@Override
	public CompletableFuture<Boolean> writeTargetMemory(Address address, byte[] data) {
		if (!isLive()) {
			return CompletableFuture.completedFuture(false);
		}
		return recorder.writeMemory(address, data)
				.thenCompose(__ -> recorder.getTarget().getModel().flushEvents())
				.thenCompose(__ -> recorder.flushTransactions())
				.thenAccept(__ -> platform.getTrace().flushEvents())
				.thenApply(__ -> true);
	}

	@Override
	public boolean readFromStaticImages(SemisparseByteArray bytes, AddressSetView guestView) {
		boolean result = false;
		// TODO: Expand to block? DON'T OVERWRITE KNOWN!
		DebuggerStaticMappingService mappingService =
			tool.getService(DebuggerStaticMappingService.class);
		if (mappingService == null) {
			return false;
		}
		byte[] data = new byte[4096];

		Trace trace = platform.getTrace();
		AddressSetView hostView = platform.mapGuestToHost(guestView);
		for (Entry<Program, Collection<MappedAddressRange>> ent : mappingService
				.getOpenMappedViews(trace, hostView, snap)
				.entrySet()) {
			Program program = ent.getKey();
			Memory memory = program.getMemory();
			AddressSetView initialized = memory.getLoadedAndInitializedAddressSet();

			Collection<MappedAddressRange> mappedSet = ent.getValue();
			for (MappedAddressRange mappedRng : mappedSet) {
				AddressRange progRng = mappedRng.getDestinationAddressRange();
				AddressSpace progSpace = progRng.getAddressSpace();
				for (AddressRange subProgRng : initialized.intersectRange(progRng.getMinAddress(),
					progRng.getMaxAddress())) {
					Msg.debug(this,
						"Filling in unknown trace memory in emulator using mapped image: " +
							program + ": " + subProgRng);
					long lower = subProgRng.getMinAddress().getOffset();
					long fullLen = subProgRng.getLength();
					while (fullLen > 0) {
						int len = MathUtilities.unsignedMin(data.length, fullLen);
						try {
							Address progAddr = progSpace.getAddress(lower);
							int read = memory.getBytes(progAddr, data, 0, len);
							if (read < len) {
								Msg.warn(this,
									"  Partial read of " + subProgRng + ". Got " + read +
										" bytes");
							}
							Address hostAddr = mappedRng.mapDestinationToSource(progAddr);
							Address guestAddr = platform.mapHostToGuest(hostAddr);
							// write(lower - shift, data, 0 ,read);
							bytes.putData(guestAddr.getOffset(), data, 0, read);
						}
						catch (MemoryAccessException | AddressOutOfBoundsException e) {
							throw new AssertionError(e);
						}
						lower += len;
						fullLen -= len;
					}
					result = true;
				}
			}
		}
		return result;
	}

	@Override
	public <T> PcodeTracePropertyAccess<T> getPropertyAccess(String name, Class<T> type) {
		return new DefaultPcodeDebuggerPropertyAccess<>(this, name, type);
	}
}
