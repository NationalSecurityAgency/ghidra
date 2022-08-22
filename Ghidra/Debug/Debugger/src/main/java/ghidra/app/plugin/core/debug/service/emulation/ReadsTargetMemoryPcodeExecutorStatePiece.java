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

import java.util.Collection;
import java.util.Map.Entry;
import java.util.concurrent.CompletableFuture;

import ghidra.app.services.DebuggerStaticMappingService;
import ghidra.app.services.DebuggerStaticMappingService.MappedAddressRange;
import ghidra.app.services.TraceRecorder;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.trace.model.Trace;
import ghidra.trace.model.memory.TraceMemorySpace;
import ghidra.trace.model.memory.TraceMemoryState;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.MathUtilities;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

/**
 * An executor state piece that knows to read live memory if applicable
 * 
 * <p>
 * This takes a handle to the trace's recorder, if applicable, and will check if the source snap is
 * the recorder's snap. If so, it will direct the recorder to capture the block(s) containing the
 * read, if they're not already {@link TraceMemoryState#KNOWN}. When such reads occur, the state
 * will wait up to 1 second (see
 * {@link AbstractReadsTargetCachedSpace#waitTimeout(CompletableFuture)}).
 * 
 * <p>
 * This state will also attempt to fill unknown bytes with values from mapped static images. The
 * order to retrieve state is:
 * <ol>
 * <li>The cache, i.e., this state object</li>
 * <li>The trace</li>
 * <li>The live target, if applicable</li>
 * <li>Mapped static images, if available</li>
 * </ol>
 * 
 * <p>
 * If all those defer, the state is read as if filled with 0s.
 */
public class ReadsTargetMemoryPcodeExecutorStatePiece
		extends AbstractReadsTargetPcodeExecutorStatePiece {

	/**
	 * A space, corresponding to a memory space, of this state
	 * 
	 * <p>
	 * All of the actual read logic is contained here. We override the space map factory so that it
	 * creates these spaces.
	 */
	protected class ReadsTargetMemoryCachedSpace extends AbstractReadsTargetCachedSpace {

		public ReadsTargetMemoryCachedSpace(Language language, AddressSpace space,
				TraceMemorySpace backing, long snap) {
			super(language, space, backing, snap);
		}

		@Override
		protected void fillUninitialized(AddressSet uninitialized) {
			AddressSet unknown;
			unknown = computeUnknown(uninitialized);
			if (unknown.isEmpty()) {
				return;
			}
			if (fillUnknownWithRecorder(unknown)) {
				unknown = computeUnknown(uninitialized);
				if (unknown.isEmpty()) {
					return;
				}
			}
			if (fillUnknownWithStaticImages(unknown)) {
				unknown = computeUnknown(uninitialized);
				if (unknown.isEmpty()) {
					return;
				}
			}
		}

		protected boolean fillUnknownWithRecorder(AddressSet unknown) {
			if (!isLive()) {
				return false;
			}
			waitTimeout(recorder.readMemoryBlocks(unknown, TaskMonitor.DUMMY, false));
			return true;
		}

		private boolean fillUnknownWithStaticImages(AddressSet unknown) {
			boolean result = false;
			// TODO: Expand to block? DON'T OVERWRITE KNOWN!
			DebuggerStaticMappingService mappingService =
				tool.getService(DebuggerStaticMappingService.class);
			byte[] data = new byte[4096];
			for (Entry<Program, Collection<MappedAddressRange>> ent : mappingService
					.getOpenMappedViews(trace, unknown, snap)
					.entrySet()) {
				Program program = ent.getKey();
				Memory memory = program.getMemory();
				AddressSetView initialized = memory.getLoadedAndInitializedAddressSet();

				Collection<MappedAddressRange> mappedSet = ent.getValue();
				for (MappedAddressRange mappedRng : mappedSet) {
					AddressRange drng = mappedRng.getDestinationAddressRange();
					long shift = mappedRng.getShift();
					for (AddressRange subdrng : initialized.intersectRange(drng.getMinAddress(),
						drng.getMaxAddress())) {
						Msg.debug(this,
							"Filling in unknown trace memory in emulator using mapped image: " +
								program + ": " + subdrng);
						long lower = subdrng.getMinAddress().getOffset();
						long fullLen = subdrng.getLength();
						while (fullLen > 0) {
							int len = MathUtilities.unsignedMin(data.length, fullLen);
							try {
								int read =
									memory.getBytes(space.getAddress(lower), data, 0, len);
								if (read < len) {
									Msg.warn(this,
										"  Partial read of " + subdrng + ". Got " + read +
											" bytes");
								}
								// write(lower - shift, data, 0 ,read);
								bytes.putData(lower - shift, data, 0, read);
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
	}

	public ReadsTargetMemoryPcodeExecutorStatePiece(PluginTool tool, Trace trace, long snap,
			TraceThread thread, int frame, TraceRecorder recorder) {
		super(tool, trace, snap, thread, frame, recorder);
	}

	@Override
	protected AbstractSpaceMap<CachedSpace> newSpaceMap() {
		return new TargetBackedSpaceMap() {
			@Override
			protected CachedSpace newSpace(AddressSpace space, TraceMemorySpace backing) {
				return new ReadsTargetMemoryCachedSpace(language, space, backing, snap);
			}
		};
	}
}
