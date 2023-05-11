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

import java.util.Map;
import java.util.concurrent.CompletableFuture;

import generic.ULongSpan;
import generic.ULongSpan.ULongSpanSet;
import ghidra.app.plugin.core.debug.service.emulation.data.PcodeDebuggerDataAccess;
import ghidra.app.plugin.core.debug.service.emulation.data.PcodeDebuggerMemoryAccess;
import ghidra.generic.util.datastruct.SemisparseByteArray;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Language;
import ghidra.trace.model.memory.TraceMemoryState;

/**
 * An executor state piece that knows to read live memory if applicable
 * 
 * <p>
 * This requires a trace-memory access shim for the debugger. It will check if the shim is
 * associated with a live session. If so, it will direct the recorder to capture the block(s)
 * containing the read, if they're not already {@link TraceMemoryState#KNOWN}. When such a target
 * comments is required, the state will wait up to 1 second for it to complete (see
 * {@link AbstractRWTargetCachedSpace#waitTimeout(CompletableFuture)}).
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
public class RWTargetMemoryPcodeExecutorStatePiece
		extends AbstractRWTargetPcodeExecutorStatePiece {

	/**
	 * A space, corresponding to a memory space, of this state
	 * 
	 * <p>
	 * All of the actual read logic is contained here. We override the space map factory so that it
	 * creates these spaces.
	 */
	protected class RWTargetMemoryCachedSpace extends AbstractRWTargetCachedSpace {

		protected final PcodeDebuggerMemoryAccess backing;

		public RWTargetMemoryCachedSpace(Language language, AddressSpace space,
				PcodeDebuggerMemoryAccess backing) {
			super(language, space, backing);
			this.backing = backing;
		}

		protected RWTargetMemoryCachedSpace(Language language, AddressSpace space,
				PcodeDebuggerMemoryAccess backing, SemisparseByteArray bytes, AddressSet written) {
			super(language, space, backing, bytes, written);
			this.backing = backing;
		}

		@Override
		public RWTargetMemoryCachedSpace fork() {
			return new RWTargetMemoryCachedSpace(language, space, backing, bytes.fork(),
				new AddressSet(written));
		}

		@Override
		protected ULongSpanSet readUninitializedFromTarget(ULongSpanSet uninitialized) {
			if (space.isUniqueSpace()) {
				return uninitialized;
			}
			AddressSetView unknown;
			AddressSet addrsUninit = addrSet(uninitialized);
			unknown = backing.intersectUnknown(addrsUninit);
			if (unknown.isEmpty()) {
				return uninitialized;
			}
			if (backing.isLive() && waitTimeout(backing.readFromTargetMemory(unknown))) {
				unknown = backing.intersectUnknown(addrsUninit);
				if (unknown.isEmpty()) {
					return uninitialized;
				}
			}
			if (backing.readFromStaticImages(bytes, unknown)) {
				ULongSpan bound = uninitialized.bound();
				return bytes.getUninitialized(bound.min(), bound.max());
			}
			return uninitialized;
		}

		@Override
		public void write(long offset, byte[] val, int srcOffset, int length) {
			if (mode.isWriteTarget() && !space.isUniqueSpace() &&
				waitTimeout(backing.writeTargetMemory(space.getAddress(offset), val))) {
				// Change should already be recorded, if successful
				return;
			}
			super.write(offset, val, srcOffset, length);
		}
	}

	private final Mode mode;

	/**
	 * Construct a piece
	 * 
	 * @param data the trace-memory access shim
	 * @param mode whether to ever write the target
	 */
	public RWTargetMemoryPcodeExecutorStatePiece(PcodeDebuggerMemoryAccess data, Mode mode) {
		super(data);
		this.mode = mode;
	}

	class WRTargetMemorySpaceMap extends TargetBackedSpaceMap {
		public WRTargetMemorySpaceMap() {
			super();
		}

		protected WRTargetMemorySpaceMap(Map<AddressSpace, CachedSpace> spaceMap) {
			super(spaceMap);
		}

		@Override
		public AbstractSpaceMap<CachedSpace> fork() {
			return new WRTargetMemorySpaceMap(fork(spaces));
		}

		@Override
		protected CachedSpace newSpace(AddressSpace space, PcodeDebuggerDataAccess data) {
			return new RWTargetMemoryCachedSpace(language, space,
				(PcodeDebuggerMemoryAccess) data);
		}
	}

	@Override
	protected AbstractSpaceMap<CachedSpace> newSpaceMap() {
		return new WRTargetMemorySpaceMap();
	}
}
