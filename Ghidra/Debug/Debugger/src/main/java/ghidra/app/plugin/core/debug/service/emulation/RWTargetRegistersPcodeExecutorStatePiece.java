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

import generic.ULongSpan.ULongSpanSet;
import ghidra.app.plugin.core.debug.service.emulation.data.PcodeDebuggerDataAccess;
import ghidra.app.plugin.core.debug.service.emulation.data.PcodeDebuggerRegistersAccess;
import ghidra.generic.util.datastruct.SemisparseByteArray;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Language;
import ghidra.trace.model.memory.TraceMemoryState;

/**
 * An executor state piece that knows to read live registers if applicable
 * 
 * <p>
 * This requires a trace-register access shim for the debugger. It will check if the shim is
 * associated with a live session. If so, it will direct the recorder to capture the register(s) to
 * be read, if they're not already {@link TraceMemoryState#KNOWN}. When such a target comments is
 * required, the state will wait up to 1 second for it to complete (see
 * {@link AbstractRWTargetCachedSpace#waitTimeout(CompletableFuture)}).
 * 
 * <ol>
 * <li>The cache, i.e., this state object</li>
 * <li>The trace</li>
 * <li>The live target, if applicable</li>
 * </ol>
 * 
 * <p>
 * If all those defer, the state is read as if filled with 0s.
 */
public class RWTargetRegistersPcodeExecutorStatePiece
		extends AbstractRWTargetPcodeExecutorStatePiece {

	/**
	 * A space, corresponding to a register space (really a thread) of this state
	 * 
	 * <p>
	 * All of the actual read logic is contained here. We override the space map factory so that it
	 * creates these spaces.
	 */
	protected class RWTargetRegistersCachedSpace extends AbstractRWTargetCachedSpace {

		protected final PcodeDebuggerRegistersAccess backing;

		public RWTargetRegistersCachedSpace(Language language, AddressSpace space,
				PcodeDebuggerRegistersAccess backing) {
			super(language, space, backing);
			this.backing = backing;
		}

		protected RWTargetRegistersCachedSpace(Language language, AddressSpace space,
				PcodeDebuggerRegistersAccess backing, SemisparseByteArray bytes,
				AddressSet written) {
			super(language, space, backing, bytes, written);
			this.backing = backing;
		}

		@Override
		public RWTargetRegistersCachedSpace fork() {
			return new RWTargetRegistersCachedSpace(language, uniqueSpace, backing, bytes.fork(),
				new AddressSet(written));
		}

		@Override
		protected ULongSpanSet readUninitializedFromTarget(ULongSpanSet uninitialized) {
			if (space.isUniqueSpace() || !backing.isLive()) {
				return uninitialized;
			}
			AddressSet addrsUninit = addrSet(uninitialized);
			AddressSetView unknown = backing.intersectUnknown(addrsUninit);
			waitTimeout(backing.readFromTargetRegisters(unknown));
			return uninitialized;
		}

		@Override
		public void write(long offset, byte[] val, int srcOffset, int length) {
			if (mode.isWriteTarget() && !space.isUniqueSpace() &&
				waitTimeout(backing.writeTargetRegister(space.getAddress(offset), val))) {
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
	 * @param data the trace-register access shim
	 * @param mode whether to ever write the target
	 */
	public RWTargetRegistersPcodeExecutorStatePiece(PcodeDebuggerRegistersAccess data, Mode mode) {
		super(data);
		this.mode = mode;
	}

	class WRTargetRegistersSpaceMap extends TargetBackedSpaceMap {
		public WRTargetRegistersSpaceMap() {
			super();
		}

		protected WRTargetRegistersSpaceMap(Map<AddressSpace, CachedSpace> spaceMap) {
			super(spaceMap);
		}

		@Override
		public AbstractSpaceMap<CachedSpace> fork() {
			return new WRTargetRegistersSpaceMap(fork(spaces));
		}

		@Override
		protected CachedSpace newSpace(AddressSpace space, PcodeDebuggerDataAccess data) {
			return new RWTargetRegistersCachedSpace(language, space,
				(PcodeDebuggerRegistersAccess) data);
		}
	}

	@Override
	protected AbstractSpaceMap<CachedSpace> newSpaceMap() {
		return new WRTargetRegistersSpaceMap();
	}
}
