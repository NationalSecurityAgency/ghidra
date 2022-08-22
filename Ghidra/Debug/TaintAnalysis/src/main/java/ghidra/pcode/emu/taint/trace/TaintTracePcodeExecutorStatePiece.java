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
package ghidra.pcode.emu.taint.trace;

import ghidra.program.model.address.AddressSpace;
import ghidra.trace.model.Trace;
import ghidra.trace.model.property.TracePropertyMapSpace;
import ghidra.trace.model.thread.TraceThread;

/**
 * The trace-integrated state piece for holding taint marks
 */
public class TaintTracePcodeExecutorStatePiece
		extends AbstractTaintTracePcodeExecutorStatePiece<TaintTraceSpace> {

	/**
	 * Create the taint piece
	 * 
	 * @param trace the trace from which to load taint marks
	 * @param snap the snap from which to load taint marks
	 * @param thread if a register space, the thread from which to load taint marks
	 * @param frame if a register space, the frame
	 */
	public TaintTracePcodeExecutorStatePiece(Trace trace, long snap, TraceThread thread,
			int frame) {
		super(trace, snap, thread, frame);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * Here we create a map that uses {@link TaintTraceSpace}s. The framework provides the concept
	 * of a space map where storage is actually a cache backed by some other object. The backing
	 * object we'll use here is {@link TracePropertyMapSpace}, which is provided by the
	 * TraceModeling module. We'll need a little bit of extra logic for fetching a register space
	 * vs. a plain memory space, but after that, we need not care which address space the backing
	 * object is for.
	 */
	@Override
	protected AbstractSpaceMap<TaintTraceSpace> newSpaceMap() {
		return new CacheingSpaceMap<TracePropertyMapSpace<String>, TaintTraceSpace>() {
			@Override
			protected TracePropertyMapSpace<String> getBacking(AddressSpace space) {
				if (map == null) {
					return null;
				}
				if (space.isRegisterSpace()) {
					return map.getPropertyMapRegisterSpace(thread, frame, false);
				}
				return map.getPropertyMapSpace(space, false);
			}

			@Override
			protected TaintTraceSpace newSpace(AddressSpace space,
					TracePropertyMapSpace<String> backing) {
				return new TaintTraceSpace(space, backing, snap);
			}
		};
	}
}
