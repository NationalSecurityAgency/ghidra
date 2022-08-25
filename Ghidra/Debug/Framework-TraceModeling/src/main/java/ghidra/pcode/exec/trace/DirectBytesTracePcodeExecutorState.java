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
package ghidra.pcode.exec.trace;

import org.apache.commons.lang3.tuple.Pair;

import ghidra.pcode.exec.*;
import ghidra.trace.model.Trace;
import ghidra.trace.model.memory.TraceMemoryState;
import ghidra.trace.model.thread.TraceThread;

/**
 * A state composing a single {@link DirectBytesTracePcodeExecutorStatePiece}
 * 
 * <p>
 * Note this does not implement {@link DefaultTracePcodeExecutorState} because it treats the trace
 * as if it were a stand-alone state. The interface expects implementations to lazily load into a
 * cache and write it back down later. This does not do that.
 * 
 * @see TraceSleighUtils
 */
public class DirectBytesTracePcodeExecutorState extends DefaultPcodeExecutorState<byte[]> {
	private final Trace trace;
	private final long snap;
	private final TraceThread thread;
	private final int frame;

	/**
	 * Create the state
	 * 
	 * @param trace the trace the executor will access
	 * @param snap the snap the executor will access
	 * @param thread the thread for reading and writing registers
	 * @param frame the frame for reading and writing registers
	 */
	public DirectBytesTracePcodeExecutorState(Trace trace, long snap, TraceThread thread,
			int frame) {
		super(new DirectBytesTracePcodeExecutorStatePiece(trace, snap, thread, frame));
		this.trace = trace;
		this.snap = snap;
		this.thread = thread;
		this.frame = frame;
	}

	/**
	 * Pair this state with an auxiliary {@link TraceMemoryState} piece
	 * 
	 * @return the new state, composing this state with the new piece
	 * @see TraceSleighUtils#buildByteWithStateExecutor(Trace, long, TraceThread, int)
	 */
	public PcodeExecutorState<Pair<byte[], TraceMemoryState>> withMemoryState() {
		return new PairedPcodeExecutorState<>(this,
			new TraceMemoryStatePcodeExecutorStatePiece(trace, snap, thread, frame));
	}
}
