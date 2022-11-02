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

import ghidra.pcode.exec.PairedPcodeExecutorState;
import ghidra.pcode.exec.PcodeExecutorState;
import ghidra.pcode.exec.trace.data.DefaultPcodeTraceAccess;
import ghidra.pcode.exec.trace.data.PcodeTraceDataAccess;
import ghidra.trace.model.Trace;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.memory.TraceMemoryState;
import ghidra.trace.model.thread.TraceThread;

/**
 * A state composing a single {@link DirectBytesTracePcodeExecutorStatePiece}
 * 
 * @see TraceSleighUtils
 */
public class DirectBytesTracePcodeExecutorState extends DefaultTracePcodeExecutorState<byte[]> {

	/**
	 * Get a trace-data access shim suitable for evaluating Sleigh expressions with thread context
	 * 
	 * <p>
	 * Do not use the returned shim for emulation, but only for one-off p-code execution, e.g.,
	 * Sleigh expression evaluation.
	 * 
	 * @param platform the platform whose language and address mappings to use
	 * @param snap the source snap
	 * @param thread the thread for register context
	 * @param frame the frame for register context, 0 if not applicable
	 * @return the trace-data access shim
	 */
	public static PcodeTraceDataAccess getDefaultThreadAccess(TracePlatform platform, long snap,
			TraceThread thread, int frame) {
		return new DefaultPcodeTraceAccess(platform, snap).getDataForThreadState(thread, frame);
	}

	/**
	 * Create the state
	 * 
	 * @param data the trace-data access shim
	 */
	public DirectBytesTracePcodeExecutorState(PcodeTraceDataAccess data) {
		super(new DirectBytesTracePcodeExecutorStatePiece(data));
	}

	/**
	 * Create the state
	 * 
	 * @param platform the platform whose language and address mappings to use
	 * @param snap the snap the executor will access
	 * @param thread the thread for reading and writing registers
	 * @param frame the frame for reading and writing registers
	 */
	public DirectBytesTracePcodeExecutorState(TracePlatform platform, long snap, TraceThread thread,
			int frame) {
		this(getDefaultThreadAccess(platform, snap, thread, frame));
	}

	/**
	 * Pair this state with an auxiliary {@link TraceMemoryState} piece
	 * 
	 * @return the new state, composing this state with the new piece
	 * @see TraceSleighUtils#buildByteWithStateExecutor(Trace, long, TraceThread, int)
	 */
	public PcodeExecutorState<Pair<byte[], TraceMemoryState>> withMemoryState() {
		return new PairedPcodeExecutorState<>(this,
			new TraceMemoryStatePcodeExecutorStatePiece(getData()));
	}
}
