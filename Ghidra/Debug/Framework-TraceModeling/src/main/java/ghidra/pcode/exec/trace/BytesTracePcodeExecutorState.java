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

import ghidra.trace.model.Trace;
import ghidra.trace.model.thread.TraceThread;

/**
 * A state composing a single {@link BytesTracePcodeExecutorStatePiece}
 */
class BytesTracePcodeExecutorState extends DefaultTracePcodeExecutorState<byte[]> {
	/**
	 * Create the state
	 * 
	 * @param trace the trace from which bytes are loaded
	 * @param snap the snap from which bytes are loaded
	 * @param thread if applicable, the thread identifying the register space
	 * @param frame if applicable, the frame identifying the register space
	 */
	public BytesTracePcodeExecutorState(Trace trace, long snap, TraceThread thread, int frame) {
		super(new BytesTracePcodeExecutorStatePiece(trace, snap, thread, frame));
	}
}
