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

import ghidra.pcode.exec.PcodeExecutorStatePiece;
import ghidra.trace.model.Trace;
import ghidra.trace.model.thread.TraceThread;

/**
 * A state piece which knows how to write its values back into a trace
 *
 * @param <A> the type of address offsets
 * @param <T> the type of values
 */
public interface TracePcodeExecutorStatePiece<A, T> extends PcodeExecutorStatePiece<A, T> {
	/**
	 * Write the accumulated values (cache) into the given trace
	 * 
	 * <p>
	 * <b>NOTE:</b> This method requires a transaction to have already been started on the
	 * destination trace.
	 * 
	 * @param trace the trace to modify
	 * @param snap the snap within the trace
	 * @param thread the thread to take register writes
	 * @param frame the frame for register writes
	 * @see TracePcodeMachine#writeDown(Trace, long, long)
	 */
	void writeDown(Trace trace, long snap, TraceThread thread, int frame);
}
