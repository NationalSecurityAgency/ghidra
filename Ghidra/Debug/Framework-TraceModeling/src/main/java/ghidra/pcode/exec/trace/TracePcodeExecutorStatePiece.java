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
import ghidra.pcode.exec.trace.data.PcodeTraceAccess;
import ghidra.pcode.exec.trace.data.PcodeTraceDataAccess;

/**
 * A state piece which knows how to write its values back into a trace
 *
 * @param <A> the type of address offsets
 * @param <T> the type of values
 */
public interface TracePcodeExecutorStatePiece<A, T> extends PcodeExecutorStatePiece<A, T> {

	/**
	 * Get the state's trace-data access shim
	 * 
	 * <p>
	 * This method is meant for auxiliary state pieces, so that it can access the same trace data as
	 * this piece.
	 * 
	 * @return the trace-data access shim
	 */
	PcodeTraceDataAccess getData();

	/**
	 * Write the accumulated values (cache) into the given trace
	 * 
	 * <p>
	 * <b>NOTE:</b> This method requires a transaction to have already been started on the
	 * destination trace.
	 * 
	 * @param into the destination data-access shim
	 * @see TracePcodeMachine#writeDown(PcodeTraceAccess)
	 */
	void writeDown(PcodeTraceDataAccess into);
}
