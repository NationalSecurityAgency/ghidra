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

import ghidra.pcode.exec.PcodeExecutorState;
import ghidra.pcode.exec.trace.data.PcodeTraceDataAccess;

/**
 * An interface for trace-bound states
 *
 * <p>
 * In particular, because this derives from {@link TracePcodeExecutorStatePiece}, such states are
 * required to implement {@link #writeDown(PcodeTraceDataAccess)}. This interface also
 * derives from {@link PcodeExecutorState} so that, as the name implies, they can be used where a
 * state is required.
 * 
 * @param <T> the type of values
 */
public interface TracePcodeExecutorState<T>
		extends PcodeExecutorState<T>, TracePcodeExecutorStatePiece<T, T> {
	// Nothing to add. Simply a composition of interfaces.
}
