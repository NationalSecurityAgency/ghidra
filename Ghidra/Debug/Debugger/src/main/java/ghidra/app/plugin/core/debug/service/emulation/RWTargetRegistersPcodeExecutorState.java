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

import ghidra.app.plugin.core.debug.service.emulation.data.PcodeDebuggerRegistersAccess;
import ghidra.pcode.exec.trace.DefaultTracePcodeExecutorState;

/**
 * A state composing a single {@link RWTargetRegistersPcodeExecutorStatePiece}
 */
public class RWTargetRegistersPcodeExecutorState extends DefaultTracePcodeExecutorState<byte[]> {
	/**
	 * Create the state
	 * 
	 * @param data the trace-registers access shim
	 * @param mode whether to ever write the target
	 */
	public RWTargetRegistersPcodeExecutorState(PcodeDebuggerRegistersAccess data, Mode mode) {
		super(new RWTargetRegistersPcodeExecutorStatePiece(data, mode));
	}
}
