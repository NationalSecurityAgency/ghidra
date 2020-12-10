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
package ghidra.dbg.error;

import ghidra.dbg.target.TargetMemory;
import ghidra.program.model.address.Address;

/**
 * An exception for when there is an unknown (possibly permanent) condition preventing memory access
 * via {@link TargetMemory#readMemory(Address, int)} and
 * {@link TargetMemory#writeMemory(Address, byte[])}
 * 
 * <p>
 * If the underlying debugger is simply in a state that prevents the request from being fulfilled,
 * e.g., the target process is running, then use {@link DebuggerModelAccessException} instead.
 */
public class DebuggerMemoryAccessException extends DebuggerRuntimeException {
	public DebuggerMemoryAccessException(String message, Throwable cause) {
		super(message, cause);
	}

	public DebuggerMemoryAccessException(String message) {
		super(message);
	}
}
