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

import ghidra.dbg.target.TargetRegisterBank;

/**
 * An exception for when there is an unknown (possibly permanent) condition preventing register
 * access via {@link TargetRegisterBank#readRegisters(java.util.Collection)},
 * {@link TargetRegisterBank#writeRegisters(java.util.Map)}, and related methods.
 * 
 * <p>
 * If the underlying debugger is simply in a state that prevents the request from being fulfilled,
 * e.g., the target process is running, then use {@link DebuggerModelAccessException} instead.
 */
public class DebuggerRegisterAccessException extends DebuggerRuntimeException {
	public DebuggerRegisterAccessException(String message, Throwable cause) {
		super(message, cause);
	}

	public DebuggerRegisterAccessException(String message) {
		super(message);
	}
}
