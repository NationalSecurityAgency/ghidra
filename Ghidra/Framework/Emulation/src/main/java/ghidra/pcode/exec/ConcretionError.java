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
package ghidra.pcode.exec;

import ghidra.pcode.exec.PcodeArithmetic.Purpose;

/**
 * The emulator or a client attempted to concretize an abstract value
 */
public class ConcretionError extends PcodeExecutionException {
	private final Purpose purpose;

	/**
	 * Create the exception
	 * 
	 * @param message a message for the client
	 * @param purpose the reason why the emulator needs a concrete value
	 */
	public ConcretionError(String message, Purpose purpose) {
		super(message);
		this.purpose = purpose;
	}

	/**
	 * Get the reason why the emulator needs a concrete value
	 * 
	 * @return the purpose
	 */
	public Purpose getPurpose() {
		return purpose;
	}
}
