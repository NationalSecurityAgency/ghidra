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
package ghidra.pcode.emu.sys;

import java.math.BigInteger;

import ghidra.pcode.exec.PcodeArithmetic;
import ghidra.pcode.exec.PcodeArithmetic.Purpose;

/**
 * A simulated process (or thread group) has exited
 * 
 * <p>
 * The simulator should catch this exception and terminate accordingly. Continuing execution of the
 * emulator beyond this exception will cause undefined behavior.
 */
public class EmuProcessExitedException extends EmuSystemException {

	/**
	 * Attempt to concretize a value and convert it to hex
	 * 
	 * @param <T> the type of the status
	 * @param arithmetic the arithmetic to operate on the value
	 * @param status the status value
	 * @return the hex string, or the error message
	 */
	public static <T> String tryConcereteToString(PcodeArithmetic<T> arithmetic, T status) {
		try {
			BigInteger value = arithmetic.toBigInteger(status, Purpose.INSPECT);
			return value.toString();
		}
		catch (Exception e) {
			return status.toString();
		}
	}

	private final Object status;

	/**
	 * Construct a process-exited exception with the given status code
	 * 
	 * <p>
	 * This will attempt to concretize the status according to the given arithmetic, for display
	 * purposes. The original status remains accessible via {@link #getStatus()}
	 * 
	 * @param <T> the type values processed by the library
	 * @param arithmetic the machine's arithmetic
	 * @param status
	 */
	public <T> EmuProcessExitedException(PcodeArithmetic<T> arithmetic, T status) {
		super("Process exited with status " + tryConcereteToString(arithmetic, status));
		this.status = status;
	}

	/**
	 * Get the status code as a {@code T} of the throwing machine
	 * 
	 * @return the status
	 */
	public Object getStatus() {
		return status;
	}
}
