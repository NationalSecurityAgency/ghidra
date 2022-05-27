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

/**
 * The emulated program invoked a system call incorrectly
 */
public class EmuInvalidSystemCallException extends EmuSystemException {

	/**
	 * The system call number was not valid
	 * 
	 * @param number the system call number
	 */
	public EmuInvalidSystemCallException(long number) {
		this("Invalid system call number: " + number);
	}

	public EmuInvalidSystemCallException(String message) {
		super(message);
	}

	public EmuInvalidSystemCallException(String message, Throwable cause) {
		super(message, null, cause);
	}
}
