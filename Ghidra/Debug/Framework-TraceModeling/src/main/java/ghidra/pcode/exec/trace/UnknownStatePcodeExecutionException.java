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

import java.util.Arrays;

import ghidra.pcode.exec.AccessPcodeExecutionException;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;

public class UnknownStatePcodeExecutionException extends AccessPcodeExecutionException {

	public static String getMessage(Language language, Address address, int size) {
		if (address.getAddressSpace().isRegisterSpace()) {
			Register reg = language.getRegister(address, size);
			if (reg != null) {
				return "No recorded value for register " + reg;
			}
			return "No recorded value for register(s) " +
				Arrays.asList(language.getRegisters(address));
		}
		try {
			return "No recorded value for memory at " + new AddressRangeImpl(address, size);
		}
		catch (AddressOverflowException e) {
			throw new AssertionError(e);
		}
	}

	public UnknownStatePcodeExecutionException(Language language, Address address, int size) {
		super(getMessage(language, address, size));
	}

	public UnknownStatePcodeExecutionException(String message, Language language, Address address,
			int size) {
		super(message + ": " + getMessage(language, address, size));
	}
}
