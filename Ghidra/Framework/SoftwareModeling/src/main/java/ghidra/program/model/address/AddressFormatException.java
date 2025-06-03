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
package ghidra.program.model.address;

import ghidra.util.exception.UsrException;

/**
 * <p>An AddressFormatException is thrown when a string that is
 * supposed to be an address representation cannot be parsed.</p>
 */
public class AddressFormatException extends UsrException {
    /**
	 * <p>Constructs an AddressFormatException with no detail message.
	 */
    public AddressFormatException() {
        super("Cannot parse string into address.");
    }


    /**
	 * <p>Constructs an AddressFormatException with the specified
	 * detail message.
	 *
	 * @param message A user message.
	 */
    public AddressFormatException(String message) {
        super(message);
    }
}
