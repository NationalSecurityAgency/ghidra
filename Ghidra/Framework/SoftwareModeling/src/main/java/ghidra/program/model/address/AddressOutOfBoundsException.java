/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

/**
 * <p>An AddressOutOfBoundsException indicates that the Address is
 * being used to address Memory which does not exist.</p>
 *
 * @version 1999-03-31
 */
public class AddressOutOfBoundsException extends RuntimeException {
	/**
	 * <p>Constructs an AddressOutOfBoundsException with no detail message.<p>
	 */
	public AddressOutOfBoundsException() {
		super("Address not contained in memory.");
	}

	/**
	 * <p>Constructs an AddressOutOfBoundsException with the specified
	 * detail message.<p>
	 *
	 * @param message The message.
	 */
	public AddressOutOfBoundsException(String message) {
		super(message);
	}
} // AddressOutOfBoundsException
