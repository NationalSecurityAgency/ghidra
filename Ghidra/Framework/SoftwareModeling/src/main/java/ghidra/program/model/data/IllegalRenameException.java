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
package ghidra.program.model.data;

import ghidra.util.exception.UsrException;

/**
 * Exception thrown if a data type does not allow its name to be changed.
 */
public class IllegalRenameException extends UsrException {

	/**
	 * Constructor.
	 */
	public IllegalRenameException() {
		super("Rename is not allowed for this data type");
	}

	/**
	 * Constructor
	 * @param message detailed message explaining exception
	 */
	public IllegalRenameException(String message) {
		super(message);
	}
}
