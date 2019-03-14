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
package ghidra.program.model.data;

import ghidra.util.exception.UsrException;

/**
 * Exception thrown if a data type is not valid for the operation being performed.
 */
public class InvalidDataTypeException extends UsrException {

	/**
	 * Constructor.
	 */
	public InvalidDataTypeException() {
		super("Invalid data type error.");
	}

	/**
	 * Constructor
	 * @param dt the data type that is invalid for the operation being performed.
	 */
	public InvalidDataTypeException(DataType dt) {
		super("Invalid data type error for " + dt.getDisplayName() + ".");
	}

	/**
	 * Constructor
	 * @param message detailed message explaining exception
	 */
	public InvalidDataTypeException(String message) {
		super(message);
	}

	/**
	 * Construct a new InvalidDataTypeException with the given message and cause
	 * 
	 * @param msg    the exception message
	 * @param cause  the exception cause
	 */
	public InvalidDataTypeException(String msg, Throwable cause) {
		super(msg, cause);
	}
}
