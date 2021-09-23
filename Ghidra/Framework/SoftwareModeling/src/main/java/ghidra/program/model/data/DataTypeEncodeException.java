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
 * Exception thrown when a value cannot be encoded for a data type
 */
public class DataTypeEncodeException extends UsrException {

	private final Object value;
	private final DataType dt;

	/**
	 * Constructor
	 * 
	 * @param message the exception message
	 * @param value the requested value or representation
	 * @param dt the data type
	 */
	public DataTypeEncodeException(String message, Object value, DataType dt) {
		this(message, value, dt, null);
	}

	/**
	 * Constructor
	 * 
	 * @param message the exception message
	 * @param value the requested value or representation
	 * @param dt the data type
	 * @param cause the exception cause
	 */
	public DataTypeEncodeException(String message, Object value, DataType dt, Throwable cause) {
		super("Cannot encode '" + value + "' for " + dt.getDisplayName() +
			(message == null ? "" : ": " + message), cause);
		this.value = value;
		this.dt = dt;
	}

	/**
	 * Constructor
	 * 
	 * @param value the requested value or representation
	 * @param dt the data type
	 * @param cause the exception cause
	 */
	public DataTypeEncodeException(Object value, DataType dt, Throwable cause) {
		this(null, value, dt, cause);
	}

	/**
	 * Get the requested value or representation
	 * 
	 * @return the requested value representation
	 */
	public Object getValue() {
		return value;
	}

	/**
	 * Get the data type
	 * 
	 * @return the data type
	 */
	public DataType getDataType() {
		return dt;
	}
}
