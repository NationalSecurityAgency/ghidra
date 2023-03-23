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
package ghidra.app.util.bin.format;

import java.util.Objects;

/**
 * <code>RelocationException</code> thrown when a supported relocation encounters an
 * unexpected error during processing.
 */
public class RelocationException extends Exception {

	/**
	 * Constructs a new exception with the specified detail message.
	 *
	 * @param message the detail message (required).
	 */
	public RelocationException(String message) {
		super(message);
		Objects.requireNonNull(message);
	}

	/**
	* Constructs a new exception with the specified detail message and
	* cause.  <p>Note that the detail message associated with
	* {@code cause} is <i>not</i> automatically incorporated in
	* this exception's detail message.
	*
	* @param message the detail message (required).
	* @param cause the cause (which is saved for later retrieval by the
	*         {@link #getCause()} method).  (A {@code null} value is
	*         permitted, and indicates that the cause is nonexistent or
	*         unknown.)
	*/
	RelocationException(String message, Exception cause) {
		super(message, cause);
		Objects.requireNonNull(message);
	}
}
