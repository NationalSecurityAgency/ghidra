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
package ghidra.app.script;

import ghidra.util.exception.UsrException;

/**
 * An exception for when a script provider cannot create a script instance
 */
public class GhidraScriptLoadException extends UsrException {
	/**
	 * Construct an exception with a custom message and cause
	 * 
	 * <p>
	 * Note that the error message displayed to the user does not automatically include details from
	 * the cause. The client must provide details from the cause in the message as needed.
	 * 
	 * @param message the error message including details and possible remedies
	 * @param cause the exception causing this one
	 */
	public GhidraScriptLoadException(String message, Throwable cause) {
		super(message, cause);
	}

	/**
	 * Construct an exception with a message
	 * 
	 * @param message the error message including details and possible remedies
	 */
	public GhidraScriptLoadException(String message) {
		super(message);
	}

	/**
	 * Construct an exception with a cause
	 * 
	 * <p>
	 * This will copy the cause's message into this exception's message.
	 * 
	 * @param cause the exception causing this one
	 */
	public GhidraScriptLoadException(Throwable cause) {
		super(cause.getMessage(), cause);
	}
}
