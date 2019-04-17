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
package ghidra.app.script;

/**
 * Exception class to be used when API calls are improperly used (i.e., GhidraScript.askProjectFolder() method is
 * being used in Headless mode).
 */
public class ImproperUseException extends RuntimeException {

	/**
	 * Constructs a new improper use exception with the specified detail message.
	 * @param msg the detail message
	 */
	public ImproperUseException(String msg) {
		super(msg);
	}

	/**
	 * Constructs a new exception with the specified cause
	 * @param cause the cause of the exception
	 */
	public ImproperUseException(Throwable cause) {
		super(cause);
	}

}
