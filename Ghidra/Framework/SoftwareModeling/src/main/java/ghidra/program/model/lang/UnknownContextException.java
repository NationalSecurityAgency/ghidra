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
package ghidra.program.model.lang;

import ghidra.util.exception.UsrException;

/**
 * <p>An UnknownContextException indicates a processor state context must be known
 * before the bytes at the parse address can form a legal known instruction.</p>
 *
 * @version 2000-02-15
 */
public class UnknownContextException extends UsrException {
	/**
	 * Constructs an UnknownContextException with a default message.
	 */
	public UnknownContextException() {
		super("The current processor state is not known for constructing a legal instruction.");
	}

	/**
	 * Constructs an UnknownContextException with the specified detail message.
	 *
	 * @param message The message.
	 */
	public UnknownContextException(String message) {
		super(message);
	}
}
