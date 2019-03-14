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
package ghidra.program.model.lang;

import ghidra.util.exception.UsrException;

/**
 * <p>An UnknownInstructionException indicates that the bytes at the parse
 * address did not form a legal known instruction.</p>
 *
 * @version 2000-02-15
 */
public class UnknownInstructionException extends UsrException {
	/**
	 * <p>Constructs an InsufficientBytesException with a default message.<p>
	 */
	public UnknownInstructionException() {
		super("Bytes do not form a legal instruction.");
	}

	/**
	 * <p>Constructs an InsufficientBytesException with the specified
	 * detail message.<p>
	 *
	 * @param message The message.
	 */
	public UnknownInstructionException(String message) {
		super(message);
	}
}
