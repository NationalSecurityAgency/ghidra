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
 * <p>An IncompatibleMaskException is thrown when operations
 * are attempting involving two masks of different lengths.</p>
 *
 */

public class IncompatibleMaskException extends UsrException {

	/**
	 *  construct a new IncompatibleMaskException with no message.
	 */
	public IncompatibleMaskException() {
		super();
	}

	/**
	 * constructs a new IncompatiblemaskException with a descriptive
	 * message.
	 *
	 * @param message the description of what went wrong.
	 */
	public IncompatibleMaskException(String message) {
		super(message);
	}
}
