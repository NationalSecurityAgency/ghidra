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
package ghidra.util.exception;

/**
 * <code>CancelledException</code> indicates that the user cancelled
 * the current operation.
 */
public class CancelledException extends UsrException {

	public static final String DEFAULT_MESSAGE = "Operation cancelled";

	/**
	 * Default constructor.  Message indicates 'Operation cancelled'.
	 */
	public CancelledException() {
		super(DEFAULT_MESSAGE);
	}

	public CancelledException(String msg) {
		super(msg);
	}

	/**
	 * {@return true if the message of this exception is {@value #DEFAULT_MESSAGE}}
	 */
	public boolean isDefaultMessage() {
		return DEFAULT_MESSAGE.equals(getMessage());
	}

}
