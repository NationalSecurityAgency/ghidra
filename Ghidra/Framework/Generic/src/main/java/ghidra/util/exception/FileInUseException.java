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
package ghidra.util.exception;

import java.io.IOException;

/**
 * <code>FileInUseException</code> indicates that there was contention
 * for a file which is in-use.  This can be caused for various reasons
 * including a file lock of some kind.
 */
public class FileInUseException extends IOException {

	/**
	 * Create a new FileInUseException with the given message.
	 *
	 * @param msg the exception message.
	 */
	public FileInUseException(String msg) {
		super(msg);
	}

	/**
	* Create a new FileInUseException with the given message and cause.
	*
	* @param msg the exception message.
	*/
	public FileInUseException(String msg, Throwable cause) {
		super(msg, cause);
	}

}
