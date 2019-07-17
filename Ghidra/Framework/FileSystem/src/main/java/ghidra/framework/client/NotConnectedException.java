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
package ghidra.framework.client;

import java.io.IOException;

/**
 * <code>NotConnectedException</code> indicates that the server connection
 * is down.  When this exception is thrown, the current operation should be
 * aborted.  At the time this exception is thrown, the user has already been
 * informed of a server error condition.
 */
public class NotConnectedException extends IOException {

	/**
	 * Constructor.
	 * @param msg error message
	 */
	public NotConnectedException(String msg) {
		super(msg);
	}

	public NotConnectedException(String msg, Throwable cause) {
		super(msg, cause);
	}
}
