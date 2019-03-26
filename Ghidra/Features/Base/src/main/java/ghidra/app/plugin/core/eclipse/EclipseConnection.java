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
package ghidra.app.plugin.core.eclipse;

import java.net.Socket;

/**
 * A class that represents a connection to Eclipse.
 */
public class EclipseConnection {

	private Process process;
	private Socket socket;

	/**
	 * Creates a new Eclipse connection object that represents no connection.
	 */
	public EclipseConnection() {
		this.process = null;
		this.socket = null;
	}

	/**
	 * Creates a new Eclipse connection object.
	 * 
	 * @param process The Eclipse process that we launched (could be null).
	 * @param socket The socket connected to Eclipse (could be null).
	 */
	public EclipseConnection(Process process, Socket socket) {
		this.process = process;
		this.socket = socket;
	}

	/**
	 * Gets the Eclipse process that we launched.
	 * 
	 * @return The Eclipse process that we launched.  Could be null if we didn't need to 
	 *   launch an Eclipse to establish a connection, or if we failed to launch Eclipse.
	 */
	public Process getProcess() {
		return process;
	}

	/**
	 * Gets the socket connection to Eclipse.
	 * 
	 * @return The socket connection to Eclipse.  Could be null if a connection was 
	 *   never established.
	 */
	public Socket getSocket() {
		return socket;
	}
}
