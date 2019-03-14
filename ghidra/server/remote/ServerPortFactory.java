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
package ghidra.server.remote;

import ghidra.framework.remote.GhidraServerHandle;
import ghidra.framework.remote.RMIServerPortFactory;

public class ServerPortFactory {

	private static RMIServerPortFactory portFactory =
		new RMIServerPortFactory(GhidraServerHandle.DEFAULT_PORT);

	/**
	 * Construction not permitted
	 */
	private ServerPortFactory() {
	}

	/**
	 * Set the base port to be used by server.
	 * @param port base port
	 */
	static void setBasePort(int port) {
		portFactory = new RMIServerPortFactory(port);
	}

	/**
	 * Returns RMI Registry port
	 */
	public static int getRMIRegistryPort() {
		return portFactory.getRMIRegistryPort();
	}

	/**
	 * Returns the SSL-protected RMI port.
	 */
	public static int getRMISSLPort() {
		return portFactory.getRMISSLPort();
	}
	
	/**
	 * Returns the SSL Stream port
	 */
	public static int getStreamPort() {
		return portFactory.getStreamPort();
	}

}
