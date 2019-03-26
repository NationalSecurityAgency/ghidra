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
package ghidra.framework.remote;

public class RMIServerPortFactory {

	private static final int REGISTERY_PORT = 0;
	private static final int RMI_SSL_PORT = 1;
	private static final int STREAM_PORT = 2;

	private int basePort;

	/**
	 * Construct port factory using specified basePort
	 */
	public RMIServerPortFactory(int basePort) {
		this.basePort = basePort;
	}

	/**
	 * Returns RMI Registry port
	 */
	public int getRMIRegistryPort() {
		return basePort + REGISTERY_PORT;
	}

	/**
	 * Returns the SSL-protected RMI port.
	 */
	public int getRMISSLPort() {
		return basePort + RMI_SSL_PORT;
	}

	/**
	 * Returns the SSL Stream port
	 */
	public int getStreamPort() {
		return basePort + STREAM_PORT;
	}
}
