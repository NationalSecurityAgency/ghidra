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
package ghidra.framework.model;

import java.io.Serializable;

/**
 * Container for a host name and port number.
 * 
 */
public class ServerInfo implements Serializable {

	private final String host;
	private final int portNumber;
	
	/**
	 * Construct a new ServerInfo object
	 * @param host host name
	 * @param portNumber port number
	 */
	public ServerInfo(String host, int portNumber) {
		this.host = host;
		this.portNumber = portNumber;
	}
	
	/**
	 * Get the server name.
	 */
	public String getServerName() {
		return host;
	}

	/**
	 * Get the port number.
	 */	
	public int getPortNumber() {
		return portNumber;
	}
	
	
	/*
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	@Override
    public boolean equals(Object obj) {
		if (!(obj instanceof ServerInfo)) {
			return false;
		}
		ServerInfo other = (ServerInfo) obj;
		return host.equals(other.host) && (portNumber == other.portNumber);
	}

	/*
	 * @see java.lang.Object#toString()
	 */
	@Override
    public String toString() {
		return host + ":" + portNumber;
	}

	/*
	 * @see java.lang.Object#hashCode()
	 */
	@Override
    public int hashCode() {
		return host.hashCode() + portNumber;
	}

}
