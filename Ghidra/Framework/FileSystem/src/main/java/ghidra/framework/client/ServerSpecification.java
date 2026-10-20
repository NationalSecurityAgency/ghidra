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
package ghidra.framework.client;

import java.net.URL;
import java.util.Objects;

/**
 * {@link ServerSpecification} URL-based server specification record
 * 
 * @param protocol URL protocol (e.g., {@code https}, {@code ghidra}).
 * @param hostname host name or IP address
 * @param port connection port (positive value)
 */
public record ServerSpecification(String protocol, String hostname, int port)
		implements Comparable<ServerSpecification> {

	public static ServerSpecification get(URL url) {
		return new ServerSpecification(url.getProtocol(), url.getHost(), getPort(url));
	}

	static int getPort(URL url) {
		int port = url.getPort();
		if (port < 0) {
			port = url.getDefaultPort();
		}
		return port;
	}

	public ServerSpecification {
		Objects.requireNonNull(protocol, "Protocol may not be null");
		Objects.requireNonNull(hostname, "Hostname may not be null");
	}

	@Override
	public int compareTo(ServerSpecification o) {
		int c = hostname.compareTo(o.hostname);
		if (c != 0) {
			return c;
		}
		c = Integer.compare(port, o.port);
		if (c != 0) {
			return c;
		}
		// NOTE: there should only be one protocol per server port
		return protocol.compareTo(o.protocol);
	}

	/**
	 * {@return server info in URL form}
	 */
	public String toUrlString() {
		return protocol + "://" + hostname + ":" + port;
	}

}

