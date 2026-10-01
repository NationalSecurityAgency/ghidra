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
package ghidra.net;

import java.net.InetAddress;
import java.net.UnknownHostException;

import org.bouncycastle.util.IPAddress;

/**
 * {@link NetworkUtils} provides collection of network utilities
 */
public class NetworkUtils {

	/**
	 * {@return true if specified ipAddress corresponds to a loopback hostname of address}
	 * NOTE: The presence of any trailing CIDR netmask on an IPv4 or IPv6 address is ignored.
	 * @param ipAddress IP address or hostname (e.g., "127.0.0.1", "localhost")
	 */
	public static boolean isLoopbackAddress(String ipAddress) {
		if (ipAddress == null || ipAddress.trim().isEmpty()) {
			return false;
		}

		// Fast-path check for literal "localhost" to avoid resolution overhead
		if ("localhost".equalsIgnoreCase(ipAddress)) {
			return true;
		}

		// Strip CIDR suffix if present (e.g., "127.0.0.1/32" -> "127.0.0.1")
		int slashIndex = ipAddress.indexOf('/');
		if (slashIndex != -1) {
			if (!IPAddress.isValidWithNetMask(ipAddress)) {
				return false;
			}
			ipAddress = ipAddress.substring(0, slashIndex);
		}

		try {
			InetAddress address = InetAddress.getByName(ipAddress);

			return address.isLoopbackAddress();
		}
		catch (UnknownHostException | SecurityException e) {
			return false;
		}
	}

}
