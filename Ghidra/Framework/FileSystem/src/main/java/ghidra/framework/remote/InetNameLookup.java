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

import java.net.InetAddress;
import java.net.UnknownHostException;

import ghidra.util.Msg;

public class InetNameLookup {

	private static final long MAX_TIME_MS = 10000;

	private static volatile boolean lookupEnabled = true;
	private static volatile boolean disableOnFailure = false;

	private InetNameLookup() {
		// static use only
	}

	public static void setDisableOnFailure(boolean state) {
		disableOnFailure = state;
	}

	public static void setLookupEnabled(boolean enable) {
		lookupEnabled = enable;
	}

	public static boolean isEnabled() {
		return lookupEnabled;
	}

	/**
	 * Gets the fully qualified domain name for this IP address or hostname.
	 * Best effort method, meaning we may not be able to return 
	 * the FQDN depending on the underlying system configuration.
	 * 
	 * @param host IP address or hostname
	 * 
	 * @return  the fully qualified domain name for this IP address, 
	 *    or if the operation is not allowed/fails
	 *    the original host name specified.
	 *    
	 * @throws UnknownHostException the forward lookup of the specified address 
	 * failed
	 */
	public static String getCanonicalHostName(String host) throws UnknownHostException {
		String bestGuess = host;
		if (lookupEnabled) {
			// host may have multiple IP addresses
			boolean found = false;
			long fastest = Long.MAX_VALUE;
			for (InetAddress addr : InetAddress.getAllByName(host)) {
				long startTime = System.currentTimeMillis();
				String name = addr.getCanonicalHostName();
				long elapsedTime = System.currentTimeMillis() - startTime;
				if (!name.equals(addr.getHostAddress())) {
					if (host.equalsIgnoreCase(name)) {
						return name; // name found matches original - use it
					}
					bestGuess = name; // name found - update best guess
					found = true;
				}
				else {
					// keep fastest reverse lookup time
					fastest = Math.min(fastest, elapsedTime);
				}
			}
			if (!found) {
				// if lookup failed to produce a name - log warning
				Msg.warn(InetNameLookup.class, "Failed to resolve IP Address: " + host +
					" (Reverse DNS may not be properly configured or you may have a network problem)");
				if (disableOnFailure && fastest > MAX_TIME_MS) {
					// if lookup failed and was slow - disable future lookups if disableOnFailure is true
					Msg.warn(InetNameLookup.class,
						"Reverse network name lookup has been disabled automatically due to lookup failure.");
					lookupEnabled = false;
				}
			}
		}
		return bestGuess;
	}

}
