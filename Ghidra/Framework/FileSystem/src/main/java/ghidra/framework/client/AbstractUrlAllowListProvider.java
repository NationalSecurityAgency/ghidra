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

import java.net.URISyntaxException;
import java.net.URL;

import org.apache.commons.lang3.StringUtils;

/**
 * {@link AbstractUrlAllowListProvider} provides the abstract URL allow list provider.
 * <p>
 * NOTE: See {@link UrlAllowListManager} for persistent allow list which will be consulted before
 * prompting user and updated if user allows access.
 */
public abstract class AbstractUrlAllowListProvider implements UrlAllowListProvider {

	/**
	 * Determine if access has previously been determined and return access state.
	 * This method will return true for opaque or non-server URLs.
	 * 
	 * @param url server URL
	 * @return true if access allowed or URL type is not handled by allow list, false
	 * if access is disallowed, or null if no allow list entry exists.
	 */
	protected static Boolean accessAllowed(URL url) {
		try {
			if (url.toURI().isOpaque() || StringUtils.isEmpty(url.getAuthority())) {
				return true;
			}
		}
		catch (URISyntaxException e) {
			throw new IllegalArgumentException("Unsupported URL: " + url, e);
		}

		return UrlAllowListManager.getAccess(url.getProtocol(), url.getHost(), getPort(url));
	}

	/**
	 * Get the port to be accessed by the specified URL.  If not specified, the default port will
	 * be returned.
	 * 
	 * @param url server URL
	 * @return URL port
	 */
	protected static int getPort(URL url) {
		int port = url.getPort();
		if (port < 0) {
			port = url.getDefaultPort();
		}
		return port;
	}


	/**
	 * Get the base URL form which only includes protocol, server and port.
	 * 
	 * @param url server URL
	 * @return simplified base URL (e.g., ghidra://host/repo )
	 * @throws IllegalArgumentException if URL does not specify an authority
	 */
	protected static String getBaseURL(URL url) throws IllegalArgumentException {

		if (url.getAuthority() == null) {
			throw new IllegalArgumentException("Invalid remote server URL: " + url);
		}

		int port = url.getPort();
		if (port < 0) {
			port = url.getDefaultPort();
		}

		return url.getProtocol() + "://" + url.getHost() + ":" + port;
	}

}
