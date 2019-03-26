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
package ghidra.framework.protocol.ghidra;

import java.net.MalformedURLException;
import java.net.URL;

/**
 * <code>DefaultGhidraProtocolHandler</code> provides the default protocol 
 * handler which corresponds to the original RMI-based Ghidra Server
 * and local file-based Ghidra projects.
 * {@literal ghidra://host/repo/... or ghidra:/path/projectName}
 */
public class DefaultGhidraProtocolHandler extends GhidraProtocolHandler {

	@Override
	public boolean isExtensionSupported(String extProtocolName) {
		return extProtocolName == null;
	}

	@Override
	public GhidraProtocolConnector getConnector(URL ghidraUrl) throws MalformedURLException {
		String protocol = ghidraUrl.getProtocol();
		if (protocol != null) {
			if (ghidraUrl.getAuthority() == null) {
				return new DefaultLocalGhidraProtocolConnector(ghidraUrl);
			}
			return new DefaultGhidraProtocolConnector(ghidraUrl);
		}
		throw new MalformedURLException(
			"Unsupported URL form for ghidra protocol: " + ghidraUrl.toExternalForm());
	}

}
