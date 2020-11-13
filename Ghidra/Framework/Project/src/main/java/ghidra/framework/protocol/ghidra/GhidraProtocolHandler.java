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

import ghidra.util.classfinder.ExtensionPoint;

/**
 * <code>GhidraProtocolHandler</code> provides the extension point for 
 * Ghidra protocol extensions.  A Ghidra protocol extension will be identified 
 * within by the optional <i>extProtocolName</i> appearing within a Ghidra URL:
 * {@literal ghidra:[<extProtocolName>:]/...} In the absence of a protocol extension
 * the {@link DefaultGhidraProtocolHandler} will be used.
 */
public abstract class GhidraProtocolHandler implements ExtensionPoint {

	/**
	 * Determine if this protocol handler is responsible for handling the
	 * specified named protocol extension.  One handler may support multiple
	 * protocol extension names (e.g., http and https).
	 * @param extProtocolName protocol extension name
	 * @return true if this handler supports the specified protocol extension name
	 */
	public abstract boolean isExtensionSupported(String extProtocolName);

	/**
	 * Get the Ghidra protocol connector for a Ghidra URL which requires this
	 * extension.
	 * @param ghidraUrl Ghidra protocol URL
	 * @return Ghidra protocol connector
	 * @throws MalformedURLException if URL is invalid
	 */
	public abstract GhidraProtocolConnector getConnector(URL ghidraUrl)
			throws MalformedURLException;

}
