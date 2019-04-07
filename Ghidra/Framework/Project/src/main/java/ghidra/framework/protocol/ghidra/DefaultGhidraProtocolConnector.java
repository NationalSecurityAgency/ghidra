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

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;

import ghidra.framework.client.ClientUtil;
import ghidra.framework.client.NotConnectedException;
import ghidra.util.Msg;

/**
 * <code>DefaultGhidraProtocolConnector</code> provides support for the
 * Ghidra URL protocol without extension for accessing the legacy Ghidra Server 
 * over an RMI interface.
 */
public class DefaultGhidraProtocolConnector extends GhidraProtocolConnector {

	private boolean readOnly;

	/**
	 * Construct a protocol connector for use with a legacy Ghidra Server 
	 * repository (RMI-based server)
	 * @param ghidraURL Ghidra Server repository URL (ghidra://server/repo/...)
	 * @throws MalformedURLException if URL is invalid
	 */
	DefaultGhidraProtocolConnector(URL ghidraURL) throws MalformedURLException {
		super(ghidraURL);
	}

	@Override
	public boolean isReadOnly() throws NotConnectedException {
		if (responseCode == -1) {
			throw new NotConnectedException("not connected");
		}
		return readOnly;
	}

	@Override
	public int connect(boolean readOnlyAccess) throws IOException {

		if (responseCode != -1) {
			throw new IllegalStateException("already connected");
		}

		this.readOnly = readOnlyAccess;

		responseCode = GhidraURLConnection.GHIDRA_NOT_FOUND; // just in case

		repositoryServerAdapter =
			ClientUtil.getRepositoryServer(url.getHost(), url.getPort(), true);

		if (repositoryName == null) {
			responseCode = GhidraURLConnection.GHIDRA_OK;
			return responseCode;
		}

		repositoryAdapter = repositoryServerAdapter.getRepository(repositoryName);
		repositoryAdapter.connect();

		if (repositoryAdapter.isConnected()) {
			responseCode = GhidraURLConnection.GHIDRA_OK;
			if (!repositoryAdapter.getUser().hasWritePermission()) {
				if (!readOnly) {
					this.readOnly = true; // write access not permitted
					Msg.warn(this,
						"User does not have write permission for repository: " + repositoryName);
				}
			}
			resolveItemPath();
		}
		else {
			responseCode = GhidraURLConnection.GHIDRA_UNAUTHORIZED;
		}

		return responseCode;
	}

	@Override
	protected URL getRepositoryRootGhidraURL() {
		if (repositoryName != null) {
			return GhidraURL.makeURL(url.getHost(), url.getPort(), repositoryName);
		}
		return null; // not applicable for server-only URL
	}

}
