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

import javax.security.auth.login.LoginException;

import ghidra.framework.client.*;
import ghidra.framework.protocol.ghidra.GhidraURLConnection.StatusCode;
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
		if (statusCode == null) {
			throw new NotConnectedException("not connected");
		}
		return readOnly;
	}

	@Override
	public StatusCode connect(boolean readOnlyAccess) throws IOException {

		if (statusCode != null) {
			throw new IllegalStateException("already connected");
		}

		this.readOnly = readOnlyAccess;

		statusCode = StatusCode.UNAVAILABLE; // if uncaught exception occurs

		repositoryServerAdapter =
			ClientUtil.getRepositoryServer(url.getHost(), url.getPort(), true);

		if (repositoryName == null) {
			statusCode = StatusCode.OK;
			return statusCode;
		}

		repositoryAdapter = repositoryServerAdapter.getRepository(repositoryName);
		if (repositoryServerAdapter.isConnected()) {
			try {
				repositoryAdapter.connect();
			}
			catch (RepositoryNotFoundException e) {
				statusCode = StatusCode.NOT_FOUND;
			}
		}
		else if (!repositoryServerAdapter.isCancelled()) {
			Throwable t = repositoryServerAdapter.getLastConnectError();
			if (t instanceof LoginException) {
				statusCode = StatusCode.UNAUTHORIZED;
			}
			//throw new NotConnectedException("Not connected to repository server", t);
			return statusCode;
		}

		if (repositoryAdapter.isConnected()) {
			statusCode = StatusCode.OK;
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
			statusCode = StatusCode.UNAUTHORIZED;
		}

		return statusCode;
	}

	@Override
	protected URL getRepositoryRootGhidraURL() {
		if (repositoryName != null) {
			return GhidraURL.makeURL(url.getHost(), url.getPort(), repositoryName);
		}
		return null; // not applicable for server-only URL
	}

}
