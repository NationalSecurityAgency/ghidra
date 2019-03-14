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

import ghidra.framework.client.NotConnectedException;
import ghidra.framework.client.RepositoryAdapter;
import ghidra.framework.model.ProjectLocator;
import ghidra.framework.store.FileSystem;

/**
 * <code>DefaultLocalGhidraProtocolConnector</code> provides support for the
 * Ghidra URL protocol which specifies a local Ghidra project without extension.
 * This connector is responsible for producing a suitable {@link ProjectLocator}
 * for accessing the project files.
 */
public class DefaultLocalGhidraProtocolConnector extends GhidraProtocolConnector {

	private ProjectLocator localStorageLocator;

	private boolean readOnly;

	/**
	 * Construct a protocol connector for use with a local file-based 
	 * Ghidra project
	 * @param ghidraURL Ghidra local file-based project URL (ghidra:/path/projectName)
	 * @throws MalformedURLException if URL is invalid
	 */
	DefaultLocalGhidraProtocolConnector(URL ghidraURL) throws MalformedURLException {
		super(ghidraURL);
		try {
			localStorageLocator = GhidraURL.getProjectStorageLocator(ghidraURL);
		}
		catch (IllegalArgumentException e) {
			throw new MalformedURLException(e.getMessage());
		}
	}

	@Override
	protected void checkHostInfo() throws MalformedURLException {
		String host = url.getHost();
		if (host.length() != 0) {
			throw new MalformedURLException("unsupported host specification");
		}
	}

	@Override
	protected String parseRepositoryName() throws MalformedURLException {
		return null;
	}

	@Override
	protected String parseItemPath() throws MalformedURLException {
		// root folder access only - TODO: add support for specifying local item/folder path
		folderPath = FileSystem.SEPARATOR;
		folderItemName = null;
		return folderPath;
	}

	@Override
	protected void connect(RepositoryAdapter repository) throws IOException {
		throw new UnsupportedOperationException("local project access only");
	}

	/**
	 * Get the ProjectLocator associated with a local project URL.
	 * @return project locator object or null if URL supplies a a RepositoryAdapter and/or 
	 * RepositoryServerAdapter.
	 */
	public ProjectLocator getLocalProjectLocator() {
		return localStorageLocator;
	}

	@Override
	protected URL getRepositoryRootGhidraURL() {
		return null; // not applicable
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
		this.readOnly = readOnlyAccess;
		if (!localStorageLocator.exists()) {
			responseCode = GhidraURLConnection.GHIDRA_NOT_FOUND;
		}
		else {
			responseCode = GhidraURLConnection.GHIDRA_OK;
		}
		return responseCode;
	}

}
