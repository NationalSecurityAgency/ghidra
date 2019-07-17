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

import org.apache.commons.lang3.StringUtils;

import ghidra.framework.client.*;
import ghidra.framework.store.FileSystem;

/**
 * <code>GhidraProtocolConnector</code> provides an abtract implementation to access Ghidra 
 * repositories using various underlying communication protocols.  The common requirement 
 * for all implementations is the ability to derive a repository URL from any folder or file
 * URL. 
 */
public abstract class GhidraProtocolConnector {

	protected final URL url;

	protected final String repositoryName;
	protected final String itemPath; // trailing "/" signifies explicit folder path 

	protected String folderPath;
	protected String folderItemName = null;

	protected int responseCode = -1;

	protected RepositoryAdapter repositoryAdapter;
	protected RepositoryServerAdapter repositoryServerAdapter;

	/**
	 * Abstract <code>GhidraProtocolConnector</code> constructor.
	 * @param url a repository resource URL appropriate for the specific protocol implementation
	 * @throws MalformedURLException if URL is invalid
	 */
	protected GhidraProtocolConnector(URL url) throws MalformedURLException {
		this.url = url;
		checkProtocol();
		checkUserInfo();
		checkHostInfo();
		this.repositoryName = parseRepositoryName();
		this.itemPath = parseItemPath();
	}

	/**
	 * Get the URL associated with the repository/project root folder.
	 * This will be used as a key to its corresponding transient project data.
	 * @return root folder URL
	 */
	protected abstract URL getRepositoryRootGhidraURL();

	/**
	 * Perform URL verification checks to ensure that it satisfies this 
	 * connector implementation requirements
	 * @throws MalformedURLException if URL is invalid
	 */
	protected void checkProtocol() throws MalformedURLException {
		if (!GhidraURL.PROTOCOL.equals(url.getProtocol())) {
			throw new MalformedURLException("expected ghidra URL protocol");
		}
	}

	/**
	 * If connector supports user information within URL it will be verified 
	 * @throws MalformedURLException if URL contains user information 
	 * and it is either invalid or unsupported
	 */
	protected void checkUserInfo() throws MalformedURLException {
		if (url.getUserInfo() != null) {
			throw new MalformedURLException("URL does not support user info");
		}
	}

	/**
	 * Presence of a host specification within URL will be verified 
	 * @throws MalformedURLException if URL is missing proper host specification
	 */
	protected void checkHostInfo() throws MalformedURLException {
		String host = url.getHost();
		if (host.length() == 0) {
			throw new MalformedURLException("missing server host specification");
		}
	}

	/**
	 * Parse repository name from URL
	 * @return repository name or null if not specified
	 * @throws MalformedURLException if URL is invalid
	 */
	protected String parseRepositoryName() throws MalformedURLException {

		String path = url.getPath();

		// Divide path into pieces
		if (path == null || path.length() < 2 || path.charAt(0) != '/') {
			return null; // content corresponds to RepositoryServerAdapter
		}

		// Isolate repository name
		path = path.substring(1);

		int index = path.indexOf(FileSystem.SEPARATOR);
		if (index >= 0) {
			path = path.substring(0, index);
		}

		if (path.length() == 0) {
			throw new MalformedURLException("invalid path specification");
		}

		return path;
	}

	/**
	 * Parse item path name from URL and establish initial values for folderPath and
	 * folderItemName.
	 * @return original item path from URL or null if not specified
	 * @throws MalformedURLException if URL is invalid
	 */
	protected String parseItemPath() throws MalformedURLException {

		String path = url.getPath();

		if (repositoryName == null) {
			return null; // presumed server-only URL
		}

		// strip off repository name from path
		path = path.substring(repositoryName.length() + 1);
		if (path.length() <= 1) {
			// root path specified
			folderPath = FileSystem.SEPARATOR;
			return folderPath; // repository URL, root folder
		}

		// Handles server repository URL case  ghidra://<host>:<port>/<repository-name>[/<folder-path>]/[<folderItemName>]

		boolean isFolder = path.endsWith(FileSystem.SEPARATOR);
		folderPath = "";
		String pathToSplit = isFolder ? path.substring(0, path.length() - 1) : path;
		String[] pieces =
			StringUtils.splitByWholeSeparatorPreserveAllTokens(pathToSplit, FileSystem.SEPARATOR);
		if (pieces.length == 0) {
			throw new MalformedURLException("invalid repository path specification");
		}
		for (int i = 1; i < pieces.length; i++) {
			String p = pieces[i];
			if (p.length() == 0) {
				throw new MalformedURLException("invalid repository path specification");
			}
			if (!isFolder && i == (pieces.length - 1)) {
				folderItemName = p;
			}
			else {
				folderPath = folderPath + FileSystem.SEPARATOR + p;
			}
		}
		if (folderPath.length() == 0) {
			folderPath = FileSystem.SEPARATOR;
		}

		return path;
	}

	/**
	 * Gets the status code from a Ghidra URL connect response.
	 * @return the Ghidra Status-Code, or -1 if not yet connected
	 * @see #connect(boolean)
	 */
	public int getResponseCode() {
		return responseCode;
	}

	/**
	 * Gets the repository name associated with the URL.
	 * @return the repository name or null if URL does not identify a specific repository
	 */
	public String getRepositoryName() {
		return repositoryName;
	}

	/**
	 * Get the RepositoryAdapter associated with a URL which specifies a repository.
	 * @return repository adapter or null if a project locator is supplied instead
	 */
	public RepositoryAdapter getRepositoryAdapter() {
		return repositoryAdapter;
	}

	/**
	 * Get the RepositoryServerAdapter associated with a URL which specifies a repository or
	 * repository server.
	 * @return repository server adapter or null if a project locator is supplied instead
	 */
	public RepositoryServerAdapter getRepositoryServerAdapter() {
		return repositoryServerAdapter;
	}

	/**
	 * Gets the repository folder path associated with the URL.
	 * If an ambiguous path has been specified, the folder path may change
	 * after a connection is established (e.g., folder item name will be appended 
	 * to folder path and item name will become null if item turns out to
	 * be a folder).
	 * @return repository folder path or null
	 */
	public String getFolderPath() {
		return folderPath;
	}

	/**
	 * Gets the repository folder item name associated with the URL.
	 * If an ambiguous path has been specified, the folder item name may become null
	 * after a connection is established (e.g., folder item name will be appended 
	 * to folder path and item name will become null if item turns out to
	 * be a folder).
	 * @return folder item name or null
	 */
	public String getFolderItemName() {
		return folderItemName;
	}

	private String appendSubfolderName(String folder, String subfolderName) {
		if (!folder.endsWith(FileSystem.SEPARATOR)) {
			folder = folder + FileSystem.SEPARATOR;
		}
		return folder + folderItemName;
	}

	/**
	 * Fully resolve folder/item reference once connected to the associated
	 * repository due to possible ambiguity  
	 * @throws IOException
	 */
	protected void resolveItemPath() throws IOException {

		// NOTE: Assume path may correspond to non-existent folder if not found
		// - this is why GHIDRA_NOT_FOUND response code setting has been disabled

		if (folderItemName != null) {
			if (itemPath.endsWith("/")) {
				// explicit folder path - force folder URL
				folderPath = appendSubfolderName(folderPath, folderItemName);
				folderItemName = null;

//				if (readOnly && !repository.folderExists(itemPath)) {
//					// TODO: URL location not found
//					responseCode = GHIDRA_NOT_FOUND;
//					return;
//				}
			}
			else if (!repositoryAdapter.fileExists(folderPath, folderItemName)) {

				// file item not found - check for existing sub-folder instead
				String path = appendSubfolderName(folderPath, folderItemName);
				if (repositoryAdapter.folderExists(path)) {
					// item name found as folder - force folder URL
					folderPath = path;
					folderItemName = null;
				}

//				if (folderItemName != null) {
//					// TODO: URL location not found
//					responseCode = GHIDRA_NOT_FOUND;
//					return;
//				}
			}
		}
	}

	/**
	 * Utilized a cached connection via the specified repository adapter.
	 * This method may only be invoked if not yet connected and the associated
	 * URL corresponds to a repository (getRepositoryName() != null).  The connection 
	 * response code should be established based upon the availability of the 
	 * URL referenced repository resource (i.e., folder or file).
	 * @param repository existing connected repository adapter
	 * @throws IOException 
	 */
	protected void connect(RepositoryAdapter repository) throws IOException {
		if (responseCode != -1) {
			throw new IllegalStateException("already connected");
		}
		if (repositoryName == null || !repositoryName.equals(repository.getName())) {
			throw new UnsupportedOperationException("invalid repository connection");
		}
		if (!repository.isConnected()) {
			throw new IllegalStateException("expected connected repository");
		}
		responseCode = GhidraURLConnection.GHIDRA_OK;
		this.repositoryAdapter = repository;
		this.repositoryServerAdapter = repository.getServer();
		resolveItemPath();
	}

	/**
	 * Connect to the resource specified by the associated URL.  This method should only be invoked
	 * once, a second attempt may result in an IOException.
	 * @param readOnly if resource should be requested for write access.
	 * @return connection response code @see {@link GhidraURLConnection}
	 * @throws IOException if a connection error occurs
	 */
	public abstract int connect(boolean readOnly) throws IOException;

	/**
	 * Determines the read-only nature of a connected resource
	 * @return true if read-only, false if write access allowed
	 * @throws NotConnectedException if connect has not yet been performed
	 */
	public abstract boolean isReadOnly() throws NotConnectedException;
}
