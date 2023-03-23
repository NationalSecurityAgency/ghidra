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

import java.io.*;
import java.net.*;

import ghidra.framework.client.*;
import ghidra.framework.data.ProjectFileManager;
import ghidra.framework.model.ProjectData;
import ghidra.util.exception.AssertException;

public class GhidraURLConnection extends URLConnection {

	/**
	 * Connection status codes
	 */
	public enum StatusCode {
		OK(20, "OK"),
		/**
		 * Ghidra Status-Code 401: Unauthorized.
		 * This status code occurs when repository access is denied.
		 */
		UNAUTHORIZED(401, "Unauthorized"),
		/**
		 * Ghidra Status-Code 404: Not Found.
		 * This status code occurs when repository or project does not exist.
		 */
		NOT_FOUND(404, "Not Found"),
		/**
		 * Ghidra Status-Code 423: Locked.
		 * This status code occurs when project is locked (i.e., in use).
		 */
		LOCKED(423, "Locked Project"),
		/**
		 * Ghidra Status-Code 503: Unavailable.
		 * This status code includes a variety of connection errors
		 * which are reported/logged by the Ghidra Server support code.
		 */
		UNAVAILABLE(503, "Unavailable");

		private int code;
		private String description;

		private StatusCode(int code, String description) {
			this.code = code;
			this.description = description;
		}

		public int getCode() {
			return code;
		}

		public String getDescription() {
			return description;
		}
	}

	// TODO: consider implementing request and response headers

//	/**
//	 * Ghidra Status-Code 200: OK.
//	 */
//	public static final int GHIDRA_OK = 200;
//
//	/**
//	 * Ghidra Status-Code 401: Unauthorized.
//	 * This response code includes a variety of connection errors
//	 * which are reported/logged by the Ghidra Server support code.
//	 */
//	public static final int GHIDRA_UNAUTHORIZED = 401;
//
//	/**
//	 * Ghidra Status-Code 404: Not Found.
//	 */
//	public static final int GHIDRA_NOT_FOUND = 404;
//
//	/**
//	 * Ghidra Status-Code 423: Locked
//	 * Caused by attempt to open local project data with write-access when project is
//	 * already opened and locked.
//	 */
//	public static final int GHIDRA_LOCKED = 423;
//
//	/**
//	 * Ghidra Status-Code 503: Unavailable
//	 * Caused by other connection failure
//	 */
//	public static final int GHIDRA_UNAVAILABLE = 503;

	/**
	 * Ghidra content type - domain folder/file wrapped within GhidraURLWrappedContent object.
	 * @see GhidraURLWrappedContent
	 */
	public static final String GHIDRA_WRAPPED_CONTENT = "GhidraWrappedContent";

	/**
	 * Ghidra content type - repository server in the form of a RepositoryAdapter
	 * @see RepositoryAdapter
	 */
	public static final String REPOSITORY_SERVER_CONTENT = "RepositoryServer";

	private StatusCode statusCode = null;

	private GhidraProtocolConnector protocolConnector;

	private ProjectFileManager projectData;
	private Object refObject;

	private boolean readOnly = true;

	/**
	 * Construct a Ghidra URL connection which uses the default handler without
	 * any extension protocol.
	 * @param ghidraUrl ghidra protocol URL (e.g., {@literal ghidra://server/repo})
	 * @throws MalformedURLException if URL is invalid
	 */
	public GhidraURLConnection(URL ghidraUrl) throws MalformedURLException {
		this(ghidraUrl, new DefaultGhidraProtocolHandler());
	}

	/**
	 * Construct a Ghidra URL connection which requires an Ghidra protocol extension
	 * @param url extension URL without the ghidra protocol prefix (e.g., {@literal http://server/repo})
	 * @param protocolHandler Ghidra protocol extension handler
	 * @throws MalformedURLException if URL is invalid
	 */
	public GhidraURLConnection(URL url, GhidraProtocolHandler protocolHandler)
			throws MalformedURLException {
		super(url);
		if (protocolHandler == null) {
			throw new IllegalArgumentException("missing required protocol handler");
		}

		protocolConnector = protocolHandler.getConnector(url);
	}

	/**
	 * Connection was opened as read-only
	 * @return true if read-only connection
	 */
	public boolean isReadOnly() {
		if (!connected) {
			return readOnly; // connect intention
		}
		try {
			return protocolConnector.isReadOnly();
		}
		catch (NotConnectedException e) {
			throw new AssertException(e); // unexpected
		}
	}

	/**
	 * Set the read-only state for this connection prior to connecting or getting content.  
	 * The default access is read-only.  Extreme care must be taken when setting the state to false 
	 * for local projects without the use of a ProjectLock.
	 * <P>
	 * <B>NOTE:</B> Local project URL connections only support read-only access.
	 * @param state read-only if true, otherwise read-write
	 * @throws UnsupportedOperationException if an attempt is made to enable write access for
	 * a local project URL.
	 * @throws IllegalStateException if already connected
	 */
	public void setReadOnly(boolean state) {
		if (connected)
			throw new IllegalStateException("Already connected");
		if (GhidraURL.isLocalProjectURL(url) && !state) {
			// local project write-access not supported due to inadequate cleanup/disposal strategy
			throw new UnsupportedOperationException("write access to local projects not supported");
		}
		readOnly = state;
	}

	/**
	 * Gets the repository name associated with this <code>GhidraURLConnection</code>.
	 * 
	 * @return the repository name or null if URL does not identify a specific repository
	 */
	public String getRepositoryName() {
		return protocolConnector.getRepositoryName();
	}

	/**
	 * Gets the repository folder path associated with this connection.
	 * If an ambiguous path has been specified, the folder path may change
	 * after a connection is established (e.g., folder item name will be appended 
	 * to folder path and item name will become null if item turns out to
	 * be a folder).
	 * 
	 * @return repository folder path or null
	 */
	public String getFolderPath() {
		return protocolConnector.getFolderPath();
	}

	/**
	 * Gets the repository folder item name associated with this connection.
	 * If an ambiguous path has been specified, the folder item name may become null
	 * after a connection is established (e.g., folder item name will be appended 
	 * to folder path and item name will become null if item turns out to
	 * be a folder).
	 * 
	 * @return folder item name or null
	 */
	public String getFolderItemName() {
		return protocolConnector.getFolderItemName();
	}

	/**
	 * Gets the status code from a Ghidra URL connect attempt.
	 * @throws IOException if an error occurred connecting to the server.
	 * @return the Ghidra connection status code or null
	 */
	public StatusCode getStatusCode() throws IOException {

		if (statusCode != null) {
			return statusCode;
		}

		getContent(); // Ensure that we have connected to the server.

		return statusCode;
	}

	@Override
	public String getContentType() {

		if (!connected || refObject == null) {
			return null; // not yet connected
		}

		if (refObject instanceof RepositoryServerAdapter) {
			return REPOSITORY_SERVER_CONTENT;
		}
		if (refObject instanceof GhidraURLWrappedContent) {
			return GHIDRA_WRAPPED_CONTENT;
		}
		return "Unknown";
	}

	/**
	 * Get content associated with the URL
	 * @return URL content generally in the form of GhidraURLWrappedContent, although other
	 * special cases may result in different content (Example: a server-only URL could result in
	 * content class of RepositoryServerAdapter).
	 * @throws IOException if an IO error occurs
	 */
	@Override
	public Object getContent() throws IOException {

		if (!connected) {
			connect();
		}

		return refObject;
	}

	/**
	 * If URL connects and corresponds to a valid repository, this method
	 * may be used to obtain the associated ProjectData object.  The caller is
	 * responsible for closing the returned project data when no longer in-use,
	 * failure to do so may prevent release of repository handle to server.
	 * Only a single call to this method is permitted.
	 * @return transient project data or null if unavailable
	 * @throws IOException if an IO error occurs
	 */
	public ProjectData getProjectData() throws IOException {

		if (!connected) {
			connect();
		}

		if (projectData instanceof TransientProjectData) {
			((TransientProjectData) projectData).incrementInstanceUseCount();
		}
		return projectData;
	}

	@Override
	public void connect() throws IOException {

		// TODO: Use protocol extension handler if specified

		if (connected) {
			return;
		}

		if (protocolConnector instanceof DefaultLocalGhidraProtocolConnector) {
			// local project connection
			DefaultLocalGhidraProtocolConnector localConnector =
				(DefaultLocalGhidraProtocolConnector) protocolConnector;
			projectData = localConnector.getLocalProjectData(readOnly);
			statusCode = localConnector.getStatusCode();
			connected = true;
			if (statusCode == StatusCode.OK) {
				refObject = new GhidraURLWrappedContent(this);
			}
			return;
		}

		String repoName = protocolConnector.getRepositoryName();
		if (repoName == null) {
			// assume only server adapter connection without repository name specified
			// any RepositoryServerAdapter caching is responsibility of connector
			statusCode = protocolConnector.connect(readOnly);
			connected = true;
			if (statusCode == StatusCode.OK) {
				refObject = protocolConnector.getRepositoryServerAdapter();
				if (refObject == null) {
					throw new AssertException("expected RepositoryServerAdapter content");
				}
			}
			return;
		}

		// Assume repository URL which will supply RepositoryAdapter content
		// If an existing transient project can be found it will be re-used and the 
		// connector notified via the connect(RepositoryAdapter), otherwise the 
		// connect(boolean readOnly) method will be invoked and a new transient project
		// will be established with a RepositoryAdapter supplied by the connector.

		// Obtain connected transient project for repository and complete connection
		TransientProjectManager transientProjectManager =
			TransientProjectManager.getTransientProjectManager();
		TransientProjectData transientProjectData =
			transientProjectManager.getTransientProject(protocolConnector, readOnly);

		connected = true;
		statusCode = protocolConnector.getStatusCode();

		if (statusCode != StatusCode.OK) {
			return;
		}

		projectData = transientProjectData;
		refObject = new GhidraURLWrappedContent(this);
	}

	@Override
	public InputStream getInputStream() throws IOException {
		throw new UnknownServiceException();
	}

	@Override
	public OutputStream getOutputStream() throws IOException {
		throw new UnknownServiceException();
	}

}
