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

import java.net.*;
import java.util.Objects;
import java.util.regex.Pattern;

import org.apache.commons.lang3.StringUtils;

import ghidra.framework.model.ProjectLocator;
import ghidra.framework.remote.GhidraServerHandle;

/**
 * Supported URL forms include:
 * <ul>
 * <li>{@literal ghidra://<host>:<port>/<repository-name>[/<folder-path>]/[<folderItemName>[#ref]]}</li>
 * <li>{@literal ghidra:/[X:/]<project-path>/<project-name>[?[/<folder-path>]/[<folderItemName>[#ref]]]}</li>
 * </ul>
 */
public class GhidraURL {

	public static final String PROTOCOL = "ghidra";

	private static final String PROTOCOL_URL_START = PROTOCOL + ":/";

	private static Pattern IS_LOCAL_URL_PATTERN =
		Pattern.compile("^" + PROTOCOL_URL_START + "[^/].*"); // e.g., ghidra:/path

	public static final String MARKER_FILE_EXTENSION = ".gpr";
	public static final String PROJECT_DIRECTORY_EXTENSION = ".rep";

	private GhidraURL() {
	}

	/**
	 * Determine if the specified URL refers to a local project and
	 * it exists.
	 * @param url ghidra URL
	 * @return true if specified URL refers to a local project and
	 * it exists.
	 */
	public static boolean localProjectExists(URL url) {
		ProjectLocator loc = getProjectStorageLocator(url);
		return loc != null && loc.exists();
	}

	/**
	 * Determine if the specified string appears to be a possible ghidra URL
	 * (starts with "ghidra:/"). 
	 * @param str string to be checked
	 * @return true if string is possible ghidra URL
	 */
	public static boolean isGhidraURL(String str) {
		return str != null && str.startsWith(PROTOCOL_URL_START);
	}

	/**
	 * Determine if the specified URL is a local project URL.
	 * No checking is performed as to the existence of the project.
	 * @param url ghidra URL
	 * @return true if specified URL refers to a local 
	 * project (ghidra:/path/projectName...)
	 */
	public static boolean isLocalProjectURL(URL url) {
		return IS_LOCAL_URL_PATTERN.matcher(url.toExternalForm()).matches();
	}

	/**
	 * Get the project locator which corresponds to the specified local project URL.
	 * Confirm local project URL with {@link #isLocalProjectURL(URL)} prior to method use.
	 * @param localProjectURL local Ghidra project URL
	 * @return project locator or null if invalid path specified
	 * @throws IllegalArgumentException URL is not a valid local project URL
	 */
	public static ProjectLocator getProjectStorageLocator(URL localProjectURL) {
		if (!isLocalProjectURL(localProjectURL)) {
			throw new IllegalArgumentException("Invalid local Ghidra project URL");
		}

		String path = localProjectURL.getPath(); // assume path always starts with '/'
		
//		if (path.indexOf(":/") == 2 && Character.isLetter(path.charAt(1))) { // check for drive letter after leading '/'
//			if (Platform.CURRENT_PLATFORM.getOperatingSystem() == OperatingSystem.WINDOWS) {
//				path = path.substring(1); // Strip-off leading '/'
//			}
//			else {
//				// assume drive letter separator ':' should be removed for non-windows
//				path = path.substring(0, 2) + path.substring(3);
//			}
//		}

		int index = path.lastIndexOf('/');
		String dirPath = index != 0 ? path.substring(0, index) : "/";
		
		String name = path.substring(index + 1);
		if (name.length() == 0) {
			return null;
		}

		return new ProjectLocator(dirPath, name);
	}

	/**
	 * Get the shared repository name associated with a repository URL or null
	 * if not applicable.  For ghidra URL extensions it is assumed that the first path element
	 * corresponds to the repository name.
	 * @param url ghidra URL for shared project resource
	 * @return repository name or null if not applicable to URL
	 */
	public static String getRepositoryName(URL url) {
		if (!isServerRepositoryURL(url)) {
			return null;
		}
		String path = url.getPath();
		if (!path.startsWith("/")) {
			// handle possible ghidra protocol extension use which is assumed to encode
			// repository and file path the same as standard ghidra URL.
			try {
				URL extensionURL = new URL(path);
				path = extensionURL.getPath();
			}
			catch (MalformedURLException e) {
				path = "";
			}
		}
		path = path.substring(1);
		int ix = path.indexOf("/");
		if (ix > 0) {
			path = path.substring(0, ix);
		}
		return path;
	}

	/**
	 * Determine if the specified URL is any type of server "repository" URL.
	 * No checking is performed as to the existence of the server or repository.
	 * NOTE: ghidra protocol extensions are not currently supported (e.g., ghidra:http://...).
	 * @param url ghidra URL
	 * @return true if specified URL refers to a Ghidra server 
	 * repository (ghidra://host/repositoryNAME/path...)
	 */
	public static boolean isServerRepositoryURL(URL url) {
		if (!isServerURL(url)) {
			return false;
		}
		String path = url.getPath();
		if (StringUtils.isBlank(path)) {
			return false;
		}
		if (!path.startsWith("/")) {
			try {
				URL extensionURL = new URL(path);
				path = extensionURL.getPath();
				if (StringUtils.isBlank(path)) {
					return false;
				}
			}
			catch (MalformedURLException e) {
				return false;
			}
		}
		return path.charAt(0) == '/' && path.length() > 1 && path.charAt(1) != '/';
	}

	/**
	 * Determine if the specified URL is any type of server URL.
	 * No checking is performed as to the existence of the server or repository.
	 * @param url ghidra URL
	 * @return true if specified URL refers to a Ghidra server 
	 * repository (ghidra://host/repositoryNAME/path...)
	 */
	public static boolean isServerURL(URL url) {
		if (!PROTOCOL.equals(url.getProtocol())) {
			return false;
		}
		return Handler.isSupportedURL(url);
	}

	/**
	 * Ensure that absolute path is specified.  Any use of Windows 
	 * separator (back-slash) will be converted to a forward-slash. 
	 * @param path path to be checked and possibly modified.
	 * @return path to be used
	 */
	private static String checkAbsolutePath(String path) {
		path = path.replace('\\', '/');
		if (!path.startsWith("/")) {
			if (path.length() >= 3 && path.indexOf(":/") == 1 &&
				Character.isLetter(path.charAt(0))) {
				// prepend a "/" on Windows paths (e.g., C:/mydir)
				path = "/" + path;
			}
			else { // absence of drive letter is tolerated even if not absolute on windows
				throw new IllegalArgumentException("Absolute directory path required");
			}
		}
		return path;
	}

	/**
	 * Create a Ghidra URL from a string form of Ghidra URL or local project path.
	 * This method can consume strings produced by the getDisplayString method.
	 * @param projectPathOrURL {@literal project path (<absolute-directory>/<project-name>)} or 
	 * string form of Ghidra URL.
	 * @return local Ghidra project URL
	 * @see #getDisplayString(URL)
	 * @throws IllegalArgumentException invalid path or URL specified
	 */
	public static URL toURL(String projectPathOrURL) {
		if (!projectPathOrURL.startsWith(PROTOCOL + ":")) {
			if (projectPathOrURL.endsWith(ProjectLocator.PROJECT_DIR_SUFFIX) ||
				projectPathOrURL.endsWith(ProjectLocator.PROJECT_FILE_SUFFIX)) {
				String ext = projectPathOrURL.substring(projectPathOrURL.lastIndexOf('.'));
				throw new IllegalArgumentException("Project path must omit extension: " + ext);
			}
			if (projectPathOrURL.contains("?") || projectPathOrURL.contains("#")) {
				throw new IllegalArgumentException("Unsupported query/ref used with project path");
			}
			projectPathOrURL = checkAbsolutePath(projectPathOrURL);
			String[] splitName = splitOffName(projectPathOrURL);
			return makeURL(splitName[0], splitName[1]);
		}
		try {
			return new URL(projectPathOrURL);
		}
		catch (MalformedURLException e) {
			throw new IllegalArgumentException(e);
		}
	}

	/**
	 * Get normalized URL which corresponds to the local-project or repository
	 * @param ghidraUrl ghidra file/folder URL (server-only URL not permitted)
	 * @return local-project or repository URL
	 */
	public static URL getProjectURL(URL ghidraUrl) {
		if (!PROTOCOL.equals(ghidraUrl.getProtocol())) {
			throw new IllegalArgumentException("ghidra protocol required");
		}

		if (isLocalProjectURL(ghidraUrl)) {
			String urlStr = ghidraUrl.toExternalForm();
			int queryIx = urlStr.indexOf('?');
			if (queryIx < 0) {
				return ghidraUrl;
			}
			urlStr = urlStr.substring(0, queryIx);
			try {
				return new URL(urlStr);
			}
			catch (MalformedURLException e) {
				throw new RuntimeException(e); // unexpected
			}
		}

		if (isServerRepositoryURL(ghidraUrl)) {

			String path = ghidraUrl.getPath();
			// handle possible ghidra protocol extension use which is assumed to encode
			// repository and file path the same as standard ghidra URL.
			if (!path.startsWith("/")) {
				try {
					URL extensionURL = new URL(path);
					path = extensionURL.getPath();
				}
				catch (MalformedURLException e) {
					path = "/";
				}
			}

			// Truncate ghidra URL
			String urlStr = ghidraUrl.toExternalForm();

			String tail = null;
			int ix = path.indexOf('/', 1);
			if (ix > 0) {
				// identify path tail to be removed
				tail = path.substring(ix);
			}

			int refIx = urlStr.indexOf('#');
			if (refIx > 0) {
				urlStr = urlStr.substring(0, refIx);
			}
			int queryIx = urlStr.indexOf('?');
			if (queryIx > 0) {
				urlStr = urlStr.substring(0, queryIx);
			}

			if (tail != null) {
				urlStr = urlStr.substring(0, urlStr.lastIndexOf(tail));
			}
			try {
				return new URL(urlStr);
			}
			catch (MalformedURLException e) {
				// ignore
			}
		}

		throw new IllegalArgumentException("Invalid project/repository URL: " + ghidraUrl);
	}

	/**
	 * Get the project pathname referenced by the specified Ghidra file/folder URL.
	 * If path is missing root folder is returned.
	 * @param ghidraUrl ghidra file/folder URL (server-only URL not permitted)
	 * @return pathname of file or folder
	 */
	public static String getProjectPathname(URL ghidraUrl) {

		if (isLocalProjectURL(ghidraUrl)) {
			String query = ghidraUrl.getQuery();
			return StringUtils.isBlank(query) ? "/" : query;
		}

		if (isServerRepositoryURL(ghidraUrl)) {
			String path = ghidraUrl.getPath();
			// handle possible ghidra protocol extension use
			if (!path.startsWith("/")) {
				try {
					URL extensionURL = new URL(path);
					path = extensionURL.getPath();
				}
				catch (MalformedURLException e) {
					path = "/";
				}
			}
			// skip repo name (first path element)
			int ix = path.indexOf('/', 1);
			if (ix > 1) {
				return path.substring(ix);
			}
			return "/";
		}

		throw new IllegalArgumentException("not project/repository URL");
	}

	/**
	 * Get hostname as an IP address if possible
	 * @param host hostname
	 * @return host IP address or original host name
	 */
	private static String getHostAsIpAddress(String host) {
		if (!StringUtils.isBlank(host)) {
			try {
				InetAddress addr = InetAddress.getByName(host);
				host = addr.getHostAddress();
			}
			catch (UnknownHostException e) {
				// just use hostname if unable to resolve
			}
		}
		return host;
	}

	/**
	 * Get a normalized URL which eliminates use of host names and optional URL ref
	 * which may prevent direct comparison.
	 * @param url ghidra URL
	 * @return normalized url
	 */
	public static URL getNormalizedURL(URL url) {
		String host = url.getHost();
		String revisedHost = getHostAsIpAddress(host);
		if (Objects.equals(host, revisedHost) && url.getRef() == null) {
			return url; // no change
		}
		String file = url.getPath();
		String query = url.getQuery();
		if (!StringUtils.isBlank(query)) {
			file += "?" + query;
		}
		try {
			return new URL(PROTOCOL, revisedHost, url.getPort(), file);
		}
		catch (MalformedURLException e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * Generate preferred display string for Ghidra URLs.
	 * Form can be parsed by the toURL method.
	 * @param url ghidra URL
	 * @return formatted URL display string
	 * @see #toURL(String)
	 */
	public static String getDisplayString(URL url) {
		if (isLocalProjectURL(url) && StringUtils.isBlank(url.getQuery()) &&
			StringUtils.isBlank(url.getRef())) {
			String path = url.getPath();
			if (path.indexOf(":/") == 2 && Character.isLetter(path.charAt(1))) {
				// assume windows path
				path = path.substring(1);
				path = path.replace('/', '\\');
			}
			return path;
		}
		return url.toString();
	}

	/**
	 * Create a URL which refers to a local Ghidra project
	 * @param dirPath absolute path of project location directory 
	 * @param projectName name of project
	 * @return local Ghidra project URL
	 */
	public static URL makeURL(String dirPath, String projectName) {
		return makeURL(dirPath, projectName, null, null);
	}
	
	/**
	 * Create a URL which refers to a local Ghidra project
	 * @param projectLocator absolute project location 
	 * @return local Ghidra project URL
	 * @throws IllegalArgumentException if {@code projectLocator} does not have an absolute location
	 */
	public static URL makeURL(ProjectLocator projectLocator) {
		return makeURL(projectLocator, null, null);
	}
	
	/**
	 * Create a URL which refers to a local Ghidra project with optional project file and ref
	 * @param projectLocation absolute path of project location directory 
	 * @param projectName name of project
	 * @param projectFilePath file path (e.g., /a/b/c, may be null)
	 * @param ref location reference (may be null)
	 * @return local Ghidra project URL
	 */
	public static URL makeURL(String projectLocation, String projectName, String projectFilePath,
			String ref) {
		if (StringUtils.isBlank(projectLocation) || StringUtils.isBlank(projectName)) {
			throw new IllegalArgumentException("Inavlid project location and/or name");
		}
		String path = checkAbsolutePath(projectLocation);
		if (!path.endsWith("/")) {
			path += "/";
		}
		StringBuilder buf = new StringBuilder(PROTOCOL);
		buf.append(":");
		buf.append(path);
		buf.append(projectName);

		if (!StringUtils.isBlank(projectFilePath)) {
			if (!projectFilePath.startsWith("/") || projectFilePath.contains("\\")) {
				throw new IllegalArgumentException("Invalid project file path");
			}
			buf.append("?");
			buf.append(projectFilePath);
		}
		if (!StringUtils.isBlank(ref)) {
			buf.append("#");
			buf.append(ref);
		}
		try {
			return new URL(buf.toString());
		}
		catch (MalformedURLException e) {
			throw new IllegalArgumentException(e);
		}
	}

	/**
	 * Create a URL which refers to a local Ghidra project with optional project file and ref
	 * @param projectLocator local project locator
	 * @param projectFilePath file path (e.g., /a/b/c, may be null)
	 * @param ref location reference (may be null)
	 * @return local Ghidra project URL
	 * @throws IllegalArgumentException if invalid {@code projectFilePath} specified or if URL 
	 * instantion fails.
	 */
	public static URL makeURL(ProjectLocator projectLocator, String projectFilePath, String ref) {
		return makeURL(projectLocator.getLocation(), projectLocator.getName(), projectFilePath,
			ref);
	}

	private static String[] splitOffName(String path) {
		String name = "";
		if (!StringUtils.isBlank(path) && !path.endsWith("/")) {
			int index = path.lastIndexOf('/');
			if (index >= 0) {
				// last name may or may not be a folder name
				name = path.substring(index + 1);
				path = path.substring(0, index);
			}
		}
		return new String[] { path, name };
	}

	/**
	 * Create a URL which refers to Ghidra Server repository content.  Path may correspond 
	 * to either a file or folder.  
	 * @param host server host name/address
	 * @param port optional server port (a value &lt;= 0 refers to the default port)
	 * @param repositoryName repository name
	 * @param repositoryPath absolute folder or file path within repository.
	 * Folder paths should end with a '/' character.
	 * @return Ghidra Server repository content URL
	 */
	public static URL makeURL(String host, int port, String repositoryName, String repositoryPath) {
		String[] splitName = splitOffName(repositoryPath);
		return makeURL(host, port, repositoryName, splitName[0], splitName[1], null);
	}

	/**
	 * Create a URL which refers to Ghidra Server repository content.  Path may correspond 
	 * to either a file or folder.  
	 * @param host server host name/address
	 * @param port optional server port (a value &lt;= 0 refers to the default port)
	 * @param repositoryName repository name
	 * @param repositoryPath absolute folder or file path within repository.
	 * @param ref ref or null 
	 * Folder paths should end with a '/' character.
	 * @return Ghidra Server repository content URL
	 */
	public static URL makeURL(String host, int port, String repositoryName, String repositoryPath,
			String ref) {
		String[] splitName = splitOffName(repositoryPath);
		return makeURL(host, port, repositoryName, splitName[0], splitName[1], ref);
	}

	/**
	 * Create a URL which refers to Ghidra Server repository content.  Path may correspond 
	 * to either a file or folder.  
	 * @param host server host name/address
	 * @param port optional server port (a value &lt;= 0 refers to the default port)
	 * @param repositoryName repository name
	 * @param repositoryFolderPath absolute folder path within repository. 
	 * @param fileName name of a file or folder contained within the specified {@code repositoryFolderPath}
	 * @param ref optional URL ref or null
	 * Folder paths should end with a '/' character.
	 * @return Ghidra Server repository content URL
	 * @throws IllegalArgumentException if invalid arguments are specified
	 */
	public static URL makeURL(String host, int port, String repositoryName,
			String repositoryFolderPath, String fileName, String ref) {
		if (StringUtils.isBlank(host)) {
			throw new IllegalArgumentException("host required");
		}
		if (StringUtils.isBlank(repositoryName)) {
			throw new IllegalArgumentException("repository name required");
		}
		if (port == 0 || port == GhidraServerHandle.DEFAULT_PORT) {
			port = -1;
		}
		String path = "/" + repositoryName;
		if (!StringUtils.isBlank(repositoryFolderPath)) {
			if (!repositoryFolderPath.startsWith("/") || repositoryFolderPath.indexOf('\\') >= 0) {
				throw new IllegalArgumentException("Invalid repository path");
			}
			path += repositoryFolderPath;
			if (!path.endsWith("/")) {
				path += "/";
			}
		}
		if (!StringUtils.isBlank(fileName)) {
			if (fileName.contains("/")) {
				throw new IllegalArgumentException("Invalid folder/file name: " + fileName);
			}
			if (!path.endsWith("/")) {
				path += "/";
			}
			path += fileName;
		}
		if (!StringUtils.isBlank(ref)) {
			path += "#" + ref;
		}
		try {
			return new URL(PROTOCOL, host, port, path);
		}
		catch (MalformedURLException e) {
			throw new IllegalArgumentException(e);
		}
	}

	/**
	 * Create a URL which refers to Ghidra Server repository and its root folder
	 * @param host server host name/address
	 * @param port optional server port (a value &lt;= 0 refers to the default port)
	 * @param repositoryName repository name
	 * @return Ghidra Server repository URL
	 */
	public static URL makeURL(String host, int port, String repositoryName) {
		return makeURL(host, port, repositoryName, null);
	}

}
