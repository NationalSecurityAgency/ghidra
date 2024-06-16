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

import java.io.File;
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

	// TODO: URL encoding/decoding should be used

	public static final String PROTOCOL = "ghidra";

	private static final String PROTOCOL_URL_START = PROTOCOL + ":/";

	private static Pattern IS_REMOTE_URL_PATTERN =
		Pattern.compile("^" + PROTOCOL_URL_START + "/[^/].*"); // e.g., ghidra://path

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
	 * Tests if the given url is using the Ghidra protocol
	 * @param url the url to test
	 * @return true if the url is using the Ghidra protocol
	 */
	public static boolean isGhidraURL(URL url) {
		return url != null && url.getProtocol().equals(PROTOCOL);
	}

	/**
	 * Determine if URL string uses a local format (e.g., {@code ghidra:/path...}).
	 * Extensive validation is not performed.  This method is intended to differentiate
	 * from a server URL only.
	 * @param str URL string
	 * @return true if string appears to be local Ghidra URL, else false
	 */
	public static boolean isLocalGhidraURL(String str) {
		return IS_LOCAL_URL_PATTERN.matcher(str).matches();
	}

	/**
	 * Determine if URL string uses a remote server format (e.g., {@code ghidra://host...}).
	 * Extensive validation is not performed.  This method is intended to differentiate
	 * from a local URL only.
	 * @param str URL string
	 * @return true if string appears to be remote server Ghidra URL, else false
	 */
	public static boolean isServerURL(String str) {
		return IS_REMOTE_URL_PATTERN.matcher(str).matches();
	}

	/**
	 * Determine if the specified URL is a local project URL.
	 * No checking is performed as to the existence of the project.
	 * @param url ghidra URL
	 * @return true if specified URL refers to a local 
	 * project (ghidra:/path/projectName...)
	 */
	public static boolean isLocalProjectURL(URL url) {
		return isLocalGhidraURL(url.toExternalForm());
	}

	/**
	 * Get the project locator which corresponds to the specified local project URL.
	 * Confirm local project URL with {@link #isLocalProjectURL(URL)} prior to method use.
	 * @param localProjectURL local Ghidra project URL
	 * @return project locator or null if invalid path specified
	 * @throws IllegalArgumentException URL is not a valid 
	 * {@link #isLocalProjectURL(URL) local project URL}.
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
	 * Determine if the specified URL is any type of supported server Ghidra URL.
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
	 * Ensure that absolute path is specified and normalize its format.
	 * An absolute path may start with a windows drive letter (e.g., c:/a/b, /c:/a/b)
	 * or without (e.g., /a/b).  Although for Windows the lack of a drive letter is
	 * not absolute, for consistency with Linux we permit this form which on
	 * Windows will use the default drive for the process. If path starts with a drive 
	 * letter (e.g., "c:/") it will have a "/" prepended (e.g., "/c:/", both forms
	 * are treated the same by the {@link File} class under Windows).
	 * @param path path to be checked and possibly modified.
	 * @return path to be used
	 * @throws IllegalArgumentException if an invalid path is specified
	 */
	private static String checkAbsolutePath(String path) {
		int scanIndex = 0;
		path = path.replace('\\', '/');
		int len = path.length();
		if (!path.startsWith("/")) {
			// Allow paths to start with windows drive letter (e.g., c:/a/b)
			if (len >= 3 && hasAbsoluteDriveLetter(path, 0)) {
				path = "/" + path;
			}
			else {
				throw new IllegalArgumentException("absolute path required");
			}
			scanIndex = 3;
		}
		else if (len >= 3 && hasDriveLetter(path, 1)) {
			if (len < 4 || path.charAt(3) != '/') {
				// path such as "/c:" not permitted
				throw new IllegalArgumentException("absolute path required");
			}
			scanIndex = 4;
		}
		checkInvalidChar("path", path, scanIndex);
		return path;
	}

	private static boolean hasDriveLetter(String path, int index) {
		return Character.isLetter(path.charAt(index++)) && path.charAt(index) == ':';
	}

	private static boolean hasAbsoluteDriveLetter(String path, int index) {
		int pathIndex = index + 2;
		return path.length() > pathIndex && hasDriveLetter(path, index) &&
			path.charAt(pathIndex) == '/';
	}

	/**
	 * Check for characters explicitly disallowed in path or project name.
	 * @param type type of string to include in exception
	 * @param str string to check
	 * @param startIndex index at which to start checking
	 * @throws IllegalArgumentException if str contains invalid character
	 */
	private static void checkInvalidChar(String type, String str, int startIndex) {
		for (int i = startIndex; i < str.length(); i++) {
			char c = str.charAt(i);
			if (ProjectLocator.DISALLOWED_CHARS.contains(c)) {
				throw new IllegalArgumentException(
					type + " contains invalid character: '" + c + "'");
			}
		}
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
			int minSplitIndex = projectPathOrURL.charAt(2) == ':' ? 3 : 0;
			int splitIndex = projectPathOrURL.lastIndexOf('/');
			if (splitIndex < minSplitIndex || projectPathOrURL.length() == (splitIndex + 1)) {
				throw new IllegalArgumentException("Absolute project path is missing project name");
			}
			++splitIndex;
			String location = projectPathOrURL.substring(0, splitIndex);
			String projectName = projectPathOrURL.substring(splitIndex);
			return makeURL(location, projectName);
		}
		try {
			return new URL(projectPathOrURL);
		}
		catch (MalformedURLException e) {
			throw new IllegalArgumentException(e);
		}
	}

	/**
	 * Get Ghidra URL which corresponds to the local-project or repository with any 
	 * file path or query details removed.
	 * @param ghidraUrl ghidra file/folder URL (server-only URL not permitted)
	 * @return local-project or repository URL
	 * @throws IllegalArgumentException if URL does not specify the {@code ghidra} protocol
	 * or does not properly identify a remote repository or local project.
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
	 * Force the specified URL to specify a folder.  This may be neccessary when only folders
	 * are supported since Ghidra permits both a folder and file to have the same name within
	 * its parent folder.  This method simply ensures that the URL path ends with a {@code /} 
	 * character if needed.
	 * @param ghidraUrl ghidra URL
	 * @return ghidra folder URL
	 * @throws IllegalArgumentException if specified URL is niether a 
	 * {@link #isServerRepositoryURL(URL) valid remote server URL}
	 * or {@link #isLocalProjectURL(URL) local project URL}.
	 */
	public static URL getFolderURL(URL ghidraUrl) {

		if (!GhidraURL.isServerRepositoryURL(ghidraUrl) &&
			!GhidraURL.isLocalProjectURL(ghidraUrl)) {
			throw new IllegalArgumentException("Invalid Ghidra URL: " + ghidraUrl);
		}

		URL repoURL = GhidraURL.getProjectURL(ghidraUrl);
		String path = GhidraURL.getProjectPathname(ghidraUrl);

		path = path.trim();
		if (!path.endsWith("/")) {

			// force explicit folder path
			path += "/";

			try {
				if (GhidraURL.isServerRepositoryURL(ghidraUrl)) {
					ghidraUrl = new URL(repoURL + path);
				}
				else {
					ghidraUrl = new URL(repoURL + "?" + path);
				}
			}
			catch (MalformedURLException e) {
				throw new AssertionError(e);
			}
		}
		return ghidraUrl;
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
	 * @throws IllegalArgumentException if an absolute projectLocation path is not specified
	 */
	public static URL makeURL(String projectLocation, String projectName, String projectFilePath,
			String ref) {
		if (StringUtils.isBlank(projectLocation) || StringUtils.isBlank(projectName)) {
			throw new IllegalArgumentException("Invalid project location and/or name");
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
	 * @throws IllegalArgumentException if required arguments are blank or invalid
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
