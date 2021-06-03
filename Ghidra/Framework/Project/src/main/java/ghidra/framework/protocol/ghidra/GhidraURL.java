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
import java.util.regex.Pattern;

import ghidra.framework.OperatingSystem;
import ghidra.framework.Platform;
import ghidra.framework.model.ProjectLocator;
import ghidra.framework.remote.GhidraServerHandle;

public class GhidraURL {

	public static final String PROTOCOL = "ghidra";

	private static Pattern IS_LOCAL_URL_PATTERN = Pattern.compile("^" + PROTOCOL + ":/[^/].*"); // e.g., ghidra:/path

	public static final String MARKER_FILE_EXTENSION = ".gpr";
	public static final String PROJECT_DIRECTORY_EXTENSION = ".rep";

	private GhidraURL() {
	}

	/**
	 * Determine if the specified URL refers to a local project and
	 * it exists.
	 * @param url
	 * @return true if specified URL refers to a local project and
	 * it exists.
	 */
	public static boolean localProjectExists(URL url) {
		if (!isLocalProjectURL(url)) {
			return false;
		}
		String path = url.getPath(); // assume path always starts with '/'
		if (Platform.CURRENT_PLATFORM.getOperatingSystem() == OperatingSystem.WINDOWS) {
			if (path.indexOf(":/") == 2) {
				path = path.substring(1);
			}
		}
		File markerFile = new File(path + MARKER_FILE_EXTENSION);
		File projectDir = new File(path + PROJECT_DIRECTORY_EXTENSION);
		return (markerFile.isFile() && projectDir.isDirectory());
	}

	/**
	 * Determine if the specified URL is a local project URL.
	 * No checking is performed as to the existence of the project.
	 * @param url
	 * @return true if specified URL refers to a local 
	 * project (ghidra:/path/projectName...)
	 */
	public static boolean isLocalProjectURL(URL url) {
		return IS_LOCAL_URL_PATTERN.matcher(url.toExternalForm()).matches();
	}

	/**
	 * Get the project name which corresponds to the specified 
	 * local project URL.
	 * @param localProjectURL local Ghidra project URL
	 * @return project name
	 * @throws IllegalArgumentException URL is not a valid local project URL
	 */
	public static String getProjectName(URL localProjectURL) {
		if (!isLocalProjectURL(localProjectURL)) {
			throw new IllegalArgumentException("Invalid local Ghidra project URL");
		}
		String path = localProjectURL.getPath();
		int index = path.lastIndexOf('/');
		return path.substring(index + 1);
	}

	/**
	 * Get the project location path which corresponds to the specified 
	 * local project URL.
	 * @param localProjectURL local Ghidra project URL
	 * @return project location path
	 * @throws IllegalArgumentException URL is not a valid local project URL
	 */
	public static String getProjectLocation(URL localProjectURL) {
		if (!isLocalProjectURL(localProjectURL)) {
			throw new IllegalArgumentException("Invalid local Ghidra project URL");
		}
		String path = localProjectURL.getPath();
		int index = path.lastIndexOf('/');
		path = path.substring(0, index);
		if (path.indexOf(":/") == 2) {
			path = path.substring(1);
			path = path.replace('/', File.separatorChar);
		}
		return path;
	}

	/**
	 * Get the project locator which corresponds to the specified 
	 * local project URL.
	 * @param localProjectURL local Ghidra project URL
	 * @return project locator
	 * @throws IllegalArgumentException URL is not a valid local project URL
	 */
	public static ProjectLocator getProjectStorageLocator(URL localProjectURL) {
		if (!isLocalProjectURL(localProjectURL)) {
			throw new IllegalArgumentException("Invalid local Ghidra project URL");
		}
		String path = localProjectURL.getPath();
		int index = path.lastIndexOf('/');
		String dirPath = path.substring(0, index);
		if (dirPath.endsWith(":")) {
			dirPath += "/";
		}
		if (dirPath.indexOf(":/") == 2) {
			dirPath = dirPath.substring(1);
			dirPath = dirPath.replace('/', File.separatorChar);
		}
		String name = path.substring(index + 1);
		return new ProjectLocator(dirPath, name);
	}

	/**
	 * Determine if the specified URL is any type of server "repository" URL.
	 * No checking is performed as to the existence of the server or repository.
	 * @param url
	 * @return true if specified URL refers to a Ghidra server 
	 * repository (ghidra://host/repositoryNAME/path...)
	 */
	public static boolean isServerRepositoryURL(URL url) {
		String path = url.getPath();
		return isServerURL(url) && path != null && path.length() > 0;
	}

	/**
	 * Determine if the specified URL is any type of server URL.
	 * No checking is performed as to the existence of the server or repository.
	 * @param url
	 * @return true if specified URL refers to a Ghidra server 
	 * repository (ghidra://host/repositoryNAME/path...)
	 */
	public static boolean isServerURL(URL url) {
		if (!PROTOCOL.equals(url.getProtocol())) {
			return false;
		}
		return Handler.isSupportedURL(url);
	}

	private static String checkAbsolutePath(String path) {
		path = path.replace('\\', '/');
		if (!path.startsWith("/")) {
			if (path.length() >= 3 && path.substring(1).startsWith(":/")) {
				// prepend a "/" on Windows paths (e.g., C:/mydir)
				path = "/" + path;
			}
			else {
				throw new IllegalArgumentException("Absolute directory path required");
			}
		}
		return path;
	}

	/**
	 * Create a Ghidra URL from a string form of Ghidra URL or local project path.
	 * This method can consume strings produced by the getDisplayString method.
	 * @param projectPathOrURL {@literal project path (<absolute-directory>/<project-name>)}
	 * @return local Ghidra project URL
	 * @see #getDisplayString(URL)
	 * @throws IllegalArgumentException invalid path or URL specified
	 */
	public static URL toURL(String projectPathOrURL) {
		String path = projectPathOrURL;
		if (!path.startsWith(PROTOCOL + ":")) {
			path = checkAbsolutePath(projectPathOrURL);
			int index = path.lastIndexOf('/');
			if (index <= 0 || index == (path.length() - 1)) {
				// Ensure that path includes projectName
				throw new IllegalArgumentException("Invalid project path or URL");
			}
			path = PROTOCOL + ":" + path;
		}
		try {
			return new URL(path);
		}
		catch (MalformedURLException e) {
			throw new IllegalArgumentException(e);
		}
	}

	/**
	 * Get a normalized URL which eliminates use of host names and additional URL refs
	 * which may prevent direct comparison.
	 * @param url
	 * @return normalized url
	 */
	public static URL getNormalizedURL(URL url) {
		if (!isServerRepositoryURL(url)) {
			// TODO: May need to add support for other ghidra URL forms
			return url;
		}
		String host = url.getHost();
		try {
			InetAddress addr = InetAddress.getByName(host);
			host = addr.getHostAddress();
		}
		catch (UnknownHostException e) {
			// just use hostname if unable to resolve
		}
		try {
			return new URL(PROTOCOL, host, url.getPort(), url.getPath());
		}
		catch (MalformedURLException e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * Generate preferred display string for Ghidra URLs.
	 * Form can be parsed by the toURL method.
	 * @param url
	 * @return
	 * @see #toURL(String)
	 */
	public static String getDisplayString(URL url) {
		if (isLocalProjectURL(url)) {
			String path = url.getPath();
			if (path.indexOf(":/") == 2) {
				// assume windows path
				path = path.substring(1);
				path = path.replace('/', '\\');
			}
			return path;
		}
		return url.toString();
	}

	/**
	 * Create a local project URL for a specified project marker file.
	 * @param projectMarkerFile project marker file
	 * @return local project URL
	 */
	public static URL makeURL(File projectMarkerFile) {
		String name = projectMarkerFile.getName();
		if (Platform.CURRENT_PLATFORM.getOperatingSystem() == OperatingSystem.WINDOWS) {
			if (!name.endsWith(MARKER_FILE_EXTENSION) &&
				!name.toLowerCase().endsWith(MARKER_FILE_EXTENSION)) {
				throw new IllegalArgumentException("Invalid project marker file");
			}
		}
		else if (!name.endsWith(MARKER_FILE_EXTENSION)) {
			throw new IllegalArgumentException("Invalid project marker file");
		}
		name = name.substring(0, name.length() - MARKER_FILE_EXTENSION.length());
		String location = projectMarkerFile.getParentFile().getAbsolutePath();
		return makeURL(location, name);
	}

	/**
	 * Create a URL which refers to a local Ghidra project
	 * @param dirPath absolute path of project location directory 
	 * @param projectName name of project
	 * @return local Ghidra project URL
	 */
	public static URL makeURL(String dirPath, String projectName) {
		String path = checkAbsolutePath(dirPath);
		if (!path.endsWith("/")) {
			path += "/";
		}
		try {
			return new URL(PROTOCOL + ":" + path + projectName);
		}
		catch (MalformedURLException e) {
			throw new IllegalArgumentException(e);
		}
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
		return makeURL(host, port, repositoryName, repositoryPath, null, null);
	}

	/**
	 * Create a URL which refers to Ghidra Server repository content.  Path may correspond 
	 * to either a file or folder.  
	 * @param host server host name/address
	 * @param port optional server port (a value &lt;= 0 refers to the default port)
	 * @param repositoryName repository name
	 * @param repositoryPath absolute folder path within repository. 
	 * @param fileName name of a file contained within the specified repository/path
	 * @param ref optional URL ref or null
	 * Folder paths should end with a '/' character.
	 * @return Ghidra Server repository content URL
	 */
	public static URL makeURL(String host, int port, String repositoryName, String repositoryPath,
			String fileName, String ref) {
		if (host == null) {
			throw new IllegalArgumentException("host required");
		}
		if (repositoryName == null) {
			throw new IllegalArgumentException("repository name required");
		}
		if (port == 0 || port == GhidraServerHandle.DEFAULT_PORT) {
			port = -1;
		}
		String path = "/" + repositoryName;
		if (repositoryPath != null) {
			if (!repositoryPath.startsWith("/") || repositoryPath.indexOf('\\') >= 0) {
				throw new IllegalArgumentException("Invalid repository path");
			}
			path += repositoryPath;
		}
		else {
			path += "/";
		}
		if (fileName != null) {
			if (!path.endsWith("/")) {
				path += "/";
			}
			path += fileName;
		}
		if (ref != null) {
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
