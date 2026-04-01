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
import java.io.UnsupportedEncodingException;
import java.net.*;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.lang3.StringUtils;

import ghidra.framework.client.RepositoryServerAdapter;
import ghidra.framework.model.*;
import ghidra.framework.remote.GhidraServerHandle;
import ghidra.util.NamingUtilities;

/**
 * Utility class which provides support for creating Ghidra local project and remote repository
 * URLs.  Valid Ghidra URL forms include:
 * <ul>
 * <li>{@literal ghidra:[ext:]//<host>:<port>/<repository-name>[/<folder-path>]/[<folderItemName>[#ref]]}</li>
 * <li>{@literal ghidra:/[X:/]<project-path>/<project-name>[?[/<folder-path>]/[<folderItemName>[#ref]]]}</li>
 * <li>{@literal ghidra:////UNCServer/UNCshare/<project-name>[?[/<folder-path>]/[<folderItemName>[#ref]]]}</li>
 * </ul>
 * <p>
 * NOTE: [ext:] corresponds to an optional Ghidra server extension protocol if supported.  
 * This requires a corresponding {@link GhidraProtocolHandler} extension.  Helper methods within
 * this utility are not provided for forming such URLs.  A separate GhidraExtURL utility 
 * should be established if such a protocol extension is established or used.  It is assumed that
 * any such extension utilizing a compliant hierarchical URL which appears as an opaque URI element
 * within the Ghidra URL.
 * <p>
 * Various system path utilities are also provided in support of local Ghidra project URLs and
 * {@link ProjectLocator}. 
 */
public class GhidraURL {

	public static final String PROTOCOL = "ghidra";

	private static final String PROTOCOL_URL_START = PROTOCOL + ":";

	/**
	 * A pattern that matches when the URL path is on the local file system.
	 * <P>
	 * Pattern: 
	 * 	
	 * 		^ghidra:(/[^/]|////)(?![/]).*
	 * 
	 * Explanation:
	 * 
	 * 		^ghidra:		- starts with 'ghidra:'
	 * 		(/|////)    	- match a single slash or 4 slashes
	 * 		(?![/])			- with no following slashes
	 *      .*				- any other text
	 * 				
	 * Examples:
	 * 	
	 * 		ghidra:/path		- matches
	 * 		ghidra:////path		- matches
	 * 		ghidra://path		- does not match
	 */
	private static Pattern IS_LOCAL_URL_PATTERN =
		Pattern.compile("^" + PROTOCOL + ":(/|////)(?![/]).*"); // e.g., ghidra:/path or ghidra:////path

	private static Pattern STARTS_WITH_TWO_FORWARD_SLASHES_PATTERN =
		Pattern.compile("^//(?![/]).*");

	/**
	 * A pattern which matches a Windows path specification with a drive letter, optional '/' prefix
	 * and optional trailing path.
	 * e.g., /C:, C:, /C:/path, C:/path
	 */
	private static Pattern WINDOWS_DRIVE_PATH_PATTERN = Pattern.compile("^[/]{0,1}[A-Za-z]:(/.*)?");

	/**
	 * A pattern that matches a UNC path which include a server and share name.
	 * e.g., //server/share/a/b
	 */
	private static Pattern UNC_PATH_PATTERN = Pattern.compile("^//(?![/]).+/(?![/]).+");

	public static final String MARKER_FILE_EXTENSION = ".gpr";
	public static final String PROJECT_DIRECTORY_EXTENSION = ".rep";

	private GhidraURL() {
	}

	/**
	 * Determine if the specified URL refers to a local project and
	 * it exists.
	 * 
	 * @param url Ghidra URL
	 * @return true if specified URL refers to a local project and
	 * it exists.
	 */
	public static boolean localProjectExists(URL url) {
		ProjectLocator loc = getProjectStorageLocator(url);
		return loc != null && loc.exists();
	}

	/**
	 * Determine if the specified string appears to be a possible Ghidra URL
	 * (starts with "ghidra:").
	 *  
	 * @param str string to be checked
	 * @return true if string is possible Ghidra URL
	 */
	public static boolean isGhidraURL(String str) {
		return str != null && str.startsWith(PROTOCOL_URL_START);
	}

	/**
	 * Tests if the given url is using the Ghidra protocol.
	 * 
	 * @param url the url to test
	 * @return true if the url is using the Ghidra protocol
	 */
	public static boolean isGhidraURL(URL url) {
		return url != null && url.getProtocol().equals(PROTOCOL);
	}

	/**
	 * Determine if URL string uses a local Ghidra project URL format (e.g., {@code ghidra:/path...}).
	 * Extensive validation is not performed.  This method is intended to differentiate
	 * from a server URL only.
	 * 
	 * @param str URL string
	 * @return true if string appears to be local Ghidra URL, else false
	 */
	public static boolean isLocalURL(String str) {
		return IS_LOCAL_URL_PATTERN.matcher(str).matches();
	}

	/**
	 * Determine if URL string uses a local Ghidra project URL format (e.g., {@code ghidra:/path...}).
	 * Extensive validation is not performed.  This method is intended to differentiate
	 * from a server URL only.
	 * 
	 * @param url URL
	 * @return true if specified URL refers to a local Ghidra project (ghidra:/path/projectName...)
	 */
	public static boolean isLocalURL(URL url) {
		return isLocalURL(url.toExternalForm());
	}

	/**
	 * Determine if a URL string corresponds to a remote Ghidra server URL 
	 * (e.g., {@code ghidra://host...}, {@code ghidra:<extension>://host...}). 
	 * Extensive validation is not performed.  This method is intended to differentiate between a 
	 * local and remote Ghidra URL only.
	 * 
	 * @param str URL string
	 * @return true if string appears to be remote server Ghidra URL, else false
	 */
	public static boolean isServerURL(String str) {
		return isGhidraURL(str) && !isLocalURL(str);
	}

	/**
	 * Determine if the specified path is only valid on a Windows platform.  Such paths contain
	 * either a drive specification or UNC path (e.g., C:\, /C:/, //server/..., \\server\..).
	 * NOTE: This does not check for existence of the specified path.
	 * 
	 * @param path file path specification
	 * @return true if path is only valid when used on a Windows system.
	 */
	public static boolean isWindowsOnlyPath(String path) {
		String normalizedPath = path.replace('\\', '/');
		return WINDOWS_DRIVE_PATH_PATTERN.matcher(normalizedPath).matches() ||
			UNC_PATH_PATTERN.matcher(normalizedPath).matches();
	}

	/**
	 * Get the project locator which corresponds to the specified local project URL.
	 * Confirm local project URL with {@link #isLocalURL(URL)} prior to method use.
	 * 
	 * @param localProjectURL local Ghidra project URL
	 * @return project locator or null if invalid path specified
	 * @throws IllegalArgumentException URL is not a valid 
	 * {@link #isLocalURL(URL) local project URL}.
	 */
	public static ProjectLocator getProjectStorageLocator(URL localProjectURL) {
		if (!isLocalURL(localProjectURL)) {
			throw new IllegalArgumentException("Invalid local Ghidra project URL");
		}

		URI uri = URI.create(localProjectURL.toExternalForm());

		String path = uri.getPath();
		int index = path.lastIndexOf('/');
		String dirPath = index != 0 ? path.substring(0, index) : "/";

		if (dirPath.startsWith("////")) {
			// Prune UNC path as it appears in URL
			dirPath = dirPath.substring(2);
		}

		String name = path.substring(index + 1);
		if (name.length() == 0) {
			return null;
		}

		return new ProjectLocator(dirPath, name);
	}

	/**
	 * {@return the URL-decoded project content path contained within the query portion of
	 * a local Ghidra URL.  The root folder will be returned if no path was specified.}
	 * 
	 * @param uri GhidraURL in URI form.
	 * @throws URISyntaxException if a URI interpretation/parse fails
	 */
	private static String getLocalProjectContentPath(URI uri) throws URISyntaxException {
		String path = uri.getQuery();
		if (path == null) {
			return "/";
		}
		if (!path.startsWith("/")) {
			throw new URISyntaxException(uri.toString(),
				"Missing absolute project content path");
		}
		return path;
	}

	/**
	 * {@return the URL-decoded path contained within the specified URI.}
	 * NOTE: This will include the repository name included within the path.
	 * 
	 * @param uri GhidraURL in URI form.
	 * @throws URISyntaxException if a URI interpretation/parse fails
	 */
	private static String getServerURIPath(URI uri) throws URISyntaxException {
		String path = null;
		if (uri.isOpaque()) {
			// handle possible ghidra protocol extension use which is assumed to encode
			// repository and file path the same as standard Ghidra URL.
			String subPart = uri.getSchemeSpecificPart();
			if (StringUtils.isBlank(subPart)) {
				throw new URISyntaxException(uri.toString(), "Invalid Ghidra URL");
			}
			path = URI.create(subPart).getPath();
		}
		else if (uri.getAuthority() != null) {
			path = uri.getPath();
		}
		if (StringUtils.isBlank(path)) {
			throw new URISyntaxException(uri.toString(),
				"Invalid ghidra repository URL - repository not specified");
		}
		return path;
	}

	/**
	 * {@return Get the URL-decoded reference/fragment from the URL or null}
	 * <p>
	 * NOTE: The presence of "+" in the original reference fragment is problematic and
	 * requires consistent use of this method in conjunction with the URL instantiation
	 * methods provided by this utility class.
	 * 
	 * @param url Ghidra URL
	 */
	public static String getDecodedReference(URL url) {
		String ref = url.getRef();
		if (StringUtils.isBlank(ref)) {
			return null;
		}
		try {
			// NOTE: original "+" may appear encoded in final URL as "%252B"
			ref = URLDecoder.decode(ref, "UTF-8");
			ref = ref.replace("%2B", "+"); // force double-decode of original "+"
			return ref;
		}
		catch (UnsupportedEncodingException e) {
			return null;
		}
	}

	/**
	 * Perform preliminary encode of '+' within raw ref string so that it may be preserved
	 * and properly decoded from {@link URI#getFragment()} by {@link #getDecodedReference(URL)}.
	 * Once fully encoded by URI a raw '+' will appear with a double encoding of "%252B".
	 * 
	 * @param rawRef raw ref/fragment to be prepared for use with URI creation.
	 * @return preliminary encoding of specified raw ref string.
	 */
	private static String encodeRefPlus(String rawRef) {
		return StringUtils.isBlank(rawRef) ? null : rawRef.replace("+", "%2B");
	}

	/**
	 * Get the shared repository name associated with a repository URL or null
	 * if not applicable.  For Ghidra URL extensions it is assumed that the first path element
	 * corresponds to the repository name.
	 * 
	 * @param url Ghidra URL for shared project resource
	 * @return repository name or null if not applicable to URL
	 */
	public static String getRepositoryName(URL url) {
		if (!isServerURL(url)) {
			return null;
		}

		try {
			URI uri = url.toURI();
			String path = getServerURIPath(uri);
			if (path.length() < 2 || path.charAt(0) != '/' || path.charAt(1) == '/') {
				return null;
			}
			path = path.substring(1);
			int ix = path.indexOf("/");
			if (ix > 0) {
				path = path.substring(0, ix);
			}
			return path;
		}
		catch (URISyntaxException e) {
			return null;
		}
	}

	/**
	 * Determine if the specified URL is any type of server "repository" URL.
	 * No checking is performed as to the existence of the server or repository.
	 * <p>
	 * NOTE: ghidra protocol extensions are not currently supported (e.g., ghidra:http://...).
	 * 
	 * @param url Ghidra URL
	 * @return true if specified URL refers to a Ghidra server 
	 * repository (ghidra://host/repositoryNAME/path...)
	 */
	public static boolean isServerRepositoryURL(URL url) {
		if (!isServerURL(url)) {
			return false;
		}
		try {
			URI uri = url.toURI();
			String path = getServerURIPath(uri);
			return path.charAt(0) == '/' && path.length() > 1 && path.charAt(1) != '/';
		}
		catch (URISyntaxException e) {
			return false;
		}
	}

	/**
	 * Determine if the specified URL is any type of supported server Ghidra URL.
	 * If a Ghidra server extension URL is specified the corresponding {@link GhidraProtocolHandler}
	 * extension must be present or false will be returned.
	 * 
	 * @param url Ghidra URL
	 * @return true if specified URL refers to a Ghidra server 
	 * repository (e.g., {@code ghidra://host/repositoryNAME/path...}, 
	 * {@code ghidra:<extension>://host/repositoryNAME/path...})
	 */
	public static boolean isServerURL(URL url) {
		if (!PROTOCOL.equals(url.getProtocol())) {
			return false;
		}
		return Handler.isSupportedURL(url);
	}

	/**
	 * Ensure that absolute path is specified and normalize its format (e.g., Windows path
	 * separators are converted to '/').  An absolute path may start with a windows drive 
	 * letter (e.g., c:\a\b, c:/a/b, /c:/a/b) or without (e.g., /a/b) or a UNC path 
	 * (e.g., //server/share/a/b, \\server\share\a\b).  
	 * <p>
	 * For Windows, the lack of a drive letter is not absolute; although, for consistency with 
	 * Linux we permit this form which on Windows will use the default drive for the process. 
	 * If path starts with a drive letter (e.g., "c:/") it will have a "/" prepended 
	 * (e.g., "/c:/", both forms are treated the same by the {@link File} class under Windows).
	 * <p>
	 * Path element naming restrictions are imposed based upon 
	 * {@link NamingUtilities#checkName(String, String)} restrictions.  These restrictions
	 * are imposed to ensure we can easily express the local project path in URL form.
	 * 
	 * @param absolutePath path to be checked and possibly modified.
	 * @param isDirectory true if returned path should include a trailing '/'
	 * @return path to be used
	 * @throws IllegalArgumentException if an invalid path is specified based upon 
	 * {@link NamingUtilities} restrictions.
	 */
	public static String checkLocalAbsolutePath(String absolutePath, boolean isDirectory) {

		String path = absolutePath.replace('\\', '/');

		Matcher matcher = UNC_PATH_PATTERN.matcher(path);
		if (matcher.matches()) {
			// Handle UNC path
			checkValidProjectPath(path, 2);
			if (isDirectory && !path.endsWith("/")) {
				path += "/";
			}
			return path;
		}
		else if (path.startsWith("//")) {
			throw new IllegalArgumentException("Invalid UNC path: " + absolutePath);
		}

		int scanIndex = 1; // char position after '/' (assumed - checked below)

		if (WINDOWS_DRIVE_PATH_PATTERN.matcher(path).matches()) {
			if (!path.startsWith("/")) {
				path = "/" + path;
			}
			if (path.length() == 3) { // e.g., '/C:'
				path += '/'; // add trailing '/' immediately after ':' (directory)
			}
			scanIndex = 4; // char position after '/C:/'
		}
		else if (!path.startsWith("/")) {
			throw new IllegalArgumentException("Absolute path required");
		}

		checkValidProjectPath(path, scanIndex);

		if (isDirectory && !path.endsWith("/")) {
			path += "/";
		}
		return path;
	}

	/**
	 * Check for valid project path. See {@link NamingUtilities#checkName(String, String)}).
	 * 
	 * @param path project path to check (using '/' path separator).
	 * @param startIndex index at which to start checking immediately after root path separator
	 * @throws IllegalArgumentException if path contains invalid character
	 */
	private static void checkValidProjectPath(String path, int startIndex) {
		String str = path.substring(startIndex);
		if (str.length() != 0) {
			for (String s : str.split("/")) {
				NamingUtilities.checkName(s, null);
			}
		}
	}

	/**
	 * Create a Ghidra URL from a string form of a Ghidra URL or local project path.
	 * This method can consume strings produced by the getDisplayString method.
	 * 
	 * @param projectPathOrURL {@literal project path (<absolute-directory>/<project-name>)} or 
	 * string form of Ghidra URL.
	 * @return local Ghidra project URL
	 * @throws IllegalArgumentException invalid path or URL specified
	 */
	public static URL toURL(String projectPathOrURL) {
		if (!isGhidraURL(projectPathOrURL)) {
			if (projectPathOrURL.endsWith(ProjectLocator.PROJECT_DIR_SUFFIX) ||
				projectPathOrURL.endsWith(ProjectLocator.PROJECT_FILE_SUFFIX)) {
				String ext = projectPathOrURL.substring(projectPathOrURL.lastIndexOf('.'));
				throw new IllegalArgumentException("Project path must omit extension: " + ext);
			}
			projectPathOrURL = checkLocalAbsolutePath(projectPathOrURL, false);
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

		// NOTE: We must assume URL is properly encoded in its external form
		try {
			return URI.create(projectPathOrURL).toURL();
		}
		catch (Exception e) {
			throw new IllegalArgumentException("Invalid Ghidra URL", e);
		}
	}

	/**
	 * Create a new URL which is resolved from a base Ghidra project or repository URL to which 
	 * the specified content folder or file path is added along with the optional reference.
	 *            
	 * @param ghidraUrl the base Ghidra project or repository URL which will be used as the basis
	 *            for forming a new Ghidra URL.            
	 * @param projectFilePath an absolute folder or file path within the project (e.g., /a/b/c, 
	 *            may be null for root folder).  Folder paths should end with a '/' character.
	 * @param ref optional location reference (may be null) which is appended to URL with a '#' 
	 *            delimiter.
	 * @return new resolved URL
	 * @throws IllegalArgumentException if an invalid Ghidra project or repository URL is specified
	 *            or an invalid folder/file path is specified.
	 */
	public static URL resolve(URL ghidraUrl, String projectFilePath, String ref) {
		
		if (!StringUtils.isBlank(projectFilePath)) {
			if (!projectFilePath.startsWith("/") || projectFilePath.contains("\\")) {
				throw new IllegalArgumentException("Absolute path required using '/' delimiter");
			}
			checkValidProjectPath(projectFilePath, 1);
		}
		else {
			projectFilePath = null;
		}

		ref = encodeRefPlus(ref);
		
		Exception exc = null;
		try {
			URI uri = ghidraUrl.toURI();

			if (isLocalURL(ghidraUrl)) {
				String systemProjectPath = forceLocalUNCPathIfNeeded(uri.getPath()); // Preserve UNC path if needed
				return new URI(PROTOCOL, null, systemProjectPath, projectFilePath, ref).toURL();
			}

			String repoName = getRepositoryName(ghidraUrl);
			if (repoName != null) {

				String path = "/" + repoName;
				if (projectFilePath != null) {
					path += projectFilePath;
				}

				if (uri.isOpaque()) {
					// handle possible ghidra protocol extension use which is assumed to encode
					// repository and file path the same as standard Ghidra URL.
					String subPart = uri.getSchemeSpecificPart();
					if (StringUtils.isBlank(subPart)) {
						throw new URISyntaxException(ghidraUrl.toExternalForm(),
							"Invalid Ghidra URL");
					}
					URI extURI = URI.create(subPart);
					URI revisedExtURI = extURI.resolve(path);
					return new URI(PROTOCOL, revisedExtURI.toURL().toExternalForm(),
						ref).toURL();
				}

				// Resolve normal Ghidra server URL
				uri = uri.resolve(path);
				if (ref != null) {
					uri = uri.resolve("#" + ref);
				}
				return uri.toURL();
			}
		}
		catch (URISyntaxException | MalformedURLException e) {
			exc = e;
		}
		throw new IllegalArgumentException("Invalid project/repository URL: " + ghidraUrl, exc);
	}

	/**
	 * Get Ghidra URL which corresponds to the local-project or repository with any 
	 * file path or query details removed.
	 * 
	 * @param ghidraUrl ghidra file/folder URL (server-only URL not permitted)
	 * @return local-project or repository URL
	 * @throws IllegalArgumentException if URL does not specify the {@code ghidra} protocol
	 * or does not properly identify a remote repository or local project.
	 */
	public static URL getProjectURL(URL ghidraUrl) {
		return resolve(ghidraUrl, null, null);
	}

	/**
	 * Get the decoded project content pathname referenced by the specified Ghidra file/folder URL.
	 * If path is missing root folder is returned.
	 * <p>
	 * NOTE: This project content pathname should not be confused with a local project storage 
	 * path associated with a {@link ProjectLocator} or local project Ghidra URL.
	 * 
	 * @param ghidraUrl Ghidra local or remote file/folder URL (server-only URL not permitted)
	 * @return pathname of file or folder
	 */
	public static String getProjectPathname(URL ghidraUrl) {

		try {
			URI uri = ghidraUrl.toURI();

			if (isLocalURL(ghidraUrl)) {
				return getLocalProjectContentPath(uri);
			}

			if (isServerURL(ghidraUrl)) {
				String path = getServerURIPath(uri); // URL-decoded path

				// skip repo name (first path element)
				int ix = path.indexOf('/', 1);
				if (ix > 1) {
					return path.substring(ix);
				}
				return "/";
			}
		}
		catch (URISyntaxException e) {
			// ignore
		}
		throw new IllegalArgumentException("Invalid project/repository URL");
	}

	/**
	 * {@return host name as an IP address if possible, otherwise supplied host string is returned}
	 * @param host host name
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

	private static String forceLocalUNCPathIfNeeded(String path) {
		if (path.startsWith("//") && path.length() > 3 && path.charAt(2) != '/') {
			path = "//" + path;
		}
		return path;
	}

	/**
	 * Force the specified URL to specify a folder.  This may be necessary when only folders
	 * are supported since Ghidra permits both a folder and file to have the same name within
	 * its parent folder.  This method simply ensures that the URL path ends with a {@code /} 
	 * character if needed.
	 * 
	 * @param ghidraUrl Ghidra URL
	 * @return ghidra folder URL
	 * @throws IllegalArgumentException if specified URL is neither a 
	 * {@link #isServerRepositoryURL(URL) valid remote server URL}
	 * or {@link #isLocalURL(URL) local project URL}.
	 */
	public static URL getFolderURL(URL ghidraUrl) {
		String folderPath = getProjectPathname(ghidraUrl);
		if (!folderPath.endsWith("/")) {
			folderPath += "/";
		}
		return resolve(ghidraUrl, folderPath, getDecodedReference(ghidraUrl));
	}

	/**
	 * Get a normalized URL which eliminates use of host names and optional URL ref
	 * which may prevent direct comparison.
	 * 
	 * @param url Ghidra URL
	 * @return normalized url
	 */
	public static URL getNormalizedURL(URL url) {

		if (!isGhidraURL(url)) {
			throw new IllegalArgumentException("Ghidra URL required");
		}

		try {
			URI uri = url.toURI();

			if (isLocalURL(url)) {
				return new URI(PROTOCOL, null, uri.getPath(), uri.getQuery(), null).toURL();
			}

			if (uri.isOpaque()) {
				// Hierarchical URL is assumed for ghidra protocol extensions
				String subPart = uri.getSchemeSpecificPart();
				if (StringUtils.isBlank(subPart)) {
					throw new URISyntaxException(url.toExternalForm(), "Invalid Ghidra URL");
				}
				URI extUri = URI.create(subPart);
				String host = extUri.getHost();
				String revisedHost = getHostAsIpAddress(host);
				if (Objects.equals(host, revisedHost) && url.getRef() == null) {
					return url; // no change
				}
				extUri = new URI(extUri.getScheme(), extUri.getUserInfo(), revisedHost,
					extUri.getPort(), extUri.getPath(), extUri.getQuery(), null);
				String ssp = extUri.toURL().toExternalForm();
				return new URI(PROTOCOL, ssp, null).toURL();
			}

			String host = uri.getHost();
			String revisedHost = getHostAsIpAddress(host);
			if (Objects.equals(host, revisedHost) && url.getRef() == null) {
				return url; // no change
			}
			// NOTE: Ghidra server does not support query so we strip it
			return new URI(uri.getScheme(), uri.getUserInfo(), revisedHost, uri.getPort(),
				uri.getPath(), null, null).toURL();
		}
		catch (Exception e) {
			throw new IllegalArgumentException("Invalid Ghidra URL", e);
		}
	}

	/**
	 * Generate preferred display string for Ghidra URLs.
	 * <p>
	 * NOTE: The display-friendly string returned is intended for display use only and should not be 
	 * parsed back into a URL.
	 * 
	 * @param url Ghidra URL
	 * @return formatted URL display string
	 * @see #toURL(String)
	 */
	public static String getDisplayString(URL url) {

		try {
			if (isLocalURL(url) && StringUtils.isBlank(url.getQuery()) &&
				StringUtils.isBlank(url.getRef())) {

				URI uri = url.toURI();
				String path = uri.getPath();
				if (path.indexOf(":/") == 2 && Character.isLetter(path.charAt(1))) {
					// assume windows path
					path = path.substring(1);
					path = path.replace('/', '\\');
				}
				return path;
			}
		}
		catch (URISyntaxException e) {
			// ignore
		}
		return url.toString();
	}

	/**
	 * Create a URL which refers to a local Ghidra project's root folder.
	 * <p>
	 * Upon a successful URL connection, a {@link GhidraURLWrappedContent}
	 * content object will be provided from which {@link GhidraURLWrappedContent#getContent(Object)}
	 * may be invoked to obtain the referenced root {@link DomainFolder}.
	 * <p>
	 * NOTE: A proper {@link GhidraURLWrappedContent#release(Object, Object)} is mandatory after
	 * retrieving the wrapped content folder or file object.
	 * 
	 * @param dirPath absolute path of project location directory 
	 * @param projectName name of project
	 * @return local Ghidra project URL
	 */
	public static URL makeURL(String dirPath, String projectName) {
		return makeURL(dirPath, projectName, null, null);
	}

	/**
	 * Create a URL which refers to a local Ghidra project's root folder.
	 * <p>
	 * Upon a successful URL connection, a {@link GhidraURLWrappedContent}
	 * content object will be provided from which {@link GhidraURLWrappedContent#getContent(Object)}
	 * may be invoked to obtain the referenced root {@link DomainFolder}.
	 * <p>
	 * NOTE: A proper {@link GhidraURLWrappedContent#release(Object, Object)} is mandatory after
	 * retrieving the wrapped content folder or file object.
	 * 
	 * @param projectLocator absolute project location 
	 * @return local Ghidra project root folder URL
	 * @throws IllegalArgumentException if {@code projectLocator} does not have an absolute location
	 */
	public static URL makeURL(ProjectLocator projectLocator) {
		return makeURL(projectLocator, null, null);
	}

	/**
	 * Create a URL which refers to a local Ghidra project with optional project folder/file path
	 * and optional reference.
	 * <p>
	 * Upon a successful URL connection, a {@link GhidraURLWrappedContent}
	 * content object will be provided from which {@link GhidraURLWrappedContent#getContent(Object)}
	 * may be invoked to obtain either the referenced {@link DomainFolder} or {@link DomainFile}.
	 * <p>
	 * NOTE: A proper {@link GhidraURLWrappedContent#release(Object, Object)} is mandatory after
	 * retrieving the wrapped content folder or file object.
	 * 
	 * @param projectLocation absolute path of project location directory 
	 * @param projectName name of project
	 * @param projectFilePath an absolute folder or file path within the project (e.g., /a/b/c, 
	 *            may be null for root folder).  Folder paths should end with a '/' character.
	 * @param ref optional location reference (may be null) which is appended to URL with a '#' 
	 *            delimiter.
	 * @return local Ghidra project URL
	 * @throws IllegalArgumentException if an absolute projectLocation path is not specified
	 */
	public static URL makeURL(String projectLocation, String projectName, String projectFilePath,
			String ref) {

		// NOTE: name and path element lengths are not restricted

		if (StringUtils.isBlank(projectLocation) || StringUtils.isBlank(projectName)) {
			throw new IllegalArgumentException("Invalid project location and/or name");
		}
		NamingUtilities.checkName(projectName, "Project name");

		String path = checkLocalAbsolutePath(projectLocation, true);
		path = checkUncPathForURL(path);
		path += projectName;

		if (!StringUtils.isBlank(projectFilePath)) {
			if (!projectFilePath.startsWith("/") || projectFilePath.contains("\\")) {
				throw new IllegalArgumentException("Absolute path required using '/' delimiter");
			}
			checkValidProjectPath(projectFilePath, 1);
		}
		else {
			projectFilePath = null;
		}

		try {
			return new URI(GhidraURL.PROTOCOL, null, path, projectFilePath, encodeRefPlus(ref))
					.toURL();
		}
		catch (URISyntaxException | MalformedURLException e) {
			throw new IllegalArgumentException("Unable to form local project URL", e);
		}
	}

	/**
	 * Adjust a UNC path starting with exactly 2 forward slashes when used to form a URL.  
	 * This handles the case where the user has typed a UNC path (e.g., \\server\share).  
	 * We already converted backslashes to forward slashes, so we look for the converted path 
	 * here (e.g., //server/share).  If we find this case, we update the path to use 4 slashes, 
	 * which is used in the formation of a local Ghidra URL. 
	 * 
	 * @param path the path to check and adjust
	 * @return the potentially updated path
	 */
	private static String checkUncPathForURL(String path) {
		Matcher matcher = STARTS_WITH_TWO_FORWARD_SLASHES_PATTERN.matcher(path);
		if (matcher.matches()) {
			return "//" + path;
		}
		return path;
	}

	/**
	 * Create a URL which refers to a Ghidra project with optional project file and ref.
	 * If project locator corresponds to a transient project a server URL form will be returned.
	 * <p>
	 * Upon a successful URL connection, a {@link GhidraURLWrappedContent}
	 * content object will be provided from which {@link GhidraURLWrappedContent#getContent(Object)}
	 * may be invoked to obtain either the referenced {@link DomainFolder} or {@link DomainFile}.
	 * <p>
	 * NOTE: A proper {@link GhidraURLWrappedContent#release(Object, Object)} is mandatory after
	 * retrieving the wrapped content folder or file object.
	 * 
	 * @param projectLocator project locator (local or transient)
	 * @param projectFilePath file path (e.g., /a/b/c, may be null).  Folder paths should 
	 *            end with a '/' character.
	 * @param ref location reference (may be null)
	 * @return local Ghidra project URL
	 * @throws IllegalArgumentException if invalid {@code projectFilePath} specified or if URL 
	 *            instantiation fails.
	 */
	public static URL makeURL(ProjectLocator projectLocator, String projectFilePath, String ref) {
		return resolve(projectLocator.getURL(), projectFilePath, ref);
	}

	/**
	 * Create a URL which refers to Ghidra Server repository content.  Path may correspond 
	 * to either a file or folder.  
	 * <p>
	 * Upon a successful URL connection, a {@link GhidraURLWrappedContent}
	 * content object will be provided from which {@link GhidraURLWrappedContent#getContent(Object)}
	 * may be invoked to obtain either the referenced {@link DomainFolder} or {@link DomainFile}.
	 * <p>
	 * NOTE: A proper {@link GhidraURLWrappedContent#release(Object, Object)} is mandatory after
	 * retrieving the wrapped content folder or file object.
	 * 
	 * @param host server host name/address
	 * @param port optional server port (a value &lt;= 0 refers to the default port)
	 * @param repositoryName repository name
	 * @param repositoryPath absolute folder or file path within repository (may be null for root folder).
	 *            Folder paths should end with a '/' character.
	 * @return Ghidra Server repository content URL
	 */
	public static URL makeURL(String host, int port, String repositoryName, String repositoryPath) {
		return makeURL(host, port, repositoryName, repositoryPath, null);
	}

	/**
	 * Create a URL which refers to Ghidra Server repository content.  Path may correspond 
	 * to either a file or folder.  
	 * <p>
	 * Upon a successful URL connection, a {@link GhidraURLWrappedContent}
	 * content object will be provided from which {@link GhidraURLWrappedContent#getContent(Object)}
	 * may be invoked to obtain either the referenced {@link DomainFolder} or {@link DomainFile}.
	 * <p>
	 * NOTE: A proper {@link GhidraURLWrappedContent#release(Object, Object)} is mandatory after
	 * retrieving the wrapped content folder or file object.
	 * 
	 * @param host server host name/address
	 * @param port optional server port (a value &lt;= 0 refers to the default port)
	 * @param repositoryName repository name (required)
	 * @param repositoryPath absolute folder or file path within repository (may be null).
	 *            Folder paths should end with a '/' character.
	 * @param ref reference (may be null) 
	 * @return Ghidra Server repository content URL
	 * @throws IllegalArgumentException if arguments are specified which cannot be encoded into URL
	 */
	public static URL makeURL(String host, int port, String repositoryName, String repositoryPath,
			String ref) {
		if (StringUtils.isBlank(host)) {
			throw new IllegalArgumentException("host required");
		}
		if (StringUtils.isBlank(repositoryName)) {
			throw new IllegalArgumentException("repository name required");
		}
		NamingUtilities.checkName(repositoryName, "Repository name");
		if (port == 0 || port == GhidraServerHandle.DEFAULT_PORT) {
			port = -1;
		}
		String path = "/" + repositoryName;
		if (!StringUtils.isBlank(repositoryPath)) {
			if (!repositoryPath.startsWith("/") || repositoryPath.indexOf('\\') >= 0) {
				throw new IllegalArgumentException("Invalid repository path");
			}
			if (repositoryPath.length() != 1) {
				String checkPath = repositoryPath.substring(1);
				if (checkPath.endsWith("/")) {
					checkPath = checkPath.substring(0, checkPath.length() - 1);
				}
				checkValidProjectPath(checkPath, 0);
			}
			path += repositoryPath;
		}

		try {
			return new URI(PROTOCOL, null, host, port, path, null, encodeRefPlus(ref)).toURL();
		}
		catch (URISyntaxException | MalformedURLException e) {
			throw new IllegalArgumentException(e);
		}
	}

	/**
	 * Create a URL which refers to Ghidra Server repository content.  Path may correspond 
	 * to either a file or folder.  See {@link #makeURL(String, int, String, String, String)}
	 * for a slightly simpler form when working with just a project folder or file pathname. 
	 * <p>
	 * Upon a successful URL connection, a {@link GhidraURLWrappedContent}
	 * content object will be provided from which {@link GhidraURLWrappedContent#getContent(Object)}
	 * may be invoked to obtain either the referenced {@link DomainFolder} or {@link DomainFile}.
	 * <p>
	 * NOTE: A proper {@link GhidraURLWrappedContent#release(Object, Object)} is mandatory after
	 * retrieving the wrapped content folder or file object.
	 * 
	 * @param host server host name/address
	 * @param port optional server port (a value &lt;= 0 refers to the default port)
	 * @param repositoryName repository name (required)
	 * @param repositoryFolderPath absolute folder path within repository (required). 
	 * @param childName name of a file or folder contained within the specified 
	 * 			{@code repositoryFolderPath} (required)
	 * @param ref optional URL ref or null
	 * Folder paths should end with a '/' character.
	 * @return Ghidra Server repository content URL
	 * @throws IllegalArgumentException if required arguments are blank or invalid
	 */
	public static URL makeURL(String host, int port, String repositoryName,
			String repositoryFolderPath, String childName, String ref) {

		Objects.requireNonNull(repositoryFolderPath, "Folder path required");
		Objects.requireNonNull(childName, "Child name required");

		String path = repositoryFolderPath;
		if (!path.endsWith("/")) {
			path += "/";
		}
		path += childName;

		return makeURL(host, port, repositoryName, path, ref);
	}

	/**
	 * Create a URL which refers to Ghidra Server named repository and its root folder.
	 * <p>
	 * Upon a successful URL connection, a {@link GhidraURLWrappedContent}
	 * content object will be provided from which {@link GhidraURLWrappedContent#getContent(Object)}
	 * may be invoked to obtain the repository's root {@link DomainFolder}.
	 * <p>
	 * NOTE: A proper {@link GhidraURLWrappedContent#release(Object, Object)} is mandatory after
	 * retrieving the wrapped content folder.
	 * 
	 * @param host server host name/address
	 * @param port optional server port (a value &lt;= 0 refers to the default port)
	 * @param repositoryName repository name (required)
	 * @return Ghidra Server repository URL
	 */
	public static URL makeURL(String host, int port, String repositoryName) {
		return makeURL(host, port, repositoryName, null);
	}

	/**
	 * Create a URL which refers to Ghidra Server (i.e., no specific repository).
	 * Upon successful connection, the returned content type will be a 
	 * {@link RepositoryServerAdapter} instance.
	 * 
	 * @param host server host name/address
	 * @param port optional server port (a value &lt;= 0 refers to the default port)
	 * @return Ghidra Server URL
	 */
	public static URL makeURL(String host, int port) {
		try {
			return new URI(PROTOCOL, null, host, port, null, null, null).toURL();
		}
		catch (URISyntaxException | MalformedURLException e) {
			throw new IllegalArgumentException(e);
		}
	}

}
