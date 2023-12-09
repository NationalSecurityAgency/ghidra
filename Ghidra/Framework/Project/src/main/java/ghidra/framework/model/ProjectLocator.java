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
package ghidra.framework.model;

import java.io.File;
import java.net.URL;
import java.util.Set;

import org.apache.commons.lang3.StringUtils;

import ghidra.framework.protocol.ghidra.GhidraURL;

/**
 * Lightweight descriptor of a local Project storage location.
 */
public class ProjectLocator {

	public static final String PROJECT_FILE_SUFFIX = ".gpr";
	public static final String PROJECT_DIR_SUFFIX = ".rep";

	private static final String LOCK_FILE_SUFFIX = ".lock";

	private final String name;
	private final String location;

	private URL url;

	/**
	 * Set of characters specifically disallowed in project name or path.
	 * These characters may interfere with path and URL parsing.
	 */
	public static Set<Character> DISALLOWED_CHARS = Set.of(':', ';', '&', '?', '#');

	/**
	 * Construct a project locator object.
	 * @param path absolute path to parent directory (may or may not exist).  The user's temp directory
	 * will be used if this value is null or blank.  The use of "\" characters will always be replaced 
	 * with "/".
	 * WARNING: Use of a relative paths should be avoided (e.g., on a windows platform
	 * an absolute path should start with a drive letter specification such as C:\path).
	 * A path such as "/path" on windows will utilize the current default drive and will
	 * not throw an exception.  If a drive letter is specified it must specify an absolute
	 * path (e.g., C:\, C:\path).
	 * @param name name of the project (may only contain alphanumeric characters or   
	 * @throws IllegalArgumentException if an absolute path is not specified or invalid project name
	 */
	public ProjectLocator(String path, String name) {
		if (name.contains("/") || name.contains("\\")) {
			throw new IllegalArgumentException("name contains path separator character: " + name);
		}
		checkInvalidChar("name", name, 0);
		if (name.endsWith(PROJECT_FILE_SUFFIX)) {
			name = name.substring(0, name.length() - PROJECT_FILE_SUFFIX.length());
		}
		this.name = name;
		if (StringUtils.isBlank(path)) {
			path = System.getProperty("java.io.tmpdir");
		}
		this.location = checkAbsolutePath(path);
		url = GhidraURL.makeURL(location, name);
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
			if (DISALLOWED_CHARS.contains(c)) {
				throw new IllegalArgumentException(
					type + " contains invalid character: '" + c + "'");
			}
		}
	}

	/**
	 * Ensure that absolute path is specified and normalize its format.
	 * An absolute path may start with a windows drive letter (e.g., c:/a/b, /c:/a/b)
	 * or without (e.g., /a/b).  Although for Windows the lack of a drive letter is
	 * not absolute, for consistency with Linux we permit this form which on
	 * Windows will use the default drive for the process. The resulting path
	 * may be transormed to always end with a "/" and if started with a drive letter
	 * (e.g., "c:/") it will have a "/" prepended (e.g., "/c:/", both forms
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
		if (!path.endsWith("/")) {
			path += "/";
		}
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
	 * @returns true if this project URL corresponds to a transient project
	 * (e.g., corresponds to remote Ghidra URL)
	 */
	public boolean isTransient() {
		return false;
	}

	/**
	 * @returns the URL associated with this local project.  If using a temporary transient
	 * project location this URL should not be used.
	 */
	public URL getURL() {
		return url;
	}

	/**
	 * @returns the name of the project identified by this project info.
	 */
	public String getName() {
		return name;
	}

	/**
	 * Get the location of the project which will contain marker file
	 * ({@link #getMarkerFile()}) and project directory ({@link #getProjectDir()}). 
	 * Note: directory may or may not exist.
	 * @return project location directory
	 */
	public String getLocation() {
		return location;
	}

	/**
	 * @returns the project directory
	 */
	public File getProjectDir() {
		return new File(location, name + PROJECT_DIR_SUFFIX);
	}

	/**
	 * @returns the file that indicates a Ghidra project.
	 */
	public File getMarkerFile() {
		return new File(location, name + PROJECT_FILE_SUFFIX);
	}

	/**
	 * @returns project lock file to prevent multiple accesses to the
	 * same project at once.
	 */
	public File getProjectLockFile() {
		return new File(location, name + LOCK_FILE_SUFFIX);
	}

	/**
	 * @returns the project directory file extension.
	 */
	public static String getProjectDirExtension() {
		return PROJECT_DIR_SUFFIX;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == null) {
			return false;
		}
		if (obj == this) {
			return true;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		ProjectLocator projectLocator = (ProjectLocator) obj;
		return name.equals(projectLocator.name) && location.equals(projectLocator.location);
	}

	@Override
	public int hashCode() {
		return name.hashCode() + location.hashCode();
	}

	@Override
	public String toString() {
		return GhidraURL.getDisplayString(url);
	}

	/**
	 * @returns the file extension suitable for creating file filters for the file chooser.
	 */
	public static String getProjectExtension() {
		return PROJECT_FILE_SUFFIX;
	}

	/**
	 * Returns whether the given file is a project directory.
	 * @param file file to check
	 * @return  true if the file is a project directory 
	 */
	public static boolean isProjectDir(File file) {
		return file.isDirectory() && file.getName().endsWith(PROJECT_DIR_SUFFIX);
	}

	/**
	 * @returns true if project storage exists
	 */
	public boolean exists() {
		return getMarkerFile().isFile() && getProjectDir().isDirectory();
	}

}
