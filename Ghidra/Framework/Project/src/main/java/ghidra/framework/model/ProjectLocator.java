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
	 * Construct a project locator object.
	 * @param path path to parent directory (may or may not exist).  The user's temp directory
	 * will be used if this value is null or blank.
	 * WARNING: Use of a relative paths should be avoided (e.g., on a windows platform
	 * an absolute path should start with a drive letter specification such as C:\path,
	 * while this same path on a Linux platform would be treated as relative).
	 * @param name name of the project
	 */
	public ProjectLocator(String path, String name) {
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
	 * Ensure that absolute path is specified.
	 * @param path path to be checked and possibly modified.
	 * @return path to be used
	 */
	private static String checkAbsolutePath(String path) {
		if (path.startsWith("/") && path.length() >= 4 && path.indexOf(":/") == 2 &&
			Character.isLetter(path.charAt(1))) {
			// strip leading "/" on Windows paths (e.g., /C:/mydir) and transform separators to '\'
			path = path.substring(1);
			path = path.replace('/', '\\');
		}
		if (path.endsWith("/") || path.endsWith("\\")) {
			path = path.substring(0, path.length() - 1);
		}
		return path;
	}

	/**
	 * Returns true if this project URL corresponds to a transient project
	 * (e.g., corresponds to remote Ghidra URL)
	 */
	public boolean isTransient() {
		return false;
	}

	/**
	 * Returns the URL associated with this local project.  If using a temporary transient
	 * project location this URL should not be used.
	 */
	public URL getURL() {
		return url;
	}

	/**
	 * Get the name of the project identified by this project info.
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
	 * Returns the project directory
	 */
	public File getProjectDir() {
		return new File(location, name + PROJECT_DIR_SUFFIX);
	}

	/**
	 * Returns the file that indicates a Ghidra project.
	 */
	public File getMarkerFile() {
		return new File(location, name + PROJECT_FILE_SUFFIX);
	}

	/**
	 * Returns project lock file to prevent multiple accesses to the
	 * same project at once.
	 */
	public File getProjectLockFile() {
		return new File(location, name + LOCK_FILE_SUFFIX);
	}

	/**
	 * Returns the project directory file extension.
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
	 * Returns the file extension suitable for creating file filters for the file chooser.
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
	 * Returns true if project storage exists
	 */
	public boolean exists() {
		return getMarkerFile().isFile() && getProjectDir().isDirectory();
	}

}
