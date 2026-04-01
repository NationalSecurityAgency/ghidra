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
import java.io.IOException;
import java.net.URL;

import org.apache.commons.lang3.StringUtils;

import ghidra.framework.Application;
import ghidra.framework.OperatingSystem;
import ghidra.framework.protocol.ghidra.GhidraURL;
import ghidra.util.NamingUtilities;
import ghidra.util.exception.NotFoundException;

/**
 * Lightweight descriptor of a local Project storage location.
 */
public class ProjectLocator {

	public static final String PROJECT_FILE_SUFFIX = ".gpr";
	public static final String PROJECT_DIR_SUFFIX = ".rep";

	private static final String LOCK_FILE_SUFFIX = ".lock";

	private final String name;
	private final String location;
	private final boolean isWindowsOnlyLocation; // drive letter or UNC path specified 

	private URL url;

	/**
	 * Construct a project locator object.
	 * @param path absolute path to parent directory (may or may not exist).  The user's temp directory
	 * will be used if this value is null or blank.  The use of "\" characters will always be replaced 
	 * with "/".  A path starting with either "//" or "\\" will be treated as a Windows UNC path.
	 * WARNING: Use of a relative paths should be avoided (e.g., on a windows platform
	 * an absolute path should start with a drive letter specification such as C:\path).
	 * A path such as "/path" on windows will utilize the current default drive and will
	 * not throw an exception.  If a drive letter is specified it must specify an absolute
	 * path (e.g., C:\, C:\path).
	 * @param name name of the project (may only contain alphanumeric characters or   
	 * @throws IllegalArgumentException if an absolute path is not specified or invalid project name
	 */
	public ProjectLocator(String path, String name) throws IllegalArgumentException {
		this(path, name, null);
	}

	protected ProjectLocator(String path, String name, URL url) throws IllegalArgumentException {
		if (name.contains("/") || name.contains("\\")) {
			throw new IllegalArgumentException("name contains path separator character: " + name);
		}
		NamingUtilities.checkProjectName(name);
		if (name.endsWith(PROJECT_FILE_SUFFIX)) {
			name = name.substring(0, name.length() - PROJECT_FILE_SUFFIX.length());
		}
		this.name = name;
		if (StringUtils.isBlank(path)) {
			path = Application.getUserTempDirectory().getAbsolutePath();
		}
		location = GhidraURL.checkLocalAbsolutePath(path, true);
		isWindowsOnlyLocation = GhidraURL.isWindowsOnlyPath(location);
		this.url = url != null ? url : GhidraURL.makeURL(location, name);
	}

	/**
	 * {@return true if this project URL corresponds to a transient project
	 * (e.g., corresponds to remote Ghidra URL)}
	 */
	public boolean isTransient() {
		return false;
	}

	/**
	 * {@return the URL associated with this local project.}
	 * If using a temporary transient project location this URL will refer to the 
	 * remote server repository.
	 */
	public URL getURL() {
		return url;
	}

	/**
	 * {@return the name of the project identified by this project info.}
	 */
	public String getName() {
		return name;
	}

	/**
	 * Get the absolute path of the directory which contains the project marker file
	 * ({@link #getMarkerFile()}) and project directory ({@link #getProjectDir()})
	 * (i.e., parent directory). 
	 * <p>
	 * Directory path will always use '/' as a path separator and may have one of the following 
	 * forms:
	 * <ul>
	 * <li>Standard path:  /a/b/</li>
	 * <li>Windows path: /C:/a/b</li>
	 * <li>Windows UNC path: //server/share/a/b</li>
	 * </ul>
	 * <p>	
	 * Note: directory may or may not exist.
	 * @return project location directory
	 */
	public String getLocation() {
		return location;
	}

	/**
	 * {@return true if this project location is only valid on a Windows platform.}
	 */
	public boolean isWindowsOnlyLocation() {
		return isWindowsOnlyLocation;
	}

	private File getParentDir() {
		return new File(location);
	}

	/**
	 * Get the project storage directory associated with this project locator.
	 * <p>
	 * NOTE: {@link #exists()} or {@link #checkProjectExistence()} method should be used prior to the 
	 * returned file.
	 * 
	 * @return the project directory
	 */
	public File getProjectDir() {
		return new File(getParentDir(), name + PROJECT_DIR_SUFFIX);
	}

	/**
	 * Get the project marker file associated with this project locator.
	 * <p>
	 * NOTE: {@link #exists()} or {@link #checkProjectExistence()} method should be used prior to the 
	 * returned file.
	 * 
	 * @return the marker file that indicates a Ghidra project.
	 */
	public File getMarkerFile() {
		return new File(getParentDir(), name + PROJECT_FILE_SUFFIX);
	}

	/**
	 * {@return project lock file to prevent multiple accesses to the same project at once.}
	 */
	public File getProjectLockFile() {
		return new File(getParentDir(), name + LOCK_FILE_SUFFIX);
	}

	/**
	 * {@return the project directory file extension.}
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
		return url.equals(projectLocator.getURL());
	}

	@Override
	public int hashCode() {
		return url.hashCode();
	}

	@Override
	public String toString() {
		return GhidraURL.getDisplayString(url);
	}

	/**
	 * {@return the file extension suitable for creating file filters for the file chooser}
	 */
	public static String getProjectExtension() {
		return PROJECT_FILE_SUFFIX;
	}

	/**
	 * {@return whether the given file is a project directory.}
	 * @param file file to check
	 */
	public static boolean isProjectDir(File file) {
		return file.isDirectory() && file.getName().endsWith(PROJECT_DIR_SUFFIX);
	}

	/**
	 * Determine if the project exists.
	 * <p>
	 * IMPORTANT: This method or {@link #checkProjectExistence()} method should always be used prior to 
	 * using File object returned by {@link #getParentDir()}, {@link #getMarkerFile()} or 
	 * {@link #getProjectLockFile()} since OS-specific checks are performed which may not
	 * be considered when using the returned File objects.
	 * 
	 * @return true if project storage exists.
	 */
	public boolean exists() {
		if (isWindowsOnlyLocation &&
			OperatingSystem.CURRENT_OPERATING_SYSTEM != OperatingSystem.WINDOWS) {
			// Do not try to evaluate a Windows-only path on other platforms
			return false;
		}
		return getMarkerFile().isFile() && getProjectDir().isDirectory();
	}

	/**
	 * Verify that this project exists with its required marker file and data storage directory.
	 * <p>
	 * IMPORTANT: This method or {@link #exists()} method should always be used prior to 
	 * using File object returned by {@link #getParentDir()}, {@link #getMarkerFile()} or 
	 * {@link #getProjectLockFile()} since OS-specific checks are performed which may not
	 * be considered when using the returned File objects.
	 * 
	 * @throws NotFoundException if project does not exist
	 */
	public void checkProjectExistence() throws NotFoundException {
		if (isWindowsOnlyLocation &&
			OperatingSystem.CURRENT_OPERATING_SYSTEM != OperatingSystem.WINDOWS) {
			throw new NotFoundException(
				"The project location is only valid on Windows: " + location);
		}

		File markerFile = getMarkerFile();
		if (!markerFile.isFile()) {
			throw new NotFoundException("Project marker file not found: " + markerFile);
		}

		File projectDir = getProjectDir();
		if (!projectDir.isDirectory()) {
			throw new NotFoundException("Project directory not found: " + projectDir);
		}
	}

	/**
	 * Verify that the specified project location directory exists in preparation for creating
	 * a new project.
	 * <p>
	 * IMPORTANT: This method or {@link #exists()} method should always be used prior to 
	 * using File object returned by {@link #getParentDir()}, {@link #getMarkerFile()} or 
	 * {@link #getProjectLockFile()} since OS-specific checks are performed which may not
	 * be considered when using the returned File objects.
	 * 
	 * @throws IOException if project location does not exist
	 */
	public void checkLocationExistence() throws IOException {
		if (isWindowsOnlyLocation &&
			OperatingSystem.CURRENT_OPERATING_SYSTEM != OperatingSystem.WINDOWS) {
			throw new IOException("The project location is only valid on Windows: " + location);
		}

		File dir = getParentDir();
		if (!dir.isDirectory()) {
			throw new IOException("Project location not found: " + dir);
		}
	}
}
