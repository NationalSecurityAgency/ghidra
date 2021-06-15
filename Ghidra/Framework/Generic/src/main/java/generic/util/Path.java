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
package generic.util;

import java.io.File;

import generic.jar.ResourceFile;
import ghidra.framework.Application;
import ghidra.framework.OperatingSystem;

/**
 * A class to represent a PATH item.
 */
public class Path implements Comparable<Path> {
	public static final String GHIDRA_HOME = "$GHIDRA_HOME";
	public static final String USER_HOME = "$USER_HOME";
	private ResourceFile file;
	private boolean isEnabled;
	private boolean isEditable;
	private boolean isReadOnly;

	/**
	 * Identifies an absolute directory path which has the following attributes:
	 * <ul>
	 * <li>isEnabled = true</li>
	 * <li>isEditable = true</li>
	 * <li>isReadOnly = false</li>
	 * </ul>
	 * @param file absolute directory path
	 */
	public Path(File file) {
		this(new ResourceFile(file), true, true, false);
	}

	/**
	 * Identifies an absolute directory path which has the following attributes:
	 * <ul>
	 * <li>isEnabled = true</li>
	 * <li>isEditable = true</li>
	 * <li>isReadOnly = false</li>
	 * </ul>
	 * @param file absolute directory path
	 */
	public Path(ResourceFile file) {
		this(file, true, true, false);
	}

	/**
	 * Identifies an absolute directory path with the specified attributes.
	 * @param file absolute directory path
	 * @param isEnabled directory path will be searched if true
	 * @param isEditable if true files contained within directory are considered editable
	 * @param isReadOnly if true files contained within directory are considered read-only
	 */
	public Path(ResourceFile file, boolean isEnabled, boolean isEditable, boolean isReadOnly) {
		this.file = file;
		this.isEnabled = isEnabled;
		this.isEditable = isEditable;
		this.isReadOnly = isReadOnly;
	}

	/**
	 * Identifies an absolute directory path which has the following attributes:
	 * <ul>
	 * <li>isEnabled = true</li>
	 * <li>isEditable = true</li>
	 * <li>isReadOnly = false</li>
	 * </ul>
	 * @param path absolute directory path
	 */
	public Path(String path) {
		this(path, true, true, false);
	}

	/**
	 * Identifies an absolute directory path which has the following attributes:
	 * <ul>
	 * <li>isEditable = true</li>
	 * <li>isReadOnly = false</li>
	 * </ul>
	 * @param path absolute directory path
	 * @param enabled directory path will be searched if true
	 */
	public Path(String path, boolean enabled) {
		this(path, enabled, true, false);
	}

	/**
	 * Identifies an absolute directory path with the specified attributes.
	 * @param path absolute directory path
	 * @param isEnabled directory path will be searched if true
	 * @param isEditable if true files contained within directory are considered editable
	 * @param isReadOnly if true files contained within directory are considered read-only
	 */
	public Path(String path, boolean isEnabled, boolean isEditable, boolean isReadOnly) {
		this.file = fromPathString(path);

		this.isEnabled = isEnabled;
		this.isEditable = isEditable;
		this.isReadOnly = isReadOnly;
	}

	static private ResourceFile resolveGhidraHome(String scriptPath) {
		ResourceFile pathFile = null;
		for (ResourceFile root : Application.getApplicationRootDirectories()) {
			int length = GHIDRA_HOME.length();
			String relativePath = scriptPath.substring(length);
			pathFile = new ResourceFile(root, relativePath);
			if (pathFile.exists()) {
				return pathFile;
			}
		}
		return pathFile;// return the last one even if it doesn't exist.
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof Path)) {
			return false;
		}
		Path that = (Path) obj;
		return this.file.equals(that.file);
	}

	@Override
	public int hashCode() {
		return file.hashCode();
	}

	/**
	 * Returns true if this path is read-only, which
	 * indicates the path cannot be written.
	 * @return true if this path is read-only
	 */
	public boolean isReadOnly() {
		return isReadOnly;
	}

	/**
	 * Returns true if this path can be modified.
	 * @return true if this path can be modified
	 */
	public boolean isEditable() {
		return isEditable;
	}

	/**
	 * Returns true if this path is enabled.
	 * Enablement indicates the path should be used.
	 * @return true if this path is enabled
	 */
	public boolean isEnabled() {
		return isEnabled;
	}

	public void setEnabled(boolean isEnabled) {
		this.isEnabled = isEnabled;
	}

	public ResourceFile getPath() {
		return file;
	}

	/**
	 * Parse the path string <b>with path element placeholders</b>, such as 
	 * {@link #GHIDRA_HOME}.
	 * @param path the path
	 * 
	 * @return the path as a ResourceFile.
	 */
	public static ResourceFile fromPathString(String path) {
		ResourceFile resourceFile = null;
		if (path.startsWith(GHIDRA_HOME)) {
			resourceFile = resolveGhidraHome(path);
		}
		else if (path.startsWith(USER_HOME)) {
			String userHome = System.getProperty("user.home");
			int length = USER_HOME.length();
			String relativePath = path.substring(length);
			resourceFile = new ResourceFile(new File(userHome + relativePath));
		}
		else {
			resourceFile = new ResourceFile(path);
		}
		if (OperatingSystem.CURRENT_OPERATING_SYSTEM == OperatingSystem.WINDOWS) {
			resourceFile = resourceFile.getCanonicalFile();
		}

		return resourceFile;
	}

	/**
	 * Returns the path as a string <b>with path element placeholders</b>, such as 
	 * {@link #GHIDRA_HOME}.
	 * 
	 * @param file the file to translate
	 * @return the path as a string .
	 */
	static public String toPathString(ResourceFile file) {
		String userHome = System.getProperty("user.home");
		String absolutePath = file.getAbsolutePath();
		for (ResourceFile appRoot : Application.getApplicationRootDirectories()) {
			String ghidraHome = appRoot.getAbsolutePath();
			if (absolutePath.startsWith(ghidraHome)) {
				int length = ghidraHome.length();
				String relativePath = absolutePath.substring(length);
				absolutePath = GHIDRA_HOME + relativePath;
				return absolutePath.replace('\\', '/');
			}
		}

		if (absolutePath.startsWith(userHome)) {
			int length = userHome.length();
			String relativePath = absolutePath.substring(length);
			absolutePath = USER_HOME + relativePath;
			return absolutePath.replace('\\', '/');
		}

		return absolutePath.replace('\\', '/');
	}

	/**
	 * Returns the path as a string <b>with path element placeholders</b>, such as 
	 * {@link #GHIDRA_HOME}.
	 * 
	 * @return the path as a string .
	 */
	public String getPathAsString() {
		return toPathString(file);
	}

	/** 
	 * Returns true if the given path is a file inside of the current Ghidra application.
	 * @return true if the given path is a file inside of the current Ghidra application.
	 */
	public boolean isInstallationFile() {
		String pathAsString = getPathAsString();
		return pathAsString.contains(GHIDRA_HOME);
	}

	public void setPath(String path) {
		if (isEditable) {
			this.file = new ResourceFile(path);
		}
		else {
			throw new IllegalStateException("Path is not editable - " + path);
		}
	}

	public void setPath(ResourceFile file) {
		if (isEditable) {
			this.file = file;
		}
		else {
			throw new IllegalStateException("Path is not editable - " + file);
		}
	}

	public boolean exists() {
		return file.exists();
	}

	@Override
	public String toString() {
		return getPathAsString();
	}

	@Override
	public int compareTo(Path p) {
		return getPathAsString().compareTo(p.getPathAsString());
	}
}
