/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import ghidra.framework.protocol.ghidra.GhidraURL;

import java.io.File;
import java.net.URL;

/**
 * Lightweight descriptor of a local Project storage location.
 */
public class ProjectLocator {

	private static final String PROJECT_FILE_SUFFIX = ".gpr";
	private static final String PROJECT_DIR_SUFFIX = ".rep";
	private static final String LOCK_FILE_SUFFIX = ".lock";

	private String name;
	private String location;
	private URL url;

	/**
	 * Construct a project URL.
	 * @param path path to parent directory 
	 * @param name name of the project
	 */
	public ProjectLocator(String path, String name) {
		this.name = name;
		if (name.endsWith(PROJECT_FILE_SUFFIX)) {
			this.name = name.substring(0, name.length() - PROJECT_FILE_SUFFIX.length());
		}
		this.location = path;
		if (path == null) {
			this.location = System.getProperty("java.io.tmpdir");
		}
		this.url = GhidraURL.makeURL(location, name);
	}

	/**
	 * Returns true if this project URL corresponds to a transient project
	 * (e.g., corresponds to remote Ghidra URL)
	 */
	public boolean isTransient() {
		return false;
	}

	/**
	 * Returns the URL associated with this local project.
	 * If this is a transient project, a remote repository URL will be returned.
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
	 * Get the location of the project.
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

	/* (non-Javadoc)
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
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
		if (hashCode() != projectLocator.hashCode()) {
			return false;
		}
		return name.equals(projectLocator.name) && location.equals(projectLocator.location);
	}

	/* (non-Javadoc)
	 * @see java.lang.Object#hashCode()
	 */
	@Override
	public int hashCode() {
		return name.hashCode() + location.hashCode();
	}

	/* (non-Javadoc)
	 * @see java.lang.Object#toString()
	 */
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
