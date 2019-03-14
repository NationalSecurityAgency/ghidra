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
package ghidra.framework.plugintool.dialog;

import java.io.File;

import ghidra.framework.Application;
import utility.module.ModuleUtilities;

/**
 * Representation of a Ghidra extension. This class encapsulates all information required to 
 * uniquely identify an extension and where (or if) it has been installed.
 * <p>
 * Note that hashCode and equals have been implemented for this. Two extension
 * descriptions are considered equal if they have the same {@link #name} attribute; all other
 * fields are unimportant save for display purposes.
 *
 */
public class ExtensionDetails implements Comparable<ExtensionDetails> {

	/** Absolute path to where this extension is installed. If not installed, this will be null. */
	private String installPath;

	/** 
	 * Absolute path to where the original source archive (zip) for this extension can be found. If 
	 * there is no archive (likely because this is an extension that comes pre-installed with
	 * Ghidra, or Ghidra is being run in development mode), this will be null. 
	 */
	private String archivePath;

	/** Name of the extension. This must be unique.*/
	private String name;

	/** Brief description, for display purposes only.*/
	private String description;

	/** Date when the extension was created, for display purposes only.*/
	private String createdOn;

	/** Author of the extension, for display purposes only.*/
	private String author;

	/** The extension version */
	private String version;

	/**
	 * Constructor.
	 * 
	 * @param name unique name of the extension; cannot be null
	 * @param description brief explanation of what the extension does; can be null
	 * @param author creator of the extension; can be null
	 * @param createdOn creation date of the extension, can be null
	 * @param version the extension version
	 */
	public ExtensionDetails(String name, String description, String author, String createdOn,
			String version) {
		this.name = name;
		this.description = description;
		this.author = author;
		this.createdOn = createdOn;
		this.version = version;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((name == null) ? 0 : name.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		ExtensionDetails other = (ExtensionDetails) obj;
		if (name == null) {
			if (other.name != null) {
				return false;
			}
		}
		else if (!name.equals(other.name)) {
			return false;
		}
		return true;
	}

	/**
	 * Returns the location where this extension is installed. If the extension is 
	 * not installed this will be null.
	 * 
	 * @return the extension path, or null
	 */
	public String getInstallPath() {
		return installPath;
	}

	public void setInstallPath(String path) {
		this.installPath = path;
	}

	/**
	 * Returns the location where the extension archive is located. If there is no 
	 * archive this will be null.
	 * 
	 * @return the archive path, or null
	 */
	public String getArchivePath() {
		return archivePath;
	}

	public void setArchivePath(String path) {
		this.archivePath = path;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getDescription() {
		return description;
	}

	public void setDescription(String description) {
		this.description = description;
	}

	public String getAuthor() {
		return author;
	}

	public void setAuthor(String author) {
		this.author = author;
	}

	public String getCreatedOn() {
		return createdOn;
	}

	public void setCreatedOn(String date) {
		this.createdOn = date;
	}

	public String getVersion() {
		return version;
	}

	public void setVersion(String version) {
		this.version = version;
	}

	/**
	 * An extension is known to be installed if it has a valid installation path AND that path
	 * contains a Module.manifest file. 
	 * <p>
	 * Note: The module manifest file is a marker that indicates several things; one of which is
	 * the installation status of an extension. When a user marks an extension to be uninstalled (by
	 * checking the appropriate checkbox in the {@link ExtensionTableModel}), the only thing
	 * that is done is to remove this manifest file, which tells the {@link ExtensionTableProvider}
	 * to remove the entire extension directory on the next launch.
	 * 
	 * @return true if the extension is installed.
	 */
	public boolean isInstalled() {
		if (installPath == null || installPath.isEmpty()) {
			return false;
		}
		
		// If running out of a jar and the install path is valid, just return true. The alternative
		// would be to inspect the jar and verify that the install path is there and is valid, but that's
		// overkill.
		if (Application.inSingleJarMode()) {
			return true;
		}

		File mm = new File(installPath, ModuleUtilities.MANIFEST_FILE_NAME);
		return mm.exists();
	}

	@Override
	public int compareTo(ExtensionDetails other) {
		return name.compareTo(other.name);
	}
}
