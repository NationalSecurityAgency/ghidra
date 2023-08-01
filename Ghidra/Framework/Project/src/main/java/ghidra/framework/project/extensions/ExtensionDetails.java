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
package ghidra.framework.project.extensions;

import java.io.File;
import java.util.List;

import generic.jar.ResourceFile;
import generic.json.Json;
import ghidra.framework.Application;
import ghidra.util.Msg;
import utilities.util.FileUtilities;
import utility.application.ApplicationLayout;
import utility.module.ModuleUtilities;

/**
 * Representation of a Ghidra extension. This class encapsulates all information required to
 * uniquely identify an extension and where (or if) it has been installed.
 * <p>
 * Note that hashCode and equals have been implemented for this. Two extension
 * descriptions are considered equal if they have the same {@link #name} attribute; all other
 * fields are unimportant except for display purposes.
 */
public class ExtensionDetails implements Comparable<ExtensionDetails> {

	/** Absolute path to where this extension is installed. If not installed, this will be null. */
	private File installDir;

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
	 * Returns the location where this extension is installed. If the extension is not installed 
	 * this will be null.
	 * 
	 * @return the extension path, or null
	 */
	public String getInstallPath() {
		if (installDir != null) {
			return installDir.getAbsolutePath();
		}
		return null;
	}

	public File getInstallDir() {
		return installDir;
	}

	public void setInstallDir(File installDir) {
		this.installDir = installDir;
	}

	/**
	 * Returns the location where the extension archive is located.  The extension archive concept
	 * is not used for all extensions, but is used for delivering extensions as part of a 
	 * distribution.
	 * 
	 * @return the archive path, or null
	 * @see ApplicationLayout#getExtensionArchiveDir()
	 */
	public String getArchivePath() {
		return archivePath;
	}

	public void setArchivePath(String path) {
		this.archivePath = path;
	}

	public boolean isFromArchive() {
		return archivePath != null;
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
	 * contains a Module.manifest file.   Extensions that are {@link #isPendingUninstall()} are 
	 * still on the filesystem, may be in use by the tool, but will be removed upon restart.
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
		if (installDir == null) {
			return false;
		}

		// If running out of a jar and the install path is valid, just return true. The alternative
		// would be to inspect the jar and verify that the install path is there and is valid, but
		// that's overkill.
		if (Application.inSingleJarMode()) {
			return true;
		}

		File f = new File(installDir, ModuleUtilities.MANIFEST_FILE_NAME);
		return f.exists();
	}

	/**
	 * Returns true if this extension is marked to be uninstalled.  The contents of the extension
	 * still exist and the tool may still be using the extension, but on restart, the extension will
	 * be removed.
	 * 
	 * @return true if marked for uninstall
	 */
	public boolean isPendingUninstall() {
		if (installDir == null) {
			return false;
		}

		if (Application.inSingleJarMode()) {
			return false; // can't uninstall from single jar mode
		}

		File f = new File(installDir, ModuleUtilities.MANIFEST_FILE_NAME_UNINSTALLED);
		return f.exists();
	}

	/**
	 * Returns true if this extension is installed under an installation folder or inside of a 
	 * source control repository folder.
	 * @return true if this extension is installed under an installation folder or inside of a 
	 * source control repository folder.
	 */
	public boolean isInstalledInInstallationFolder() {
		if (installDir == null) {
			return false; // not installed
		}

		ApplicationLayout layout = Application.getApplicationLayout();

		List<ResourceFile> extDirs = layout.getExtensionInstallationDirs();
		if (extDirs.size() < 2) {
			Msg.trace(this, "Unexpected extension installation dirs; revisit this assumption");
			return false;
		}

		// extDirs.get(0) is the user extension dir
		ResourceFile appExtDir = extDirs.get(1);
		if (FileUtilities.isPathContainedWithin(appExtDir.getFile(false), installDir)) {
			return true;
		}
		return false;
	}

	/**
	 * Converts the module manifest and extension properties file that are in an installed state to 
	 * an uninstalled state.
	 * 
	 * Specifically, the following will be renamed:
	 * <UL>
	 * <LI>Module.manifest to Module.manifest.uninstalled</LI>
	 * <LI>extension.properties = extension.properties.uninstalled</LI>
	 * </UL>
	 * 
	 * @return false if any renames fail
	 */
	public boolean markForUninstall() {

		if (installDir == null) {
			return false; // already marked as uninstalled
		}

		Msg.trace(this, "Marking extension for uninstall '" + installDir + "'");

		boolean success = true;
		File manifest = new File(installDir, ModuleUtilities.MANIFEST_FILE_NAME);
		if (manifest.exists()) {
			File newFile = new File(installDir, ModuleUtilities.MANIFEST_FILE_NAME_UNINSTALLED);
			if (!manifest.renameTo(newFile)) {
				Msg.trace(this, "Unable to rename module manifest file: " + manifest);
				success = false;
			}
		}
		else {
			Msg.trace(this, "No manifest file found for extension '" + name + "'");
		}

		File properties = new File(installDir, ExtensionUtils.PROPERTIES_FILE_NAME);
		if (properties.exists()) {
			File newFile = new File(installDir, ExtensionUtils.PROPERTIES_FILE_NAME_UNINSTALLED);
			if (!properties.renameTo(newFile)) {
				Msg.trace(this, "Unable to rename properties file: " + properties);
				success = false;
			}
		}
		else {
			Msg.trace(this, "No properties file found for extension '" + name + "'");
		}

		return success;
	}

	/**
	 * A companion method for {@link #markForUninstall()} that allows extensions marked for cleanup 
	 * to be restored to the installed state.
	 * <p>
	 * Specifically, the following will be renamed:
	 * <UL>
	 * <LI>Module.manifest.uninstalled to Module.manifest</LI>
	 * <LI>extension.properties.uninstalled to extension.properties</LI>
	 * </UL>
	 * @return true if successful
	 */
	public boolean clearMarkForUninstall() {

		if (installDir == null) {
			Msg.error(ExtensionUtils.class,
				"Cannot restore extension; extension installation dir is missing for: " + name);
			return false; // already marked as uninstalled
		}

		Msg.trace(this, "Restoring extension state files for '" + installDir + "'");

		boolean success = true;
		File manifest = new File(installDir, ModuleUtilities.MANIFEST_FILE_NAME_UNINSTALLED);
		if (manifest.exists()) {
			File newFile = new File(installDir, ModuleUtilities.MANIFEST_FILE_NAME);
			if (!manifest.renameTo(newFile)) {
				Msg.trace(this, "Unable to rename module manifest file: " + manifest);
				success = false;
			}
		}
		else {
			Msg.trace(this, "No manifest file found for extension '" + name + "'");
		}

		File properties = new File(installDir, ExtensionUtils.PROPERTIES_FILE_NAME_UNINSTALLED);
		if (properties.exists()) {
			File newFile = new File(installDir, ExtensionUtils.PROPERTIES_FILE_NAME);
			if (!properties.renameTo(newFile)) {
				Msg.trace(this, "Unable to rename properties file: " + properties);
				success = false;
			}
		}
		else {
			Msg.trace(this, "No properties file found for extension '" + name + "'");
		}

		return success;
	}

	@Override
	public int compareTo(ExtensionDetails other) {
		return name.compareTo(other.name);
	}

	@Override
	public String toString() {
		return Json.toString(this);
	}
}
