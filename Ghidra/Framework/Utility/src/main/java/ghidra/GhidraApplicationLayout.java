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
package ghidra;

import java.io.*;
import java.util.*;

import generic.jar.ResourceFile;
import ghidra.framework.ApplicationProperties;
import ghidra.framework.GModule;
import ghidra.util.SystemUtilities;
import utilities.util.FileUtilities;
import utility.application.ApplicationLayout;
import utility.application.ApplicationUtilities;
import utility.module.ModuleUtilities;

/**
 * The Ghidra application layout defines the customizable elements of the Ghidra
 * application's directory structure.
 */
public class GhidraApplicationLayout extends ApplicationLayout {

	/**
	 * Constructs a new Ghidra application layout object.
	 * 
	 * @throws FileNotFoundException if there was a problem getting a user
	 *             directory.
	 * @throws IOException if there was a problem getting the application
	 *             properties or modules.
	 */
	public GhidraApplicationLayout() throws FileNotFoundException, IOException {

		// Application root directories
		applicationRootDirs = findGhidraApplicationRootDirs();

		// Application properties
		applicationProperties = new ApplicationProperties(applicationRootDirs);

		// Application installation directory
		applicationInstallationDir = findGhidraApplicationInstallationDir();


		// User directories
		userTempDir = ApplicationUtilities.getDefaultUserTempDir(getApplicationProperties());
		userCacheDir = ApplicationUtilities.getDefaultUserCacheDir(getApplicationProperties());
		userSettingsDir = ApplicationUtilities.getDefaultUserSettingsDir(getApplicationProperties(),
			getApplicationInstallationDir());

		// Extensions
		extensionInstallationDirs = findExtensionInstallationDirectories();
		extensionArchiveDir = findExtensionArchiveDirectory();

		// Patch directory
		patchDir = findPatchDirectory();

		// Modules
		modules = findGhidraModules();
	}

	/**
	 * Constructs a new Ghidra application layout object using a provided
	 * application installation directory instead of this layout's default.
	 * <p>
	 * This is used when something external to Ghidra needs Ghidra's layout
	 * (like the Eclipse GhidraDevPlugin).
	 * 
	 * @param applicationInstallationDir The application installation directory.
	 * @throws FileNotFoundException if there was a problem getting a user
	 *             directory.
	 * @throws IOException if there was a problem getting the application
	 *             properties.
	 */
	public GhidraApplicationLayout(File applicationInstallationDir)
			throws FileNotFoundException, IOException {

		// Application installation directory
		this.applicationInstallationDir = new ResourceFile(applicationInstallationDir);

		// Application root directories
		applicationRootDirs =
			Arrays.asList(new ResourceFile(this.applicationInstallationDir, "Ghidra"));

		// Application properties
		applicationProperties = new ApplicationProperties(applicationRootDirs);

		// User directories
		userTempDir = ApplicationUtilities.getDefaultUserTempDir(getApplicationProperties());
		userCacheDir = ApplicationUtilities.getDefaultUserCacheDir(getApplicationProperties());
		userSettingsDir = ApplicationUtilities.getDefaultUserSettingsDir(getApplicationProperties(),
			getApplicationInstallationDir());
		
		// Extensions
		extensionInstallationDirs = findExtensionInstallationDirectories();
		extensionArchiveDir = findExtensionArchiveDirectory();

		// Patch directory
		patchDir = findPatchDirectory();
		
		// Modules
		modules = findGhidraModules();
	}

	/**
	 * Finds the application root directories for this application layout.
	 * 
	 * @return A collection of the application root directories for this layout.
	 */
	protected Collection<ResourceFile> findGhidraApplicationRootDirs() {
		return ApplicationUtilities.findDefaultApplicationRootDirs();
	}

	/**
	 * Finds the application installation directory for this Ghidra application
	 * layout.
	 * 
	 * @return The application installation directory for this Ghidra
	 *         application layout. Could be null if there is no application
	 *         installation directory.
	 */
	protected ResourceFile findGhidraApplicationInstallationDir() {
		if (applicationRootDirs.isEmpty()) {
			return null;
		}

		ResourceFile dir = applicationRootDirs.iterator().next().getParentFile();
		if (SystemUtilities.isInDevelopmentMode()) {
			dir = dir.getParentFile();
		}
		return dir;
	}

	/**
	 * Finds the modules for this Ghidra application layout.
	 * 
	 * @return The modules for this Ghidra application layout.
	 * @throws IOException if there was a problem finding the modules on disk.
	 */
	protected Map<String, GModule> findGhidraModules() throws IOException {

		// Find standard module root directories from within the application root directories
		Collection<ResourceFile> moduleRootDirectories =
			ModuleUtilities.findModuleRootDirectories(applicationRootDirs, new LinkedHashSet<>());

		// Find installed extension modules
		for (ResourceFile extensionInstallDir : extensionInstallationDirs) {
			File[] extensionModuleDirs =
				extensionInstallDir.getFile(false).listFiles(d -> d.isDirectory());
			if (extensionModuleDirs != null) {
				for (File extensionModuleDir : extensionModuleDirs) {

					// Skip extensions that live in an application root directory...we've already 
					// found those.
					if (applicationRootDirs.stream()
							.anyMatch(dir -> FileUtilities.isPathContainedWithin(dir.getFile(false),
								extensionModuleDir))) {
						continue;
					}
					// Skip extensions slated for cleanup
					if (new File(extensionModuleDir, ModuleUtilities.MANIFEST_FILE_NAME_UNINSTALLED)
							.exists()) {
						continue;
					}

					moduleRootDirectories.add(new ResourceFile(extensionModuleDir));
				}
			}
		}

		// Examine the classpath to look for modules outside of the application root directories.
		// These might exist if Ghidra was launched from an Eclipse project that resides
		// external to the Ghidra installation.
		for (String entry : System.getProperty("java.class.path", "").split(File.pathSeparator)) {
			final ResourceFile classpathEntry = new ResourceFile(entry);

			// We only care about directories (skip jars)
			if (!classpathEntry.isDirectory()) {
				continue;
			}

			// Skip classpath entries that live in an application root directory...we've already
			// found those.
			if (applicationRootDirs.stream()
					.anyMatch(dir -> FileUtilities.isPathContainedWithin(
						dir.getFile(false), classpathEntry.getFile(false)))) {
				continue;
			}

			// We are going to assume that the classpath entry is in a subdirectory of the module
			// directory (i.e., bin/), so only check parent directory for the module.
			ResourceFile classpathEntryParent = classpathEntry.getParentFile();
			if (classpathEntryParent != null &&
				ModuleUtilities.isModuleDirectory(classpathEntryParent)) {
				moduleRootDirectories.add(classpathEntryParent);
			}
		}

		return ModuleUtilities.findModules(applicationRootDirs, moduleRootDirectories);
	}

	/**
	 * Returns the directory that allows users to add jar and class files to override existing
	 * distribution files
	 * @return the patch dir; null if not in a distribution
	 */
	protected ResourceFile findPatchDirectory() {

		if (SystemUtilities.isInDevelopmentMode()) {
			return null;
		}

		if (applicationInstallationDir == null) {
			return null;
		}

		return new ResourceFile(applicationInstallationDir, "Ghidra/patch");
	}

	/**
	 * Returns the directory where all Ghidra extension archives are stored.
	 * This should be at the following location:<br>
	 * <ul>
	 * <li><code>[application root]/Extensions/Ghidra</code></li>
	 * </ul>
	 * 
	 * @return the archive folder, or null if can't be determined
	 */
	protected ResourceFile findExtensionArchiveDirectory() {

		if (SystemUtilities.isInDevelopmentMode()) {
			return null;
		}

		if (applicationInstallationDir == null) {
			return null;
		}
		return new ResourceFile(applicationInstallationDir, "Extensions/Ghidra");
	}

	/**
	 * Returns a prioritized list of directories where Ghidra extensions are installed. These 
	 * should be at the following locations:<br>
	 * <ul>
	 * <li><code>[user settings dir]/Extensions</code></li>
	 * <li><code>[application install dir]/Ghidra/Extensions</code></li>
	 * <li><code>ghidra/Ghidra/Extensions</code> (development mode)</li>
	 * </ul>
	 * 
	 * @return the install folder, or null if can't be determined
	 */
	protected List<ResourceFile> findExtensionInstallationDirectories() {

		List<ResourceFile> dirs = new ArrayList<>();
		
		// Would like to find a better way to do this, but for the moment this seems the
		// only solution. We want to get the 'Extensions' directory in ghidra, but there's 
		// no way to retrieve that directory directly. We can only get the full set of 
		// application root dirs and search for it, hoping we don't encounter one with the
		// name 'Extensions' in one of the other root dirs.
		if (SystemUtilities.isInDevelopmentMode()) {
			ResourceFile rootDir = getApplicationRootDirs().iterator().next();
			File temp = new File(rootDir.getFile(false), "Extensions");
			if (temp.exists()) {
				dirs.add(new ResourceFile(temp));
			}
		}
		else {
			dirs.add(new ResourceFile(new File(userSettingsDir, "Extensions")));
			dirs.add(new ResourceFile(applicationInstallationDir, "Ghidra/Extensions"));
		}

		return dirs;
	}
}
