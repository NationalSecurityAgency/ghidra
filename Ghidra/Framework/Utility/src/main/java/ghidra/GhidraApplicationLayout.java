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

		// Modules
		modules = findGhidraModules();

		// User directories
		userTempDir = ApplicationUtilities.getDefaultUserTempDir(getApplicationProperties());
		userCacheDir = ApplicationUtilities.getDefaultUserCacheDir(getApplicationProperties());
		userSettingsDir = ApplicationUtilities.getDefaultUserSettingsDir(getApplicationProperties(),
			getApplicationInstallationDir());

		// Extensions
		extensionInstallationDir = findExtensionInstallationDirectory();
		extensionArchiveDir = findExtensionArchiveDirectory();
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

		// Modules
		modules = findGhidraModules();

		// User directories
		userTempDir = ApplicationUtilities.getDefaultUserTempDir(getApplicationProperties());
		userCacheDir = ApplicationUtilities.getDefaultUserCacheDir(getApplicationProperties());
		userSettingsDir = ApplicationUtilities.getDefaultUserSettingsDir(getApplicationProperties(),
			getApplicationInstallationDir());
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
			ModuleUtilities.findModuleRootDirectories(applicationRootDirs, new ArrayList<>());

		// If Ghidra was launched from our Eclipse GhidraDev plugin, we want to add the
		// Eclipse module project (and it's dependent projects) to the list of module root 
		// directories so Ghidra can discover them.
		String eclipseProjectDirProperty = System.getProperty("eclipse.project.dir");
		if (eclipseProjectDirProperty != null && !eclipseProjectDirProperty.isEmpty()) {
			ResourceFile eclipseProjectDir = new ResourceFile(eclipseProjectDirProperty);
			if (ModuleUtilities.isModuleDirectory(eclipseProjectDir)) {
				moduleRootDirectories.add(eclipseProjectDir);
			}
		}
		String eclipseProjectDependencies = System.getProperty("eclipse.project.dependencies");
		if (eclipseProjectDependencies != null && !eclipseProjectDependencies.isEmpty()) {
			for (String path : eclipseProjectDependencies.split(File.pathSeparator)) {
				ResourceFile eclipseProjectDir = new ResourceFile(path);
				if (ModuleUtilities.isModuleDirectory(eclipseProjectDir)) {
					moduleRootDirectories.add(eclipseProjectDir);
				}
			}
		}

		return ModuleUtilities.findModules(applicationRootDirs, moduleRootDirectories);
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
	 * Returns the directory where all Ghidra extension archives should be
	 * installed. This should be at the following location:<br>
	 * <ul>
	 * <li><code>[application install dir]/Ghidra/Extensions</code></li>
	 * <li><code>ghidra/Ghidra/Extensions</code> (development mode)</li>
	 * </ul>
	 * 
	 * @return the install folder, or null if can't be determined
	 */
	protected ResourceFile findExtensionInstallationDirectory() {

		// Would like to find a better way to do this, but for the moment this seems the
		// only solution. We want to get the 'Extensions' directory in ghidra, but there's 
		// no way to retrieve that directory directly. We can only get the full set of 
		// application root dirs and search for it, hoping we don't encounter one with the
		// name 'Extensions' in one of the other root dirs.
		if (SystemUtilities.isInDevelopmentMode()) {
			ResourceFile rootDir = getApplicationRootDirs().iterator().next();
			File temp = new File(rootDir.getFile(false), "Extensions");
			if (temp.exists()) {
				return new ResourceFile(temp);
			}

			return null;
		}

		ResourceFile installDir = findGhidraApplicationInstallationDir();
		return new ResourceFile(installDir, "Ghidra/Extensions");
	}
}
