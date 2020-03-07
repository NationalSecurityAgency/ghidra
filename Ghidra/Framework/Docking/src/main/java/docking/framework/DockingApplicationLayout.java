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
package docking.framework;

import java.io.FileNotFoundException;
import java.util.ArrayList;
import java.util.Objects;

import generic.jar.ResourceFile;
import ghidra.framework.ApplicationProperties;
import ghidra.util.SystemUtilities;
import utility.application.ApplicationLayout;
import utility.application.ApplicationUtilities;
import utility.module.ModuleUtilities;

/**
 * The docking application layout defines the customizable elements of a docking application's 
 * directory structure.
 */
public class DockingApplicationLayout extends ApplicationLayout {

	private static final String NO_RELEASE_NAME = "NO_RELEASE";

	/**
	 * Constructs a new docking application layout object with the given name.
	 * 
	 * @param name The name of the application.
	 * @throws FileNotFoundException if there was a problem getting a user directory.
	 */
	public DockingApplicationLayout(String name) throws FileNotFoundException {
		this(name, "0.1");
	}

	/**
	 * Constructs a new docking application layout object with the given name and version.
	 * 
	 * @param name The name of the application.
	 * @param version The version of the application.
	 * @throws FileNotFoundException if there was a problem getting a user directory.
	 */
	public DockingApplicationLayout(String name, String version) throws FileNotFoundException {
		this(new ApplicationProperties(name, version, NO_RELEASE_NAME));
	}

	/**
	 * Constructs a new docking application layout object with the given set of application
	 * properties.
	 * 
	 * @param applicationProperties The properties object that will be read system properties.
	 * @throws FileNotFoundException if there was a problem getting a user directory.
	 */
	public DockingApplicationLayout(ApplicationProperties applicationProperties)
			throws FileNotFoundException {

		this.applicationProperties = Objects.requireNonNull(applicationProperties);

		// Application root directories
		if (SystemUtilities.isInDevelopmentMode()) {
			applicationRootDirs = ApplicationUtilities.findDefaultApplicationRootDirs();
		}
		else {
			applicationRootDirs = new ArrayList<>();
			applicationRootDirs.add(new ResourceFile(System.getProperty("user.dir")));
		}

		// Application installation directory
		applicationInstallationDir = applicationRootDirs.iterator().next().getParentFile();
		if (SystemUtilities.isInDevelopmentMode()) {
			applicationInstallationDir = applicationInstallationDir.getParentFile();
		}

		// Modules
		if (SystemUtilities.isInDevelopmentMode()) {
			modules = ModuleUtilities.findModules(applicationRootDirs,
				ModuleUtilities.findModuleRootDirectories(applicationRootDirs, new ArrayList<>()));
		}
		else {
			modules = ModuleUtilities.findModules(applicationRootDirs, applicationRootDirs);
		}

		// User directories
		userTempDir = ApplicationUtilities.getDefaultUserTempDir(applicationProperties);
		userSettingsDir = ApplicationUtilities.getDefaultUserSettingsDir(applicationProperties,
			applicationInstallationDir);
	}

}
