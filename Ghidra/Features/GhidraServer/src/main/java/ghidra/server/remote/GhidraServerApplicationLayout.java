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
package ghidra.server.remote;

import java.io.IOException;
import java.util.Collections;

import ghidra.framework.ApplicationProperties;
import ghidra.util.SystemUtilities;
import utility.application.ApplicationLayout;
import utility.application.ApplicationUtilities;
import utility.module.ModuleUtilities;

/**
 * The Ghidra server application layout defines the customizable elements of the Ghidra
 * server application's directory structure.
 */
public class GhidraServerApplicationLayout extends ApplicationLayout {

	/**
	 * Constructs a new Ghidra server application layout object.
	 *
	 * @throws IOException if there was a problem getting a user directory or the application 
	 *   properties.
	 */
	public GhidraServerApplicationLayout() throws IOException {

		// Application root directories
		applicationRootDirs = ApplicationUtilities.findDefaultApplicationRootDirs();

		// Application properties
		applicationProperties = new ApplicationProperties(applicationRootDirs);

		// Application installation directory
		applicationInstallationDir = getApplicationRootDirs().iterator().next().getParentFile();
		if (SystemUtilities.isInDevelopmentMode() && getApplicationRootDirs().size() > 1) {
			applicationInstallationDir = applicationInstallationDir.getParentFile();
		}

		// Extension directories
		extensionArchiveDir = null;
		extensionInstallationDirs = Collections.emptyList();

		// User directories (don't let anything use the user home directory...there may not be one)
		userTempDir =
			ApplicationUtilities.getDefaultUserTempDir(applicationProperties.getApplicationName());

		// Modules - required to find module data files
		modules = ModuleUtilities.findModules(applicationRootDirs,
			ModuleUtilities.findModuleRootDirectories(applicationRootDirs));

	}
}
