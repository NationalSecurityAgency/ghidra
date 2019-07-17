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
package utility.application;

import java.io.FileNotFoundException;
import java.util.ArrayList;

import generic.jar.ResourceFile;
import ghidra.framework.ApplicationProperties;

/**
 * The dummy application layout defines the customizable elements of a dummy application's 
 * directory structure.  A dummy application only has a name, an installation/root dir, and
 * a user temp directory.
 */
public class DummyApplicationLayout extends ApplicationLayout {

	/**
	 * Constructs a new dummy application layout object.
	 * 
	 * @throws FileNotFoundException if there was a problem getting a user directory.
	 */
	public DummyApplicationLayout(String name) throws FileNotFoundException {

		// Application properties
		applicationProperties = new ApplicationProperties(name);

		// Application installation directory
		ResourceFile cwd = new ResourceFile(System.getProperty("user.dir"));
		applicationInstallationDir = cwd;

		// Application root directories
		applicationRootDirs = new ArrayList<>();
		applicationRootDirs.add(cwd);

		// User directories
		userTempDir = ApplicationUtilities.getDefaultUserTempDir(applicationProperties);
	}
}
