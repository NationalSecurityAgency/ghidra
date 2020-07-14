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

import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.*;

import generic.jar.ResourceFile;
import ghidra.framework.ApplicationProperties;
import ghidra.framework.GModule;
import utility.application.ApplicationLayout;
import utility.module.ModuleUtilities;

/**
 * The Ghidra jar application layout defines the customizable elements of the Ghidra application's 
 * directory structure when running in "single jar mode."
 */
public class GhidraJarApplicationLayout extends GhidraApplicationLayout {

	/**
	 * Constructs a new Ghidra jar application layout object.
	 * 
	 * @throws FileNotFoundException if there was a problem getting a user directory.
	 * @throws IOException if there was a problem getting the application properties or modules.
	 */
	public GhidraJarApplicationLayout() throws FileNotFoundException, IOException {
		super();
	}

	@Override
	public boolean inSingleJarMode() {
		return true;
	}

	@Override
	protected Collection<ResourceFile> findGhidraApplicationRootDirs() {
		List<ResourceFile> dirs = new ArrayList<>();
		dirs.add(new ResourceFile(ApplicationLayout.class.getResource("/_Root/Ghidra/" +
			ApplicationProperties.PROPERTY_FILE).toExternalForm()).getParentFile());
		return dirs;
	}

	@Override
	protected ResourceFile findGhidraApplicationInstallationDir() {
		if (getApplicationRootDirs().isEmpty()) {
			return null;
		}
		return getApplicationRootDirs().iterator().next().getParentFile();
	}

	@Override
	protected Map<String, GModule> findGhidraModules() throws IOException {
		return ModuleUtilities.findModules(getApplicationRootDirs(),
			ModuleUtilities.findJarModuleRootDirectories(getApplicationRootDirs().iterator().next(),
				new ArrayList<>()));
	}

	@Override
	protected ResourceFile findExtensionArchiveDirectory() {
		return null;
	}

	@Override
	protected List<ResourceFile> findExtensionInstallationDirectories() {
		ResourceFile extensionInstallDir = new ResourceFile(
			ApplicationLayout.class.getResource("/_Root/Ghidra/Extensions").toExternalForm());
		return Collections.singletonList(extensionInstallDir);
	}
}
