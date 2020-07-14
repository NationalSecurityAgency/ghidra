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
import java.util.Collections;
import java.util.List;

import generic.jar.ResourceFile;

/**
 * The Ghidra test application layout defines the customizable elements of the Ghidra 
 * application's directory structure when running a test.
 * <p>
 * This layout exists because tests often need to provide their own user settings
 * directory, rather than using Ghidra's default.
 */
public class GhidraTestApplicationLayout extends GhidraApplicationLayout {

	/**
	 * Constructs a new Ghidra application layout object with the provided user settings
	 * directory.
	 * <p>
	 * This layout is useful when running Ghidra tests.
	 * 
	 * @param userSettingsDir The custom user settings directory to use.
	 * @throws FileNotFoundException if there was a problem getting a user directory.
	 * @throws IOException if there was a problem getting the application properties.
	 */
	public GhidraTestApplicationLayout(File userSettingsDir)
			throws FileNotFoundException, IOException {
		super();
		this.userSettingsDir = userSettingsDir;
	}

	@Override
	protected ResourceFile findExtensionArchiveDirectory() {
		File archiveDir = new File(getUserTempDir(), "ExtensionArchiveDir");
		return new ResourceFile(archiveDir);
	}

	@Override
	protected List<ResourceFile> findExtensionInstallationDirectories() {
		File installDir = new File(getUserTempDir(), "ExtensionInstallDir");
		return Collections.singletonList(new ResourceFile(installDir));
	}

	@Override
	protected ResourceFile findPatchDirectory() {
		File dir = new File(getUserTempDir(), "patch");
		return new ResourceFile(dir);
	}
}
