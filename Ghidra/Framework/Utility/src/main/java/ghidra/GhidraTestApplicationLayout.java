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
import java.nio.file.Path;
import java.util.*;
import java.util.function.Predicate;

import generic.jar.ResourceFile;
import ghidra.framework.GModule;
import utility.module.ClasspathFilter;
import utility.module.ModuleUtilities;

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

	@Override
	protected Map<String, GModule> findGhidraModules() throws IOException {

		//
		// 1) Enforces module dependencies by classpath to better control the test environment.
		// 2) Add any dependent modules into the tests that are not already on the classpath. For
		//    example, this class adds all processor modules, as we do not use classpath
		//    dependencies for processor modules usage.
		//
		Set<String> modulePatterns = getDependentModulePatterns();
		Predicate<Path> additionalPaths = path -> {
			String pathString = path.toString();
			return modulePatterns.stream().anyMatch(pattern -> pathString.contains(pattern));
		};

		Collection<ResourceFile> roots =
			ModuleUtilities.findModuleRootDirectories(applicationRootDirs);
		return ModuleUtilities.findModules(applicationRootDirs, roots,
			new ClasspathFilter(additionalPaths));
	}

	/**
	 * Returns patterns that will be used to check against each discovered module.  Matching module
	 * paths will be included as modules to be used during testing.  By default, only modules that
	 * match the classpath entries are included.  If your tests needs modules not referenced by the
	 * classpath, then you can override this method and add any module patterns needed.
	 *
	 * <p>The pattern is any desired text that will be matched against.  If you wish to use path
	 * separators, be sure to do so in a platform-dependent manner.
	 *
	 * @return the patterns
	 */
	protected Set<String> getDependentModulePatterns() {
		//@formatter:off
		char slash = File.separatorChar;
		return new HashSet<>(Set.of(
			slash + "Processors" + slash,
			"TestResources",

			// This could easily be in a subclass, included by only those tests that need this
			// entry. At the time of writing, there are 8 tests that need this module.  For now,
			// adding the entry here seems like the easiest thing to do.
			"DemanglerGnu"
		));
		//@formatter:on
	}
}
