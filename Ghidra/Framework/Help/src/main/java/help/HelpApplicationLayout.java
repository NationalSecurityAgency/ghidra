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
package help;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.*;
import java.util.Map.Entry;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import generic.jar.ResourceFile;
import ghidra.framework.ApplicationProperties;
import ghidra.framework.GModule;
import ghidra.util.SystemUtilities;
import util.CollectionUtils;
import utility.application.ApplicationLayout;
import utility.application.ApplicationUtilities;
import utility.module.ClasspathFilter;
import utility.module.ModuleUtilities;

//
// TODO this class should be deleted when the GP-1981 branch is merged into master. The 
//      DockingApplicationLayout is not accessible by help, due to Docking depending on Help.
//      Much of the application layout code should live in Utility so that it is reachable by more
//      modules.   Docking and Ghidra application layout classes should also have their names 
//      changed.   
//
// 		Perhaps: ModuleAppliactionLayout and ClasspathApplicationLayout.
//
public class HelpApplicationLayout extends ApplicationLayout {

	private static final String NO_RELEASE_NAME = "NO_RELEASE";

	/** Dev mode main source bin dir pattern */
	private static final Pattern CLASS_PATH_MODULE_NAME_PATTERN =
		Pattern.compile(".*/(\\w+)/bin/main");

	/**
	 * Constructs a new docking application layout object with the given name and version.
	 *
	 * @param name The name of the application.
	 * @param version The version of the application.
	 * @throws FileNotFoundException if there was a problem getting a user directory.
	 */
	public HelpApplicationLayout(String name, String version) throws FileNotFoundException {

		this.applicationProperties =
			Objects.requireNonNull(new ApplicationProperties(name, version, NO_RELEASE_NAME));
		this.applicationRootDirs = getDefaultApplicationRootDirs();
		applicationRootDirs.addAll(getAdditionalApplicationRootDirs(applicationRootDirs));

		// Application installation directory
		applicationInstallationDir = applicationRootDirs.iterator().next().getParentFile();
		if (SystemUtilities.isInDevelopmentMode()) {
			applicationInstallationDir = applicationInstallationDir.getParentFile();
		}

		// Modules
		if (SystemUtilities.isInDevelopmentMode()) {

			// In development mode we rely on the IDE's classpath to determine which modules to
			// include, as opposed to scanning the filesystem.  This prevents unrelated modules
			// from being used.

			modules = ModuleUtilities.findModules(applicationRootDirs,
				ModuleUtilities.findModuleRootDirectories(applicationRootDirs),
				new ClasspathFilter());
		}
		else {
			modules = ModuleUtilities.findModules(applicationRootDirs, applicationRootDirs);
		}

		// User directories
		userTempDir = ApplicationUtilities.getDefaultUserTempDir(applicationProperties);
		userSettingsDir = ApplicationUtilities.getDefaultUserSettingsDir(applicationProperties,
			applicationInstallationDir);
	}

	protected Collection<ResourceFile> getAdditionalApplicationRootDirs(
			Collection<ResourceFile> roots) {
		return Collections.emptyList();
	}

	protected Map<String, GModule> findModules() {
		if (!SystemUtilities.isInDevelopmentMode()) {
			// in release mode we only have one application root, so no need to find all others
			return ModuleUtilities.findModules(applicationRootDirs, applicationRootDirs);
		}

		// In development mode we may have multiple module root directories under which modules may
		// be found.  Search all roots for modules.
		Collection<ResourceFile> roots =
			ModuleUtilities.findModuleRootDirectories(applicationRootDirs, new ArrayList<>());
		Map<String, GModule> allModules = ModuleUtilities.findModules(applicationRootDirs, roots);

		// Filter any modules found to ensure that we only include those that are listed on the 
		// classpath.  (Due to the nature of how the development classpath is created, not all 
		// found modules may match the classpath entries.)
		Set<String> cpNames = getClassPathModuleNames();
		Map<String, GModule> filteredModules = new HashMap<>();
		Set<Entry<String, GModule>> entrySet = allModules.entrySet();
		for (Entry<String, GModule> entry : entrySet) {
			GModule module = entry.getValue();
			if (cpNames.contains(module.getName())) {
				filteredModules.put(entry.getKey(), module);
			}
		}

		return filteredModules;
	}

	private Set<String> getClassPathModuleNames() {
		String cp = System.getProperty("java.class.path");
		String[] pathParts = cp.split(File.pathSeparator);
		Set<String> paths = new HashSet<>(Arrays.asList(pathParts));
		Set<String> cpNames = new HashSet<>();
		for (String cpEntry : paths) {
			Matcher matcher = CLASS_PATH_MODULE_NAME_PATTERN.matcher(cpEntry);
			if (matcher.matches()) {
				cpNames.add(matcher.group(1));
			}
		}
		return cpNames;
	}

	/**
	 * Get the default list of Application directories.  In repo-based
	 * development mode this includes the root Ghidra directory within each repo.
	 * When not in development mode, the requirement is that the current working
	 * directory correspond to the installation root.  The first entry will be
	 * the primary root in both cases.
	 * @return root directories
	 */
	public static Collection<ResourceFile> getDefaultApplicationRootDirs() {
		if (SystemUtilities.isInDevelopmentMode()) {
			return ApplicationUtilities.findDefaultApplicationRootDirs();
		}
		return CollectionUtils.asList(new ResourceFile(System.getProperty("user.dir")));
	}
}
