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
package ghidra.framework;

import java.io.IOException;
import java.util.*;

import generic.jar.ResourceFile;
import ghidra.util.Msg;
import utility.module.ModuleManifestFile;

public class GModule {
	private final String BUILD_OUTPUT_DIR = "build";
	private static final HashSet<String> EXCLUDED_DIRECTORY_NAMES = new HashSet<>();

	// document some of our assumptions
	static {
		EXCLUDED_DIRECTORY_NAMES.add(".svn");
		EXCLUDED_DIRECTORY_NAMES.add("bin");
		EXCLUDED_DIRECTORY_NAMES.add("classes");
		EXCLUDED_DIRECTORY_NAMES.add("developer_scripts");
		EXCLUDED_DIRECTORY_NAMES.add("ghidra_scripts");
		EXCLUDED_DIRECTORY_NAMES.add("help");
		EXCLUDED_DIRECTORY_NAMES.add("os");
		EXCLUDED_DIRECTORY_NAMES.add("resources");
		EXCLUDED_DIRECTORY_NAMES.add("src");
		EXCLUDED_DIRECTORY_NAMES.add("test");
	}

	private ResourceFile moduleRoot;
	private List<ResourceFile> searchRootsByPriority = new ArrayList<>();
	private Set<String> dataSearchIgnoreDirs = new HashSet<>();
	private Set<String> fatJars = new HashSet<>();

	public GModule(Collection<ResourceFile> appRoots, ResourceFile moduleRoot) {

		if (!moduleRoot.exists()) {
			Msg.error(this, "Attempted to create module for non-existent directory: " + moduleRoot);
		}

		this.moduleRoot = moduleRoot;
		searchRootsByPriority.add(moduleRoot);
		ResourceFile buildDir = new ResourceFile(moduleRoot, BUILD_OUTPUT_DIR);
		if (buildDir.exists()) {
			searchRootsByPriority.add(buildDir);
		}

		List<ResourceFile> shadowModules = getShadowModuleAcrossRepos(appRoots);
		searchRootsByPriority.addAll(shadowModules);

		loadModuleInfo();
	}

	private void loadModuleInfo() {
		try {
			ModuleManifestFile manifestFile = new ModuleManifestFile(moduleRoot);
			dataSearchIgnoreDirs = manifestFile.getDataSearchIgnoreDirs();
			fatJars = manifestFile.getFatJars();
		}
		catch (IOException e) {
			// don't care - if not using moduleManifest to find modules, then we don't
			// care if its missing, and if we are using it to find modules, its too late 
			// at this point and we wouldn't be called here.
		}
	}

	private List<ResourceFile> getShadowModuleAcrossRepos(Collection<ResourceFile> appRoots) {
		List<ResourceFile> list = new ArrayList<>();
		String relativeModulePath = getRelativeModulePath(appRoots);
		if (relativeModulePath == null) {
			return list; // not a nested module application
		}
		for (ResourceFile appRoot : appRoots) {
			ResourceFile moduleInAppRoot = new ResourceFile(appRoot, relativeModulePath);
			if (moduleInAppRoot.equals(moduleRoot)) {
				continue;
			}
			if (moduleInAppRoot.exists()) {
				list.add(moduleInAppRoot);
			}
		}
		return list;
	}

	private String getRelativeModulePath(Collection<ResourceFile> appRoots) {
		String moduleRootPath = moduleRoot.getAbsolutePath();

		for (ResourceFile appRoot : appRoots) {
			String appRootPath = appRoot.getAbsolutePath();

			if (moduleRootPath.equals(appRootPath)) {
				// The module root is an appRoot; it doesn't support nested modules
				return null;
			}

			if (moduleRootPath.startsWith(appRootPath)) {
				return moduleRootPath.substring(appRootPath.length() + 1);
			}
		}
		return null;
	}

	public void collectExistingModuleDirs(List<ResourceFile> accumulator,
			String moduleRelativePath) {
		for (ResourceFile moduleSearchRoot : searchRootsByPriority) {
			ResourceFile dir = new ResourceFile(moduleSearchRoot, moduleRelativePath);
			if (dir.exists()) {
				accumulator.add(dir);
			}
		}

	}

	public ResourceFile getModuleRoot() {
		return moduleRoot;
	}

	public void accumulateDataFilesByExtension(List<ResourceFile> accumulator, String extension) {
		for (ResourceFile moduleSearchRoot : searchRootsByPriority) {
			ResourceFile dataDir = new ResourceFile(moduleSearchRoot, "data");
			if (dataDir.exists()) {
				accumulateFilesByExtension(extension, dataDir, accumulator);
			}
		}
	}

	public ResourceFile findModuleFile(String relativeDataFilePath) {
		for (ResourceFile moduleSearchRoot : searchRootsByPriority) {
			ResourceFile file = new ResourceFile(moduleSearchRoot, relativeDataFilePath);
			if (file.exists()) {
				return file;
			}
		}
		return null;
	}

	public Set<String> getFatJars() {
		return fatJars;
	}

	private void accumulateFilesByExtension(String extension, ResourceFile dir,
			List<ResourceFile> accumulator) {
		ResourceFile[] children = dir.listFiles();
		for (ResourceFile child : children) {
			if (child.isDirectory()) {
				if (shouldSearch(child)) {
					accumulateFilesByExtension(extension, child, accumulator);
				}
			}
			else {

				// Ignore ._ resource fork files
				if (child.getName().startsWith("._")) {
					continue;
				}

				if (child.getName().endsWith(extension)) {
					accumulator.add(child);
				}
			}
		}
	}

	private boolean shouldSearch(ResourceFile child) {
		String childName = child.getName();
		if (EXCLUDED_DIRECTORY_NAMES.contains(childName)) {
			return false;
		}
		if (dataSearchIgnoreDirs.contains(childName)) {
			return false;
		}
		return true;
	}

	public String getName() {
		return moduleRoot.getName();
	}

	@Override
	public String toString() {
		return getName();
	}
}
