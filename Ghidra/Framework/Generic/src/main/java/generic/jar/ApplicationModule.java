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
package generic.jar;

import java.io.File;
import java.io.IOException;
import java.util.*;

import ghidra.framework.Application;
import ghidra.util.exception.AssertException;
import utility.module.ModuleManifestFile;

public class ApplicationModule implements Comparable<ApplicationModule> {

	private File moduleDir;
	private String relativePath;
	private File applicationRoot;

	public ApplicationModule(File applicationRoot, File moduleDir) {
		this.applicationRoot = applicationRoot;
		this.moduleDir = moduleDir;
		String filePath = moduleDir.getAbsolutePath();
		String rootPath = applicationRoot.getAbsolutePath();
		if (!filePath.startsWith(rootPath)) {
			throw new AssertException("ApplicationRoot is not in the parent path of moduleDir!");
		}

		relativePath = filePath.substring(rootPath.length() + 1);
	}

	public String getName() {
		return moduleDir.getName();
	}

	public File getModuleDir() {
		return moduleDir;
	}

	public File getApplicationRoot() {
		return applicationRoot;
	}

	public String getRelativePath() {
		return relativePath;
	}

	public boolean isExtension() {
		return moduleDir.getParentFile().getName().equalsIgnoreCase("Extensions");
	}

	public boolean isFramework() {
		return moduleDir.getParentFile().getName().equalsIgnoreCase("Framework");
	}

	public boolean isDebug() {
		return moduleDir.getParentFile().getName().equalsIgnoreCase("Debug");
	}

	public boolean isProcessor() {
		return moduleDir.getParentFile().getName().equalsIgnoreCase("Processors");
	}

	public boolean isFeature() {
		return moduleDir.getParentFile().getName().equalsIgnoreCase("Features");
	}

	public boolean isConfiguration() {
		return moduleDir.getParentFile().getName().equalsIgnoreCase("Configurations");
	}

	public boolean isGPL() {
		return moduleDir.getParentFile().getName().equalsIgnoreCase("GPL");
	}
	@Override
	public int compareTo(ApplicationModule o) {
		int myRank = getRank();
		int otherRank = o.getRank();
		int result = myRank - otherRank;
		if (result == 0) {
			result = getName().compareTo(o.getName());
		}
		return result;
	}

	@Override
	public String toString() {
		return getName();
	}

	private int getRank() {
		if (getName().equals("RenoirGraph")) {
			return 10;  // renoir is always last
		}
		if (isFramework()) {
			return 1;
		}
		if (isFeature()) {
			return 2;
		}
		if (isProcessor()) {
			return 3;
		}
		return 4;
	}

	public boolean excludeFromGhidraJar() {
		try {

			Collection<ResourceFile> applicationRoots = Application.getApplicationRootDirectories();

			// multiple dirs during development (repo dirs); single dir in installation (install dir)
			Set<File> rootDirParents = new HashSet<File>();
			for (ResourceFile root : applicationRoots) {
				rootDirParents.add(root.getParentFile().getFile(true));
			}

			ModuleManifestFile moduleManifestFile = new ModuleManifestFile(moduleDir);
			return moduleManifestFile.excludeFromGhidraJar();
		}
		catch (IOException e) {
			return false;
		}
	}

}
