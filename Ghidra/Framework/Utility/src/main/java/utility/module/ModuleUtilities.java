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
package utility.module;

import java.io.File;
import java.io.IOException;
import java.nio.file.*;
import java.util.*;

import generic.jar.ResourceFile;
import ghidra.framework.GModule;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.AssertException;
import utilities.util.FileUtilities;
import utility.application.ApplicationLayout;

/**
 * Utility methods for module related things.
 */
public class ModuleUtilities {

	private static final String BINARY_PATH = System.getProperty("binaryPath", "bin/main");
	public static final String MANIFEST_FILE_NAME = "Module.manifest";
	public static final String MANIFEST_FILE_NAME_UNINSTALLED = "Module.manifest.uninstalled";
	public static final String MODULE_LIST = "MODULE_LIST";

	/**
	 * How many directories deep to look for module directories, starting from an application root 
	 * directory. For example, 3 would pick up modules as deep as: root/category/category/module
	 */
	private static final int MAX_MODULE_DEPTH = 3;

	/**
	 * Checks if the given directory is a module.
	 * 
	 * @param dir the directory to check.
	 * @return true if the given directory is a module
	 */
	public static boolean isModuleDirectory(ResourceFile dir) {
		return new ResourceFile(dir, MANIFEST_FILE_NAME).exists();
	}

	/**
	 * Returns true if the given path is a module root directory.
	 * 
	 * @param path the path to check
	 * @return true if the given path is a module root directory.
	 */
	public static boolean isModuleDirectory(Path path) {
		File file = path.toFile();
		return new File(file, MANIFEST_FILE_NAME).exists();
	}

	/**
	 * Searches the given root directory for module root directories.  Adds any discovered module
	 * root directories to the given collection.
	 * 
	 * @param rootDir The directory to start looking for module root directories in.
	 * @param moduleRootDirs A collection to add discovered module root directories to.
	 * @return The given collection with any discovered modules added.
	 */
	public static Collection<ResourceFile> findModuleRootDirectories(ResourceFile rootDir,
			Collection<ResourceFile> moduleRootDirs) {
		// look for any external GPL modules 
		findModuleRootDirectoriesHelper(new ResourceFile(rootDir, "../GPL"), moduleRootDirs,
			MAX_MODULE_DEPTH);
		return findModuleRootDirectoriesHelper(rootDir, moduleRootDirs, MAX_MODULE_DEPTH);
	}

	private static Collection<ResourceFile> findModuleRootDirectoriesHelper(ResourceFile rootDir,
			Collection<ResourceFile> moduleRootDirs, int remainingDepth) {
		if (!rootDir.exists() || remainingDepth <= 0) {
			return moduleRootDirs;
		}
		for (ResourceFile subDir : rootDir.listFiles(ResourceFile::isDirectory)) {
			if ("build".equals(subDir.getName())) {
				continue; // ignore all "build" directories
			}
			if (ModuleUtilities.isModuleDirectory(subDir)) {
				moduleRootDirs.add(subDir);
			}
			else {
				findModuleRootDirectoriesHelper(subDir, moduleRootDirs, remainingDepth - 1);
			}
		}
		return moduleRootDirs;
	}

	/**
	 * Searches the given root directories for module root directories.  Adds any discovered module
	 * root directories to the given collection.
	 * 
	 * @param rootDirs The directories to look for module root directories in.
	 * @param moduleRootDirs A collection to add discovered module root directories to.
	 * @return The given collection with any discovered modules added.
	 */
	public static Collection<ResourceFile> findModuleRootDirectories(
			Collection<ResourceFile> rootDirs, Collection<ResourceFile> moduleRootDirs) {
		for (ResourceFile rootDir : rootDirs) {
			findModuleRootDirectories(rootDir, moduleRootDirs);
		}
		return moduleRootDirs;
	}

	/**
	 * Searches the given jar root directory for module root directories.  Uses a "module list"
	 * file to locate the module root directories. Adds any discovered module root directories
	 * to the given collection.
	 * 
	 * @param rootDir The jar directory to start looking for module root directories in.
	 * @param moduleRootDirs A collection to add discovered module root directories to.
	 * @return The given collection with any discovered modules added.
	 * @throws IOException if there was a problem reading the module list file.
	 */
	public static Collection<ResourceFile> findJarModuleRootDirectories(ResourceFile rootDir,
			Collection<ResourceFile> moduleRootDirs) throws IOException {
		ResourceFile moduleListFile = new ResourceFile(rootDir, MODULE_LIST);
		for (String relativeModulePath : FileUtilities.getLines(moduleListFile)) {
			moduleRootDirs.add(new ResourceFile(rootDir, relativeModulePath));
		}
		return moduleRootDirs;
	}

	/**
	 * Searches for modules in a given collection of module root directories.
	 * 
	 * @param appRootDirs The collection of application root directories associated with the the given
	 *   list of module root directories.
	 * @param moduleRootDirs A collection of module root directories to search for modules in.
	 * @return The discovered modules as a map (mapping module name to module for convenience).
	 */
	public static Map<String, GModule> findModules(Collection<ResourceFile> appRootDirs,
			Collection<ResourceFile> moduleRootDirs) {

		Map<String, GModule> map = new TreeMap<>();

		for (ResourceFile moduleRoot : moduleRootDirs) {
			GModule gModule = new GModule(appRootDirs, moduleRoot);
			if (map.put(moduleRoot.getName(), gModule) != null) {
				StringBuilder collided = new StringBuilder();
				for (ResourceFile collideRoot : moduleRootDirs) {
					if (moduleRoot.getName().equals(collideRoot.getName())) {
						collided.append("\n");
						collided.append(collideRoot.getAbsolutePath());
					}
				}
				throw new AssertException(
					"Multiple modules collided with same name: " + moduleRoot.getName() + collided);
			}
		}
		return Collections.unmodifiableMap(map);
	}

	/**
	 * Gets the "lib" directories from the given modules.
	 * 
	 * @param modules The modules to get the lib directories of.
	 * @return A collection of lib directories from the given modules.
	 */
	public static Collection<ResourceFile> getModuleLibDirectories(Map<String, GModule> modules) {
		List<ResourceFile> libraryDirectories = new ArrayList<>();
		for (GModule module : modules.values()) {
			module.collectExistingModuleDirs(libraryDirectories, "lib");

			// In testing mode, we run out of an intermediate build state...the module jars
			// live in a build/libs directory.  We only want to look in here when testing because
			// other run modes (such as a Ghidra release launched from a user's Eclipse) may contain
			// build remnants that could cause problems if discovered.
			if (SystemUtilities.isInTestingMode()) {
				module.collectExistingModuleDirs(libraryDirectories, "libs");
			}
		}
		return libraryDirectories;
	}

	/**
	 * Gets the directory locations of the .class files and resources from the given modules.
	 * 
	 * @param modules The modules to get the compiled .class and resources directories of.
	 * @return A collection of directories containing classes and resources from the given modules.
	 */
	public static Collection<ResourceFile> getModuleBinDirectories(Map<String, GModule> modules) {
		String[] binaryPathTokens = BINARY_PATH.split(":");
		List<ResourceFile> binDirectories = new ArrayList<>();
		for (GModule module : modules.values()) {
			Arrays.stream(binaryPathTokens).forEach(
				token -> module.collectExistingModuleDirs(binDirectories, token));
		}
		return binDirectories;
	}

	/**
	 * Returns true if the given path is parented by a module root directory.
	 * <p>
	 * For example, given a module path of <code>/some/dir/features/cool_module/</code>, then this
	 * method will return true for these paths:
	 * <br>
	 * <br>
	 * <code>/some/dir/features/cool_module</code><br>
	 * <code>/some/dir/features/cool_module/some/child/dir</code>
	 * <br>
	 * <br>and false for these paths:
	 * <br>
	 * <br> 
	 * <code>/some/random/path</code><br>
	 * <code>/some/dir/features/</code>
	 * 
	 * @param pathName the path name to check
	 * @return true if the given path is parented by a module root directory.
	 * @see #isModuleDirectory(Path)
	 */
	public static boolean isInModule(String pathName) {
		return getModule(pathName) != null;
	}

	/**
	 * Returns the path of the module containing the given path string, if it is parented by a 
	 * module root directory.
	 * <p>
	 * For example, given a module path of <code>/some/dir/features/cool_module/</code>, then this
	 * method will return that module path, given these paths:
	 * <br>
	 * <br>
	 * <code>/some/dir/features/cool_module</code><br>
	 * <code>/some/dir/features/cool_module/some/child/dir</code>
	 * <br>
	 * <br>and null for these paths:
	 * <br>
	 * <br> 
	 * <code>/some/random/path</code><br>
	 * <code>/some/dir/features/</code>
	 * 
	 * @param pathName the path name to check
	 * @return the module root directory; null if the path is not in a module
	 * @see #isModuleDirectory(Path)
	 */
	public static Path getModule(String pathName) {
		Path path = toPath(pathName);
		while (path != null) {
			if (isModuleDirectory(path)) {
				return path;
			}
			path = path.getParent();
		}
		return null;
	}

	private static Path toPath(String pathname) {
		try {
			return Paths.get(pathname);
		}
		catch (InvalidPathException e) {
			Msg.trace(ModuleUtilities.class, "Invalid path: " + pathname);
			return null;
		}
	}

	/**
	 * Returns a file that is the root folder of the repository containing the given file.  'Root'
	 * here means a folder that contains a repository folder.  As an example, given a repo 
	 * structure of:
	 * 
	 * <p><code>/userdir/repoRoot/repoDir/.git</code><br>
	 * 
	 * <p>then this method, given will produce the following results (input -&gt; output):<br>
	 * 
	 * <p><code>/userdir/repoRoot/repoDir/.git -&gt; /userdir/repoRoot</code>
	 * <br><code>/userdir/repoRoot/repoDir -&gt; /userdir/repoRoot</code>
	 * <br><code>/userdir/repoRoot -&gt; /userdir/repoRoot</code>
	 * 
	 * 
	 * @param f the child file of the desired repo
	 * @return a file that is the root folder of the repository containing the given file; null
	 *         if the given file is not under a repo directory or itself a repo root
	 */
	public static File findRepoRoot(File f) {
		if (f == null) {
			return null;
		}

		File repoDir = findRepo(f);
		if (repoDir != null) {
			return repoDir.getParentFile();
		}

		// one last check to see if the given file is actually itself a repo root
		File[] children = f.listFiles(file -> file.isDirectory());
		if (children != null) {
			for (File child : children) {
				File childRepo = findRepo(child);
				if (childRepo != null) {
					return childRepo.getParentFile();
				}
			}
		}
		return null;
	}

	/**
	 * Returns a file that is the repository folder containing the given file.  As an example, 
	 * given a repo structure of:
	 * 
	 * <p><code>/userdir/repoRoot/repoDir/.git</code><br>
	 * 
	 * <p>then this method, given will produce the following results (input -&gt; output):<br>
	 * 
	 * <p><code>/userdir/repoRoot/repoDir/.git -&gt; /userdir/repoRoot/repoDir</code>
	 * <br><code>/userdir/repoRoot/repoDir -&gt; /userdir/repoRoot/repoDir</code>
	 * 
	 * @param f the child file of the desired repo
	 * @return a file that is the repo folder of the repository containing the given file; null
	 *         if the given file is not under a repo directory
	 */
	public static File findRepo(File f) {
		if (f == null) {
			return null;
		}
		File testGit = new File(f, ".git");
		if (testGit.exists()) {
			return f;
		}
		return findRepo(f.getParentFile());
	}

	/**
	 * Checks to see if the given {@link GModule module} is external to the Ghidra installation
	 * directory
	 * 
	 * @param module the module to check
	 * @param layout Ghidra's layout
	 * @return true if the given {@link GModule module} is external to the Ghidra installation
	 *   directory
	 */
	public static boolean isExternalModule(GModule module, ApplicationLayout layout) {
		File moduleRootDir = module.getModuleRoot().getFile(false);
		return !layout.getApplicationRootDirs()
				.stream()
				.map(dir -> dir.getParentFile().getFile(false))
				.anyMatch(dir -> FileUtilities.isPathContainedWithin(dir, moduleRootDir));
	}
}
