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
import java.util.*;

import generic.jar.ResourceFile;
import ghidra.framework.GModule;
import ghidra.util.SystemUtilities;
import utility.module.ModuleUtilities;

/**
 * Class to build the Ghidra classpath, add it to the {@link GhidraClassLoader}, and start the 
 * desired {@link GhidraLaunchable} that's passed in as a command line argument.
 */
public class GhidraLauncher {

	/**
	 * Launches the given {@link GhidraLaunchable}, passing through the args to it.
	 * 
	 * @param args The first argument is the name of the class to launch.  The remaining args
	 *     get passed through to the class's {@link GhidraLaunchable#launch} method.
	 * @throws Exception If there was a problem launching.  See the exception's message for more
	 *     details on what went wrong.  
	 */
	public static void main(String[] args) throws Exception {

		// Make sure our class loader is being used
		if (!(ClassLoader.getSystemClassLoader() instanceof GhidraClassLoader)) {
			throw new ClassNotFoundException("ERROR: Ghidra class loader not in use.  " +
				"Confirm JVM argument \"-Djava.system.class.loader argument=" +
				GhidraClassLoader.class.getName() + "\" is set.");
		}

		// Get application layout
		GhidraApplicationLayout layout = new GhidraApplicationLayout();

		// Build the classpath
		List<String> classpathList = new ArrayList<String>();
		if (SystemUtilities.isInDevelopmentMode()) {
			addModuleBinPaths(classpathList, layout.getModules());
			addExternalJarPaths(classpathList, layout.getApplicationRootDirs());
		}
		else {
			addPatchPaths(classpathList, layout.getApplicationRootDirs());
			addModuleJarPaths(classpathList, layout.getModules());
		}
		classpathList = orderClasspath(classpathList);

		// Add the classpath to the class loader
		GhidraClassLoader loader = (GhidraClassLoader) ClassLoader.getSystemClassLoader();
		classpathList.forEach(entry -> loader.addPath(entry));

		// Make sure the thing to launch is a GhidraLaunchable
		Class<?> cls = ClassLoader.getSystemClassLoader().loadClass(args[0]);
		if (!GhidraLaunchable.class.isAssignableFrom(cls)) {
			throw new IllegalArgumentException(
				"ERROR: \"" + args[0] + "\" is not a launchable class");
		}

		// Launch the target class, which is the first argument.  Strip off the first argument
		// and pass the rest through to the target class's launch method.
		GhidraLaunchable launchable = (GhidraLaunchable) cls.getConstructor().newInstance();
		launchable.launch(layout, Arrays.copyOfRange(args, 1, args.length));
	}

	/**
	 * Add bin patch directories and lib patch jars to the given path list.  This should be done
	 * first so they take precedence in the classpath.
	 * 
	 * @param pathList The list of paths to add to.
	 * @param appRootDirs The application root directories to search.
	 */
	private static void addPatchPaths(List<String> pathList, Collection<ResourceFile> appRootDirs) {

		for (ResourceFile rootDir : appRootDirs) {

			ResourceFile dir = new ResourceFile(rootDir, "bin");
			if (dir.exists()) {
				pathList.add(dir.getAbsolutePath());
			}

			ResourceFile debugLibDir = new ResourceFile(rootDir, "lib");
			if (debugLibDir.exists()) {
				pathList.addAll(findJarsInDir(debugLibDir));
			}
		}
	}

	/**
	 * Add module bin directories to the given path list.
	 * 
	 * @param pathList The list of paths to add to.
	 * @param modules The modules to get the bin directories of.
	 */
	private static void addModuleBinPaths(List<String> pathList, Map<String, GModule> modules) {
		ModuleUtilities.getModuleBinDirectories(modules).forEach(
			d -> pathList.add(d.getAbsolutePath()));
	}

	/**
	 * Add module lib jars to the given path list.
	 * 
	 * @param pathList The list of paths to add to.
	 * @param modules The modules to get the jars of.
	 */
	private static void addModuleJarPaths(List<String> pathList, Map<String, GModule> modules) {
		ModuleUtilities.getModuleLibDirectories(modules).forEach(
			d -> pathList.addAll(findJarsInDir(d)));
	}

	/**
	 * Add external runtime lib jars to the given path list.  The external jars are discovered by
	 * parsing the build/libraryDependencies.txt file that results from a prepDev.
	 * 
	 * @param pathList The list of paths to add to.
	 * @param appRootDirs The application root directories to search.
	 * @throws IOException if a required file or directory was not found.
	 */
	private static void addExternalJarPaths(List<String> pathList,
			Collection<ResourceFile> appRootDirs) throws IOException {

		final String LIBDEPS = "build/libraryDependencies.txt";

		// Get "libraryDependencies.txt" file
		ResourceFile libraryDependenciesFile = null;
		for (ResourceFile root : appRootDirs) {
			if (libraryDependenciesFile == null) {
				ResourceFile f = new ResourceFile(root.getParentFile(), LIBDEPS);
				if (f.isFile()) {
					libraryDependenciesFile = f;
				}
			}
		}

		// Make sure we found everything
		if (libraryDependenciesFile == null) {
			throw new FileNotFoundException(LIBDEPS + " file was not found!  Please do a prepDev.");
		}

		// Add the jars to the path list (don't add duplicates)
		Set<String> pathSet = new HashSet<>();
		try (BufferedReader reader =
			new BufferedReader(new FileReader(libraryDependenciesFile.getFile(false)))) {
			String line;
			while ((line = reader.readLine()) != null) {
				String path = line.trim();
				if (!path.startsWith("Module:") && path.endsWith(".jar")) {
					ResourceFile jarFile = new ResourceFile(path);
					if (!jarFile.isFile()) {
						System.err.println("Failed to find required jar file: " + jarFile);
						continue;
					}
					pathSet.add(jarFile.getAbsolutePath());
				}
			}
		}
		pathList.addAll(pathSet);
	}

	/**
	 * Searches the given directory (non-recursively) for jars and returns their paths in a list.
	 * 
	 * @param dir The directory to search for jars in.
	 * @return A list of discovered jar paths.
	 */
	public static List<String> findJarsInDir(ResourceFile dir) {
		List<String> list = new ArrayList<>();
		ResourceFile[] names = dir.listFiles();
		if (names != null) {
			for (ResourceFile file : names) {
				if (file.getName().endsWith(".jar")) {
					list.add(file.getAbsolutePath());
				}
			}
		}
		return list;
	}

	/**
	 * Updates the list of paths to make sure the order is correct for any class-loading dependencies.
	 *  
	 * @param pathList The list of paths to order.
	 * @return A new list with the elements of the original list re-ordered as needed.
	 */
	private static List<String> orderClasspath(List<String> pathList) {

		List<String> orderedList = new ArrayList<String>(pathList);

		for (String path : pathList) {
			if (path.endsWith("Renoir.jar")) { // Renoir.jar must be after all other jars
				orderedList.remove(path);
				orderedList.add(path);
				break;
			}
		}

		return orderedList;
	}
}
