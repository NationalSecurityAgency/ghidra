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
import java.util.stream.Collectors;

import generic.jar.ResourceFile;
import ghidra.framework.GModule;
import ghidra.util.SystemUtilities;
import utility.application.ApplicationLayout;
import utility.module.ModuleUtilities;

/**
 * Class used to prepare Ghidra for launching
 * <p>
 * A {@link #main(String[])} method is provided which redirects execution to a 
 * {@link GhidraLaunchable} class passed in as a command line argument
 */
public class GhidraLauncher {

	/**
	 * Launches the given {@link GhidraLaunchable} specified in the first command line argument
	 * 
	 * @param args The first argument is the name of the {@link GhidraLaunchable} to launch.
	 *   The remaining args get passed through to the class's {@link GhidraLaunchable#launch} 
	 *   method.
	 * @throws Exception If there was a problem launching.  See the exception's message for more
	 *     details on what went wrong.  
	 */
	public static void launch(String[] args) throws Exception {

		// Initialize the Ghidra environment
		GhidraApplicationLayout layout = initializeGhidraEnvironment();
		
		// Make sure the thing to launch is a GhidraLaunchable
		Class<?> cls = ClassLoader.getSystemClassLoader().loadClass(args[0]);
		if (!GhidraLaunchable.class.isAssignableFrom(cls)) {
			throw new IllegalArgumentException("\"" + args[0] + "\" is not a launchable class");
		}

		// Launch the target class, which is the first argument.  Strip off the first argument
		// and pass the rest through to the target class's launch method.
		GhidraLaunchable launchable = (GhidraLaunchable) cls.getConstructor().newInstance();
		launchable.launch(layout, Arrays.copyOfRange(args, 1, args.length));
	}

	/**
	 * Launches the given {@link GhidraLaunchable} specified in the first command line argument
	 * 
	 * @param args The first argument is the name of the {@link GhidraLaunchable} to launch.
	 *   The remaining args get passed through to the class's {@link GhidraLaunchable#launch} 
	 *   method.
	 * @throws Exception If there was a problem launching.  See the exception's message for more
	 *     details on what went wrong. 
	 * @deprecated Use {@link Ghidra#main(String[])} instead
	 */
	@Deprecated(since = "10.1", forRemoval = true)
	public static void main(String[] args) throws Exception {
		launch(args);
	}

	/**
	 * Initializes the Ghidra environment by discovering its {@link GhidraApplicationLayout layout}
	 * and adding all relevant modules and libraries to the classpath
	 * <p>
	 * NOTE: This method expects that the {@link GhidraClassLoader} is the active classloader
	 * 
	 * @return Ghidra's {@link GhidraApplicationLayout layout}
	 * @throws IOException if there was an issue getting the {@link GhidraApplicationLayout layout}
	 * @throws ClassNotFoundException if the {@link GhidraClassLoader} is not the active classloader 
	 */
	public static GhidraApplicationLayout initializeGhidraEnvironment()
			throws IOException, ClassNotFoundException {

		// Make sure our class loader is being used
		if (!(ClassLoader.getSystemClassLoader() instanceof GhidraClassLoader)) {
			throw new ClassNotFoundException("Ghidra class loader not in use.  " +
				"Confirm JVM argument \"-Djava.system.class.loader argument=" +
				GhidraClassLoader.class.getName() + "\" is set.");
		}
		GhidraClassLoader loader = (GhidraClassLoader) ClassLoader.getSystemClassLoader();

		// Get application layout
		GhidraApplicationLayout layout = new GhidraApplicationLayout();
		
		// Get the classpath
		List<String> classpathList = buildClasspath(layout);

		// Add the classpath to the class loader
		classpathList.forEach(loader::addPath);

		return layout;
	}

	/**
	 * Builds and returns a classpath from the given {@link GhidraApplicationLayout layout}
	 * <p>
	 * NOTE: This method does NOT add the built classpath to a classloader...it just returns it
	 * 
	 * @param layout Ghidra's {@link GhidraApplicationLayout layout}
	 * @return A {@link List} of classpath entries
	 * @throws IOException if there was an IO-related issue with building the classpath
	 */
	private static List<String> buildClasspath(GhidraApplicationLayout layout) throws IOException {

		List<String> classpathList = new ArrayList<>();
		Map<String, GModule> modules = getOrderedModules(layout);

		if (SystemUtilities.isInDevelopmentMode()) {
			addModuleBinPaths(classpathList, modules);
			addExternalJarPaths(classpathList, layout.getApplicationRootDirs());
		}
		else {
			addPatchPaths(classpathList, layout.getPatchDir());
			addModuleJarPaths(classpathList, modules);
		}
		classpathList = orderClasspath(classpathList, modules);
		return classpathList;
	}

	/**
	 * Add patch jars to the given path list.  This should be done first so they take precedence in 
	 * the classpath.
	 * 
	 * @param pathList The list of paths to add to
	 * @param patchDir The application installation directory; may be null
	 */
	private static void addPatchPaths(List<String> pathList, ResourceFile patchDir) {
		if (patchDir == null || !patchDir.exists()) {
			return;
		}

		// this will allow for unbundled class files
		pathList.add(patchDir.getAbsolutePath());

		// this is each jar file, sorted for loading consistency
		List<String> jars = findJarsInDir(patchDir);
		pathList.addAll(jars);
	}

	/**
	 * Add module bin directories to the given path list.
	 * 
	 * @param pathList The list of paths to add to.
	 * @param modules The modules to get the bin directories of.
	 */
	private static void addModuleBinPaths(List<String> pathList, Map<String, GModule> modules) {
		Collection<ResourceFile> dirs = ModuleUtilities.getModuleBinDirectories(modules);
		dirs.forEach(d -> pathList.add(d.getAbsolutePath()));
	}

	/**
	 * Add module lib jars to the given path list.
	 * 
	 * @param pathList The list of paths to add to.
	 * @param modules The modules to get the jars of.
	 */
	private static void addModuleJarPaths(List<String> pathList, Map<String, GModule> modules) {
		Collection<ResourceFile> dirs = ModuleUtilities.getModuleLibDirectories(modules);
		dirs.forEach(d -> pathList.addAll(findJarsInDir(d)));
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

		// Add the jars to the path list (don't add duplicates, preserve order)
		Set<String> pathSet = new LinkedHashSet<>();
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

		if (pathSet.isEmpty()) {
			throw new IllegalStateException(
				"Files listed in '" + LIBDEPS + "' are incorrect--rebuild this file");
		}

		pathList.addAll(pathSet);
	}

	/**
	 * Searches the given directory (non-recursively) for jars and returns their paths in a list.
	 * The paths will be sorted by jar file name.
	 * 
	 * @param dir The directory to search for jars in
	 * @return A list of discovered jar paths, sorted by jar file name
	 */
	public static List<String> findJarsInDir(ResourceFile dir) {
		Set<ResourceFile> set = new TreeSet<>((a, b) -> a.getName().compareTo(b.getName()));
		ResourceFile[] names = dir.listFiles();
		if (names != null) {
			for (ResourceFile file : names) {
				if (file.getName().endsWith(".jar")) {
					set.add(file);
				}
			}
		}
		return set.stream().map(f -> f.getAbsolutePath()).collect(Collectors.toList());
	}

	/**
	 * Gets the modules ordered by "class-loader priority".  This ensures that core modules (things 
	 * in Framework/Features/Processors, etc) come before user modules (Extensions).  It also
	 * guarantees a consistent module order from run to run.
	 * 
	 * @param layout The layout
	 * @return the modules mapped by name, ordered by priority
	 */
	private static Map<String, GModule> getOrderedModules(ApplicationLayout layout) {

		Comparator<GModule> comparator = (module1, module2) -> {
			int nameComparison = module1.getName().compareTo(module2.getName());

			// First handle modules that are external to the Ghidra installation.
			// These should be put at the end of the list.
			boolean external1 = ModuleUtilities.isExternalModule(module1, layout);
			boolean external2 = ModuleUtilities.isExternalModule(module2, layout);
			if (external1 && external2) {
				return nameComparison;
			}
			if (external1) {
				return -1;
			}
			if (external2) {
				return 1;
			}

			// Now handle modules that are internal to the Ghidra installation.
			// We will primarily order them by "type" and secondarily by name.
			Map<String, Integer> typePriorityMap = new HashMap<>();
			typePriorityMap.put("Framework", 0);
			typePriorityMap.put("Configurations", 1);
			typePriorityMap.put("Features", 2);
			typePriorityMap.put("Debug", 3);
			typePriorityMap.put("Processors", 4);
			typePriorityMap.put("GPL", 5);
			typePriorityMap.put("Extensions", 6);
			typePriorityMap.put("Test", 7);

			String type1 = module1.getModuleRoot().getParentFile().getName();
			String type2 = module2.getModuleRoot().getParentFile().getName();
			int priority1 = typePriorityMap.getOrDefault(type1, typePriorityMap.size());
			int priority2 = typePriorityMap.getOrDefault(type2, typePriorityMap.size());
			if (priority1 != priority2) {
				return Integer.compare(priority1, priority2);
			}
			return nameComparison;
		};

		List<GModule> moduleList = new ArrayList<>(layout.getModules().values());
		Collections.sort(moduleList, comparator);
		Map<String, GModule> moduleMap = new LinkedHashMap<>();
		for (GModule module : moduleList) {
			moduleMap.put(module.getName(), module);
		}
		return moduleMap;
	}

	/**
	 * Updates the list of paths to make sure the order is correct for any class-loading dependencies.
	 *  
	 * @param pathList The list of paths to order.
	 * @param modules The modules on the classpath.
	 * @return A new list with the elements of the original list re-ordered as needed.
	 */
	private static List<String> orderClasspath(List<String> pathList,
			Map<String, GModule> modules) {

		Set<String> fatJars = modules.values()
				.stream()
				.flatMap(m -> m.getFatJars().stream())
				.collect(Collectors.toSet());

		List<String> orderedList = new ArrayList<>(pathList);

		for (String path : pathList) {
			if (fatJars.contains(new File(path).getName())) {
				orderedList.remove(path);
				orderedList.add(path);
			}
		}

		return orderedList;
	}
}
