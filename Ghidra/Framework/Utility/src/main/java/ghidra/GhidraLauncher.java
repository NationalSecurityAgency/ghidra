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
import java.lang.reflect.Constructor;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.stream.Collectors;

import generic.jar.ResourceFile;
import ghidra.framework.GModule;
import ghidra.util.SystemUtilities;
import utilities.util.FileUtilities;
import utility.application.ApplicationLayout;
import utility.module.ModuleUtilities;

/**
 * Class used to prepare Ghidra for launching
 * <p>
 * A {@link #main(String[])} method is provided which redirects execution to a 
 * {@link GhidraLaunchable} class passed in as a command line argument
 */
public class GhidraLauncher {

	private static Instant START_INSTANT = Instant.now();

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

		GhidraApplicationLayout layout = initializeGhidraEnvironment();

		// Make sure the thing to launch meets the criteria:
		// 1) Class exists
		// 2) Class implements GhidraLaunchable
		// 3) Class has a 0-argument constructor
		Class<?> cls;
		try {
			cls = ClassLoader.getSystemClassLoader().loadClass(args[0]);
		}
		catch (ClassNotFoundException e) {
			throw new IllegalArgumentException("\"" + args[0] + "\" class was not found");
		}
		if (!GhidraLaunchable.class.isAssignableFrom(cls)) {
			throw new IllegalArgumentException("\"" + args[0] + "\" is not a launchable class");
		}
		Constructor<?> constructor;
		try {
			constructor = cls.getConstructor();
		}
		catch (NoSuchMethodException e) {
			throw new IllegalArgumentException(
				"\"" + args[0] + "\" does not have a 0-argument constructor");
		}

		// Launch the target class, which is the first argument.  Strip off the first argument
		// and pass the rest through to the target class's launch method.
		GhidraLaunchable launchable = (GhidraLaunchable) constructor.newInstance();
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
	 * {@return the current number of milliseconds that have elapsed since execution began}
	 */
	public static long getMillisecondsFromLaunch() {
		return ChronoUnit.MILLIS.between(START_INSTANT, Instant.now());
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

		// First add any "bin" paths the module might have. These could come from external modules
		// being developed and passed in via system property if we are in release mode, or they 
		// could be generated for each Ghidra module by Eclipse if we are in development mode.
		addModuleBinPaths(classpathList, modules);

		if (SystemUtilities.isInDevelopmentMode()) {

			// If we didn't find any "bin" paths and we are in development mode, assume Ghidra was 
			// compiled with Gradle, and add the module jars Gradle built.
			boolean gradleDevMode = classpathList.isEmpty();
			if (gradleDevMode) {
				// Add the module jars Gradle built.
				// Note: this finds Extensions' jar files so there is no need to to call
				// addExtensionJarPaths()
				addModuleJarPaths(classpathList, modules);
			}
			else { /* Eclipse dev mode */
				// Support loading pre-built, jar-based, non-repo extensions in Eclipse dev mode
				addExtensionJarPaths(classpathList, modules, layout);
			}

			// In development mode, 3rd party library jars do not live in module directories. 
			// Instead, each jar lives in an external, non-repo location, which is listed in 
			// build/libraryDependencies.txt.
			addExternalJarPaths(classpathList, layout.getApplicationRootDirs());
		}
		else {

			// Release mode is simple.  We expect all of Ghidra's modules to be in pre-build jars.
			addPatchPaths(classpathList, layout.getPatchDir());
			addModuleJarPaths(classpathList, modules);
		}

		//
		// The framework may choose to handle extension class loading separately from all other 
		// class loading.  In that case, we will separate the extension jar files from standard 
		// module jar files. 
		//
		// (If the custom extension class loading is disabled, then the extensions will be put onto
		// the standard classpath.)
		setExtensionJarPaths(modules, layout, classpathList);

		// Ghidra launches from the Utility module, so it's already on the classpath.  We don't
		// want to add it a second time, so remove the one we discovered.
		GModule utilityModule = modules.get("Utility");
		if (utilityModule == null) {
			throw new IOException("Failed to find the 'Utility' module!");
		}
		classpathList.removeIf(
			e -> e.startsWith(utilityModule.getModuleRoot().getAbsolutePath()));

		return orderClasspath(classpathList, modules);
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
		Collection<ResourceFile> dirs = ModuleUtilities.getModuleBinDirectories(modules.values());
		dirs.forEach(d -> pathList.add(d.getAbsolutePath()));
	}

	/**
	 * Add module lib jars to the given path list.
	 * 
	 * @param pathList The list of paths to add to.
	 * @param modules The modules to get the jars of.
	 */
	private static void addModuleJarPaths(List<String> pathList, Map<String, GModule> modules) {
		Collection<ResourceFile> dirs = ModuleUtilities.getModuleLibDirectories(modules.values());
		dirs.forEach(d -> pathList.addAll(findJarsInDir(d)));
	}

	/**
	 * Initializes the Extension classpath system property, unless disabled.
	 * @param modules the known modules
	 * @param layout the application layout
	 * @param classpathList the standard classpath elements
	 */
	private static void setExtensionJarPaths(Map<String, GModule> modules,
			GhidraApplicationLayout layout, List<String> classpathList) {

		if (!Boolean.getBoolean(GhidraClassLoader.ENABLE_RESTRICTED_EXTENSIONS_PROPERTY)) {
			// custom extension class loader is disabled; use normal classpath
			return;
		}

		List<String> extClasspathList = new ArrayList<>();
		addExtensionJarPaths(extClasspathList, modules, layout);

		// Remove the extensions that were added before this method was called
		classpathList.removeAll(extClasspathList);

		String extCp = String.join(File.pathSeparator, extClasspathList);
		System.setProperty(GhidraClassLoader.CP_EXT, extCp);
	}

	/**
	 * Add extension module lib jars to the given path list.  (This is only needed in dev mode to 
	 * find any pre-built extensions that have been installed, since  we already find extension 
	 * module jars in production mode.)
	 * 
	 * @param pathList The list of paths to add to.
	 * @param modules The modules to get the jars of.
	 * @param layout the application layout.
	 */
	private static void addExtensionJarPaths(List<String> pathList,
			Map<String, GModule> modules, GhidraApplicationLayout layout) {

		List<ResourceFile> extensionInstallationDirs = layout.getExtensionInstallationDirs();
		for (GModule module : modules.values()) {

			ResourceFile moduleDir = module.getModuleRoot();
			if (!FileUtilities.isPathContainedWithin(extensionInstallationDirs, moduleDir)) {
				continue; // not an extension
			}

			Collection<ResourceFile> libDirs =
				ModuleUtilities.getModuleLibDirectories(Set.of(module));
			if (libDirs.size() != 1) {
				continue; // assume multiple lib dirs signals a non-built development project
			}

			// We have one lib dir; the name 'lib' is used for a fully built extension.  Grab all 
			// jars from the built extensions lib directory.
			ResourceFile dir = libDirs.iterator().next();
			if (dir.getName().equals("lib")) {
				pathList.addAll(findJarsInDir(dir));
			}
		}
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
					if (path.startsWith("#") || path.startsWith("//")) {
						System.err.println("Skipping jar file: " + jarFile);
						continue;
					}
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
