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
package ghidra.util.classfinder;

import java.io.File;
import java.lang.reflect.Modifier;
import java.util.*;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import utility.module.ModuleUtilities;

/**
 * Finds classes in the classPath that match one of the filter classes.
 */
public class ClassFinder {
	static final Logger log = LogManager.getLogger(ClassFinder.class);

	private static List<Class<?>> FILTER_CLASSES =
		Collections.unmodifiableList(Arrays.asList(ExtensionPoint.class));

	private List<ClassDir> classDirs = new ArrayList<>();
	private List<ClassJar> classJars = new ArrayList<>();

	private Map<String, List<Class<?>>> classesByName;

	public ClassFinder(List<String> searchPaths, TaskMonitor monitor) throws CancelledException {
		initialize(searchPaths, monitor);
	}

	private void initialize(List<String> searchPaths, TaskMonitor monitor)
			throws CancelledException {
		classDirs.clear();
		classJars.clear();
		reconcileClasses(searchPaths, monitor);
	}

	private void reconcileClasses(List<String> searchPaths, TaskMonitor monitor)
			throws CancelledException {

		Set<String> pathSet = new LinkedHashSet<>(searchPaths);

		Iterator<ClassDir> dirs = classDirs.iterator();
		while (dirs.hasNext()) {
			monitor.checkCanceled();
			ClassDir classDir = dirs.next();
			String dirPath = classDir.getDirPath();
			if (!pathSet.contains(dirPath)) {
				log.trace(dirPath + " dropped from previous classpath");
				dirs.remove();
			}
			else {
				classDir.rescan(monitor);
				pathSet.remove(dirPath);
			}
		}

		Iterator<ClassJar> jars = classJars.iterator();
		while (jars.hasNext()) {
			monitor.checkCanceled();
			ClassJar classJar = jars.next();
			String jarPath = classJar.getJarPath();
			if (!pathSet.contains(jarPath)) {
				log.trace(jarPath + " dropped from previous classpath");
				jars.remove();
			}
			else {
				classJar.rescan(monitor);
				pathSet.remove(jarPath);
			}
		}

		Iterator<String> pathIterator = pathSet.iterator();
		while (pathIterator.hasNext()) {
			monitor.checkCanceled();
			String path = pathIterator.next();
			String lcPath = path.toLowerCase();
			File file = new File(path);
			if ((lcPath.endsWith(".jar") || lcPath.endsWith(".zip")) && file.exists()) {

				if (ClassJar.ignoreJar(lcPath)) {
					log.trace("Ignoring jar file: " + path);
					continue;
				}

				log.trace("Searching jar file: " + path);
				classJars.add(new ClassJar(path, monitor));
			}
			else if (file.isDirectory()) {
				log.trace("Searching classpath directory: " + path);
				classDirs.add(new ClassDir(path, monitor));
			}
		}

	}

	public List<Class<?>> getClasses(Class<?> filterClass, TaskMonitor monitor)
			throws CancelledException {
		if (classesByName == null) {
			Map<String, List<Class<?>>> map = new HashMap<>();

			Set<Class<?>> classSet = new HashSet<>();
			Iterator<ClassDir> classDirIterator = classDirs.iterator();
			while (classDirIterator.hasNext()) {
				monitor.checkCanceled();
				ClassDir classDir = classDirIterator.next();
				classDir.getClasses(classSet, monitor);
			}
			Iterator<ClassJar> classJarsIterator = classJars.iterator();
			while (classJarsIterator.hasNext()) {
				monitor.checkCanceled();
				ClassJar classJar = classJarsIterator.next();
				classJar.getClasses(classSet, monitor);
			}

			for (Class<?> filterClasse : FILTER_CLASSES) {
				monitor.checkCanceled();
				List<Class<?>> list = new ArrayList<>();
				Iterator<Class<?>> classSetIterator = classSet.iterator();
				while (classSetIterator.hasNext()) {
					Class<?> c = classSetIterator.next();
					if (filterClasse.isAssignableFrom(c)) {
						list.add(c);
					}
				}

				map.put(filterClasse.getName(), list);
			}

			classesByName = map;
		}

		List<Class<?>> classes = classesByName.get(filterClass.getName());
		return classes != null ? classes : Collections.emptyList();
	}

	/*package*/ static Class<?> loadExtensionPoint(String path, String fullName) {

		if (!ClassSearcher.isExtensionPointName(fullName)) {
			return null;
		}

		ClassLoader classLoader = ClassSearcher.class.getClassLoader();
		try {
			Class<?> c = Class.forName(fullName, true, classLoader);
			if (isClassOfInterest(c)) {
				return c;
			}
		}
		catch (Throwable t) {
			processClassLoadError(path, fullName, t);
		}

		return null;
	}

	private static void processClassLoadError(String path, String name, Throwable t) {

		if (t instanceof LinkageError) {
			// We see this sometimes when loading classes that match our naming convention for
			// extension points, but are actually extending 3rd party libraries.  For now, do 
			// not make noise in the log for this case.
			Msg.trace(ClassFinder.class,
				"LinkageError loading class " + name + "; Incompatible class version? ", t);
			return;
		}

		if (!(t instanceof ClassNotFoundException)) {
			Msg.error(ClassFinder.class, "Error loading class " + name + " - " + t.getMessage(), t);
			return;
		}

		processClassNotFoundExcepetion(path, name, (ClassNotFoundException) t);
	}

	private static void processClassNotFoundExcepetion(String path, String name,
			ClassNotFoundException t) {

		if (!isModuleEntryMissingFromClasspath(path)) {
			// not sure if this can actually happen--it implies a half-built Eclipse issue
			Msg.error(ClassFinder.class, "Error loading class " + name + " - " + t.getMessage(), t);
			return;
		}

		// We have a special case: we know a module class was loaded, but it is not in our
		// classpath.  This can happen in Eclipse when we scan all modules, but the launcher does
		// not include all modules.
		if (SystemUtilities.isInTestingMode()) {
			// ignore the error in testing mode, as many modules are not loaded for any given test
			return;
		}

		Msg.error(ClassFinder.class,
			"Module class is missing from the classpath.\n\tUpdate your launcher " +
				"accordingly.\n\tModule: '" + path + "'\n\tClass: '" + name + "'");
	}

	private static boolean isModuleEntryMissingFromClasspath(String path) {

		boolean inModule = ModuleUtilities.isInModule(path);
		if (!inModule) {
			return false;
		}

		String classPath = System.getProperty("java.class.path");
		boolean inClassPath = classPath.contains(path);
		return !inClassPath;
	}

	/**
	 * Checks to see if the given class is an extension point of interest.
	 * 
	 * @param c The class to check.
	 * @return True if the given class is an extension point of interest; otherwise, false.
	 */
	public static boolean isClassOfInterest(Class<?> c) {
		if (Modifier.isAbstract(c.getModifiers())) {
			return false;
		}
		if (c.getEnclosingClass() != null && !Modifier.isStatic(c.getModifiers())) {
			return false;
		}
		if (!Modifier.isPublic(c.getModifiers())) {
			return false;
		}
		if (ExtensionPoint.Util.isExcluded(c)) {
			return false;
		}

		for (Class<?> filterClasse : FILTER_CLASSES) {
			if (filterClasse.isAssignableFrom(c)) {
				return true;
			}
		}
		return false;
	}
}
