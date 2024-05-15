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
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Modifier;
import java.nio.file.*;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import javax.swing.event.ChangeListener;

import org.apache.commons.collections4.BidiMap;
import org.apache.commons.collections4.bidimap.DualHashBidiMap;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import generic.jar.ResourceFile;
import generic.json.Json;
import ghidra.GhidraClassLoader;
import ghidra.framework.Application;
import ghidra.util.*;
import ghidra.util.datastruct.WeakDataStructureFactory;
import ghidra.util.datastruct.WeakSet;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.extensions.*;
import ghidra.util.task.TaskMonitor;
import utilities.util.FileUtilities;
import utility.module.ModuleUtilities;

/**
 * This class is a collection of static methods used to discover classes that implement a
 * particular interface or extend a particular base class.
 * <p>
 * <b>Warning: Using the search feature of this class will trigger other classes to be loaded.
 * Thus, clients should not make calls to this class inside of static initializer blocks</b>
 *
 * <p>Note: if your application is not using a module structure for its release build, then
 * your application must create the following file, with the required entries,
 * in order to find extension points:
 * <pre>
 * 	&lt;install dir&gt;/data/ExtensionPoint.manifest
 * </pre>
 *
 */
public class ClassSearcher {

	private static final Logger log = LogManager.getLogger(ClassSearcher.class);

	/** 
	 * This provides a means for custom apps that do not use a module structure to search all jars
	 */
	public static final String SEARCH_ALL_JARS_PROPERTY = "class.searcher.search.all.jars";
	static final boolean SEARCH_ALL_JARS = Boolean.getBoolean(SEARCH_ALL_JARS_PROPERTY);

	private static final boolean IS_USING_RESTRICTED_EXTENSIONS =
		Boolean.getBoolean(GhidraClassLoader.ENABLE_RESTRICTED_EXTENSIONS_PROPERTY);

	private static List<Class<?>> FILTER_CLASSES = Arrays.asList(ExtensionPoint.class);
	private static Pattern extensionPointSuffixPattern;
	private static Map<String, Set<ClassFileInfo>> extensionPointSuffixToInfoMap;
	private static BidiMap<ClassFileInfo, Class<?>> loadedCache = new DualHashBidiMap<>();
	private static Set<ClassFileInfo> falsePositiveCache = new HashSet<>();
	private static volatile boolean hasSearched;
	private static volatile boolean isSearching;
	private static WeakSet<ChangeListener> listenerList =
		WeakDataStructureFactory.createCopyOnReadWeakSet();

	/**
	 * Prevent class instantiation
	 */
	private ClassSearcher() {
		// do nothing
	}

	/**
	 * Searches the classpath and updates the list of available classes which satisfies the 
	 * internal class filter. When the search completes (and was not cancelled), any registered 
	 * change listeners are notified.
	 *
	 * @param monitor the progress monitor for the search
	 * @throws CancelledException if the operation was cancelled
	 */
	public static void search(TaskMonitor monitor) throws CancelledException {

		if (hasSearched) {
			log.trace("Already searched for classes: using cached results");
			return;
		}

		log.trace("Using restricted extension class loader? " + IS_USING_RESTRICTED_EXTENSIONS);

		Instant start = Instant.now();
		isSearching = true;

		if (Application.inSingleJarMode()) {
			log.trace("Single Jar Mode: using extensions from the jar file");
			extensionPointSuffixToInfoMap = loadExtensionClassesFromJar();
		}
		else {
			extensionPointSuffixToInfoMap = findClasses(monitor);
		}

		log.trace("Found extension classes {}", extensionPointSuffixToInfoMap);
		if (extensionPointSuffixToInfoMap.isEmpty()) {
			throw new AssertException("Unable to locate extension points!");
		}

		hasSearched = true;
		isSearching = false;

		Swing.runNow(() -> fireClassListChanged());

		String finishedMessage =
			"Class search complete (" + ChronoUnit.MILLIS.between(start, Instant.now()) + " ms)";
		monitor.setMessage(finishedMessage);
		log.info(finishedMessage);
	}

	/**
	 * Get {@link ExtensionPointProperties#priority() priority-sorted} classes that implement or
	 * derive from the given ancestor class
	 * 
	 * @param ancestorClass the ancestor class
	 * @return set of classes that implement or extend T
	 */
	public static <T> List<Class<? extends T>> getClasses(Class<T> ancestorClass) {
		return getClasses(ancestorClass, null);
	}

	/**
	 * Get {@link ExtensionPointProperties#priority() priority-sorted} classes that
	 * implement or derive from the given ancestor class
	 * 
	 * @param ancestorClass the ancestor class
	 * @param classFilter A Predicate that tests class objects (that are already of type T)
	 * 			for further filtering, {@code null} is equivalent to "return true"
	 * @return {@link ExtensionPointProperties#priority() priority-sorted} list of
	 * 			classes that implement or extend T and pass the filtering test performed by the
	 * 			predicate
	 */
	@SuppressWarnings("unchecked") // we checked the type of each use so we know the casts are safe
	public static <T> List<Class<? extends T>> getClasses(Class<T> ancestorClass,
			Predicate<Class<? extends T>> classFilter) {
		if (!hasSearched) {
			return List.of();
		}
		if (isSearching) {
			throw new IllegalStateException(
				"Cannot call the getClasses() while the ClassSearcher is searching!");
		}

		String suffix = getExtensionPointSuffix(ancestorClass.getName());
		if (suffix == null) {
			return List.of();
		}

		List<Class<? extends T>> list = new ArrayList<>();
		for (ClassFileInfo info : extensionPointSuffixToInfoMap.get(suffix)) {

			if (falsePositiveCache.contains(info)) {
				continue;
			}

			Class<?> c = loadedCache.get(info);
			if (c == null) {
				c = loadExtensionPoint(info.path(), info.name());
				ClassFileInfo existing = loadedCache.getKey(c);
				if (existing != null) {
					log.info(
						"Skipping load of class '%s' from '%s'. Already loaded from '%s'."
								.formatted(info.name(), info.path(), existing.path()));
				}
				if (c == null) {
					falsePositiveCache.add(info);
					continue;
				}
			}

			loadedCache.put(info, c);

			if (ancestorClass.isAssignableFrom(c) &&
				(classFilter == null || classFilter.test((Class<T>) c))) {
				list.add((Class<? extends T>) c);
			}
		}

		prioritizeClasses(list);
		return list;
	}

	/**
	 * Gets all {@link ExtensionPointProperties#priority() priority-sorted} class instances that 
	 * implement or derive from the given filter class
	 * 
	 * @param c the filter class
	 * @return {@link ExtensionPointProperties#priority() priority-sorted} {@link List} of 
	 *   class instances that implement or extend T
	 */
	public static <T> List<T> getInstances(Class<T> c) {
		return getInstances(c, filter -> true);
	}

	/**
	 * Get {@link ExtensionPointProperties#priority() priority-sorted} classes instances that 
	 * implement or derive from the given filter class and pass the given filter predicate
	 * 
	 * @param c the filter class
	 * @param filter A filter predicate that tests class objects (that are already of type T).
	 *   {@code null} is equivalent to "return true".
	 * @return {@link ExtensionPointProperties#priority() priority-sorted} {@link List} of class 
	 *   instances that implement or extend T and pass the filtering test performed by the predicate
	 */
	public static <T> List<T> getInstances(Class<T> c, ClassFilter filter) {
		List<Class<? extends T>> classes = getClasses(c);
		List<T> instances = new ArrayList<>();

		for (Class<? extends T> clazz : classes) {
			if (!filter.accepts(clazz)) {
				continue;
			}

			try {
				Constructor<? extends T> constructor = clazz.getConstructor((Class<?>[]) null);
				T t = constructor.newInstance((Object[]) null);
				instances.add(t);
			}
			catch (InstantiationException e) {
				Msg.showError(ClassSearcher.class, null, "Error Instantiating Extension Point",
					"Error creating class " + clazz.getSimpleName() + " for extension " +
						c.getName() +
						".  Discovered class is not a concrete implementation or does not " +
						"have a nullary constructor!",
					e);
			}
			catch (IllegalAccessException e) {
				Msg.showError(ClassSearcher.class, null, "Error Instantiating Extension Point",
					"Error creating class " + clazz.getSimpleName() + " for extension " +
						c.getName() +
						".  Discovered class does not have a public, default constructor!",
					e);
			}
			catch (SecurityException e) {
				String message = "Error creating class " + clazz.getSimpleName() +
					" for extension " + c.getName() + ".  Security Exception!";
				Msg.showError(ClassSearcher.class, null, "Error Instantiating Extension Point",
					message, e);

				throw new AssertException(message, e);
			}
			catch (Exception e) {
				Msg.showError(ClassSearcher.class, null, "Error Creating Extension Point",
					"Error creating class " + clazz.getSimpleName() +
						" when creating extension points for " + c.getName(),
					e);
			}
		}

		return instances;

	}

	/**
	 * Add a change listener that will be notified when the classpath
	 * is searched for new classes.
	 * <p><strong>Note:</strong> The listener list is implemented
	 * using WeakReferences. Therefore, the caller must maintain a handle to
	 * the listener being added, or else it will be garbage collected and
	 * never called.</p>
	 * @param l the listener to add
	 */
	public static void addChangeListener(ChangeListener l) {
		listenerList.add(l);
	}

	/**
	 * Remove the change listener
	 * @param l the listener to remove
	 */
	public static void removeChangeListener(ChangeListener l) {
		listenerList.remove(l);
	}

	/**
	 * Gets class information about each discovered potential extension point.
	 * <p>
	 * NOTE: A discovered potential extension point may end up not getting loaded if it is not
	 * "of interest" (see {@link #isClassOfInterest(Class)}. These are referred to as false
	 * positives.
	 * 
	 * @return A {@link Set} of class information about each discovered potential extension point
	 */
	public static Set<ClassFileInfo> getExtensionPointInfo() {
		return extensionPointSuffixToInfoMap.values()
				.stream()
				.flatMap(e -> e.stream())
				.collect(Collectors.toSet());
	}

	/**
	 * Gets class information about each loaded extension point.
	 * <p>
	 * NOTE: Ghidra may load more classes as it runs. Therefore, repeated calls to this method may
	 * return more results, as more extension points are loaded.
	 * 
	 * @return A {@link Set} of class information about each loaded extension point
	 */
	public static Set<ClassFileInfo> getLoaded() {
		return loadedCache.keySet();
	}

	/**
	 * Gets class information about discovered potential extension points that end up not getting
	 * loaded.
	 * <p>
	 * NOTE: Ghidra may load more classes as it runs. Therefore, repeated calls to this method may
	 * return more results, as more potential extension points are identified as false positives.
	 * 
	 * @return A {@link Set} of class information about each loaded extension point
	 */
	public static Set<ClassFileInfo> getFalsePositives() {
		return falsePositiveCache;
	}

	/**
	 * Gets the given class's extension point suffix.
	 * <p>
	 * Note that if multiple suffixes match, the smallest will be chosen. For a detailed
	 * explanation, see the comment inside {@link #loadExtensionPointSuffixes()}.
	 * 
	 * @param className The name of the potential extension point class
	 * @return The given class's extension point suffix, or null if it is not an extension point or
	 *   {@link #search(TaskMonitor)} has not been called yet
	 */
	public static String getExtensionPointSuffix(String className) {
		if (extensionPointSuffixPattern == null) {
			extensionPointSuffixPattern = loadExtensionPointSuffixes();
		}
		if (className.contains("$") || className.endsWith("Test")) {
			return null;
		}
		int packageIndex = className.lastIndexOf('.');
		if (packageIndex > 0) {
			className = className.substring(packageIndex + 1);
		}
		Matcher m = extensionPointSuffixPattern.matcher(className);
		return m.find() && m.groupCount() == 1 ? m.group(1) : null;
	}

	/**
	 * Checks to see if the given class is an extension point of interest.
	 * 
	 * @param c The class to check.
	 * @return True if the given class is an extension point of interest; otherwise, false.
	 */
	public static boolean isClassOfInterest(Class<?> c) {
		if (Modifier.isAbstract(c.getModifiers())) { // we don't support abstract (includes interfaces)
			return false;
		}
		if (c.getEnclosingClass() != null) { // we don't support inner classes
			return false;
		}
		if (!Modifier.isPublic(c.getModifiers())) { // we don't support non-public
			return false;
		}
		if (ExtensionPointProperties.Util.isExcluded(c)) {
			return false;
		}

		for (Class<?> filterClass : FILTER_CLASSES) {
			if (filterClass.isAssignableFrom(c)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Writes the current class searcher statistics to the info log
	 */
	public static void logStatistics() {
		log.info("Class searcher loaded %d extension points (%d false positives)"
				.formatted(loadedCache.size(), falsePositiveCache.size()));
	}

	/**
	 * Scans the disk to find potential extension point class files. Matching is performed by file
	 * name only. The class files are not opened or loaded by this method.
	 * 
	 * @param monitor the progress monitor for the disk scan
	 * @return A {@link Map} of discovered {@link ClassFileInfo class information}, keyed by their
	 *   extension point suffix
	 * @throws CancelledException if the user cancelled the operation
	 */
	private static Map<String, Set<ClassFileInfo>> findClasses(TaskMonitor monitor)
			throws CancelledException {
		log.info("Searching for classes...");

		Set<ClassDir> classDirs = new HashSet<>();
		Set<ClassJar> classJars = new HashSet<>();

		for (String searchPath : gatherSearchPaths()) {
			String lcSearchPath = searchPath.toLowerCase();
			File searchFile = new File(searchPath);
			if ((lcSearchPath.endsWith(".jar") || lcSearchPath.endsWith(".zip")) &&
				searchFile.exists()) {

				if (ClassJar.ignoreJar(searchPath)) {
					log.trace("Ignoring jar file: {}", searchPath);
					continue;
				}

				log.trace("Searching jar file: {}", searchPath);
				classJars.add(new ClassJar(searchPath, monitor));
			}
			else if (searchFile.isDirectory()) {
				log.trace("Searching classpath directory: {}", searchPath);
				classDirs.add(new ClassDir(searchPath, monitor));
			}
		}

		Set<ClassFileInfo> classSet = new HashSet<>();
		for (ClassDir dir : classDirs) {
			monitor.checkCancelled();
			dir.getClasses(classSet, monitor);
		}
		for (ClassJar jar : classJars) {
			monitor.checkCancelled();
			jar.getClasses(classSet, monitor);
		}

		return classSet.stream()
				.collect(Collectors.groupingBy(ClassFileInfo::suffix, Collectors.toSet()));
	}

	/**
	 * Sorts the given {@link List} of {@link Class}es first by their defined priority, then by
	 * their name.
	 * 
	 * @param list The {@link List} of {@link Class}es to sort. This {@link List} will be modified.
	 */
	private static <T> void prioritizeClasses(List<Class<? extends T>> list) {
		Collections.sort(list, (c1, c2) -> {
			// Sort classes primarily by priority and secondarily by name
			int p1 = ExtensionPointProperties.Util.getPriority(c1);
			int p2 = ExtensionPointProperties.Util.getPriority(c2);
			if (p1 > p2) {
				return -1;
			}
			if (p1 < p2) {
				return 1;
			}
			return c1.getName().compareTo(c2.getName());
		});
	}

	private static List<String> gatherSearchPaths() {

		//
		// By default all classes are found on the standard classpath.  In the default mode, there
		// are no values associated with the GhidraClassLoader.CP_EXT property.  Alternatively, 
		// users can enable Extension classpath restriction.  In this mode, any Extension module's 
		// jar files will *not* be on the standard classpath, but instead will be on CP_EXT.
		//
		List<String> rawPaths = new ArrayList<>();
		getPropertyPaths(GhidraClassLoader.CP, rawPaths);
		getPropertyPaths(GhidraClassLoader.CP_EXT, rawPaths);
		return canonicalizePaths(rawPaths);
	}

	private static void getPropertyPaths(String property, List<String> results) {
		String paths = System.getProperty(property);
		log.trace("Paths in {}: {}", property, paths);
		if (StringUtils.isBlank(paths)) {
			return;
		}

		StringTokenizer st = new StringTokenizer(paths, File.pathSeparator);
		while (st.hasMoreTokens()) {
			results.add(st.nextToken());
		}
	}

	private static List<String> canonicalizePaths(Collection<String> paths) {

		//@formatter:off
		List<String> canonical = paths.stream()
			 .map(path -> {
				 String normalized = normalize(path);
				 return normalized;
			 })
			 .collect(Collectors.toList());
		//@formatter:on

		return canonical;
	}

	private static String normalize(String path) {

		try {
			Path p = Paths.get(path);
			Path normalized = p.normalize();
			Path absolutePath = normalized.toAbsolutePath();
			return absolutePath.toString();
		}
		catch (InvalidPathException e) {
			// we have seen odd strings being placed into the classpath--ignore them, as we
			// don't know how to use them
			log.trace("Invalid path '{}'", path);
			return path;
		}
	}

	private static Map<String, Set<ClassFileInfo>> loadExtensionClassesFromJar() {
		ResourceFile appRoot = Application.getApplicationRootDirectory();
		ResourceFile extensionClassesFile = new ResourceFile(appRoot, "EXTENSION_POINT_CLASSES");
		try {
			List<String> classNames = FileUtilities.getLines(extensionClassesFile);
			Set<ClassFileInfo> extensionClasses = new HashSet<>();
			for (String className : classNames) {
				String epName = getExtensionPointSuffix(className);
				if (epName != null) {
					extensionClasses
							.add(new ClassFileInfo(appRoot.getAbsolutePath(), className, epName));
				}
			}
			return extensionClasses.stream()
					.collect(Collectors.groupingBy(ClassFileInfo::suffix, Collectors.toSet()));

		}
		catch (IOException e) {
			throw new AssertException(
				"Unexpected IOException reading extension class file " + extensionClassesFile, e);
		}
	}

	private static Pattern loadExtensionPointSuffixes() {
		Set<String> extensionPointSuffixes = new HashSet<>();

		Collection<ResourceFile> moduleRootDirectories = Application.getModuleRootDirectories();
		if (moduleRootDirectories.isEmpty()) {
			throw new AssertException("Could not find modules for Class Searcher!");
		}

		log.trace("Scanning module root directories: {}", moduleRootDirectories);

		for (ResourceFile moduleRoot : moduleRootDirectories) {
			ResourceFile file = new ResourceFile(moduleRoot, "data/ExtensionPoint.manifest");
			if (file.exists()) {
				extensionPointSuffixes.addAll(FileUtilities.getLinesQuietly(file));
			}
		}

		// Build regex of the form .*(suffix1|suffix2|suffix3|...)$
		// If one suffix ends with another suffix, precedence should be given to the shorter one.
		// This will result in some false positives, but will prevent some corner error cases as
		// described in this example:
		// There are 2 valid suffixes, Plugin and BobPlugin. Someone makes a new class:
		//
		//     class BillBobPlugin extends Plugin
		//
		// The person who made this class was unaware that BobPlugin was also a valid suffix. If
		// we were to match on the longest suffix, BillBobPlugin would erroneously be associated
		// with BobPlugin, and getClasses() would fail. Now consider this example:
		//
		//     class BillBobPlugin extends BobPlugin
		//
		// Since BillBobPlugin will be associated with the shorter "Plugin" suffix, it will be
		// grouped with the other Plugin extension points.  However, when getClasses(BobPlugin.class)
		// is called, we retrieve the same shortest suffix from the given "BobPlugin" class name, 
		// which is Plugin. This will result in BillBobPlugin getting properly discovered from the
		// Plugin group. Final checks are performed to make sure the provided class is assignable
		// from any class in the group, which filters out the bad associations.
		StringBuilder buffy = new StringBuilder(".*(");
		String between = "";
		for (String suffix : extensionPointSuffixes) {
			suffix = suffix.trim();
			if (suffix.isEmpty()) {
				continue;
			}

			buffy.append(between);
			buffy.append(suffix);
			between = "|";
		}
		buffy.append(")$");
		log.trace("Using extension point pattern: {}", buffy);
		return Pattern.compile(buffy.toString());
	}

	private static void fireClassListChanged() {
		for (ChangeListener listener : listenerList) {
			try {
				listener.stateChanged(null);
			}
			catch (Throwable t) {
				Msg.showError(ClassSearcher.class, null, "Exception",
					"Error in listener for class list changed", t);
			}
		}
	}

	/**
	 * If the given class name matches the known extension name patterns, then this method will try
	 * to load that class using the provided path.   Extensions may be loaded using their own 
	 * class loader, depending on the system property 
	 * {@link GhidraClassLoader#ENABLE_RESTRICTED_EXTENSIONS_PROPERTY}.
	 * <p>
	 * Examples: 
	 * <pre>
	 * /foo/bar/baz/file.jar fully.qualified.ClassName
	 * /foo/bar/baz/bin fully.qualified.ClassName
	 * </pre>
	 * 
	 * @param path the jar or dir path
	 * @param className the fully qualified class name
	 * @return the class if it is an extension point
	 */
	private static Class<?> loadExtensionPoint(String path, String className) {

		if (getExtensionPointSuffix(className) == null) {
			return null;
		}

		ClassLoader classLoader = getClassLoader(path);

		try {
			Class<?> c = Class.forName(className, true, classLoader);
			if (isClassOfInterest(c)) {
				return c;
			}
		}
		catch (Throwable t) {
			processClassLoadError(path, className, t);
		}

		return null;
	}

	private static ClassLoader getClassLoader(String path) {
		ClassLoader classLoader = ClassSearcher.class.getClassLoader();
		if (!IS_USING_RESTRICTED_EXTENSIONS) {
			return classLoader; // custom extension class loader is disabled
		}

		ExtensionDetails extension = ExtensionUtils.getExtension(path);
		if (extension != null) {
			log.trace(() -> "Installing custom extension class loader for: " +
				Json.toStringFlat(extension));
			classLoader = new ExtensionModuleClassLoader(extension);
		}
		return classLoader;
	}

	private static void processClassLoadError(String path, String name, Throwable t) {

		if (t instanceof LinkageError) {
			// We see this sometimes when loading classes that match our naming convention for
			// extension points, but are actually extending 3rd party libraries.  For now, do 
			// not make noise in the log for this case.
			log.trace("LinkageError loading class {}; Incompatible class version? ", name, t);
			return;
		}

		if (!(t instanceof ClassNotFoundException)) {
			log.error("Error loading class {} - {}", name, t.getMessage(), t);
			return;
		}

		processClassNotFoundExcepetion(path, name, (ClassNotFoundException) t);
	}

	private static void processClassNotFoundExcepetion(String path, String name,
			ClassNotFoundException t) {

		if (!isModuleEntryMissingFromClasspath(path)) {
			// not sure if this can actually happen--it implies a half-built Eclipse issue
			log.error("Error loading class {} - {}", name, t.getMessage(), t);
			return;
		}

		// We have a special case: we know a module class was loaded, but it is not in our
		// classpath.  This can happen in Eclipse when we scan all modules, but the launcher does
		// not include all modules.
		if (SystemUtilities.isInTestingMode()) {
			// ignore the error in testing mode, as many modules are not loaded for any given test
			return;
		}

		log.error("Module class is missing from the classpath.\n\tUpdate your launcher " +
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
}
