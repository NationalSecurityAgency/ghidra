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
import java.nio.file.*;
import java.util.*;
import java.util.function.Predicate;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import javax.swing.event.ChangeListener;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import generic.jar.ResourceFile;
import ghidra.framework.Application;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.datastruct.WeakDataStructureFactory;
import ghidra.util.datastruct.WeakSet;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import utilities.util.FileUtilities;

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

	// This provides a means for custom apps that do not use a module structure to search all jars
	public static final String SEARCH_ALL_JARS_PROPERTY = "class.searcher.search.all.jars";
	private static final String SEARCH_ALL_JARS_PROPERTY_VALUE =
		System.getProperty(SEARCH_ALL_JARS_PROPERTY, Boolean.FALSE.toString());
	static final boolean SEARCH_ALL_JARS = Boolean.parseBoolean(SEARCH_ALL_JARS_PROPERTY_VALUE);

	static final Logger log = LogManager.getLogger(ClassSearcher.class);

	private static ClassFinder searcher;
	private static List<Class<?>> extensionPoints;

	private static WeakSet<ChangeListener> listenerList =
		WeakDataStructureFactory.createCopyOnReadWeakSet();

	private static Pattern extensionPointSuffixPattern;

	private static volatile boolean hasSearched;
	private static volatile boolean isSearching;
	private static final ClassFilter DO_NOTHING_FILTER = c -> true;

	private ClassSearcher() {
		// you cannot create one of these
	}

	/**
	 * Get {@link ExtensionPointProperties#priority() priority-sorted} classes that implement or 
	 * derive from the given class
	 * 
	 * @param c the filter class
	 * @return set of classes that implement or extend T
	 */
	public static <T> List<Class<? extends T>> getClasses(Class<T> c) {
		return getClasses(c, null);
	}

	/**
	 * Get {@link ExtensionPointProperties#priority() priority-sorted} classes that 
	 * implement or derive from the given class
	 * 
	 * @param c the filter class
	 * @param classFilter A Predicate that tests class objects (that are already of type T)
	 * 			for further filtering, <code>null</code> is equivalent to "return true"
	 * @return {@link ExtensionPointProperties#priority() priority-sorted} list of 
	 * 			classes that implement or extend T and pass the filtering test performed by the 
	 * 			predicate
	 */
	@SuppressWarnings("unchecked") // we checked the type of each use so we know the casts are safe
	public static <T> List<Class<? extends T>> getClasses(Class<T> c,
			Predicate<Class<? extends T>> classFilter) {
		if (isSearching) {
			throw new IllegalStateException(
				"Cannot call the getClasses() while the ClassSearcher is searching!");
		}

		List<Class<? extends T>> list = new ArrayList<>();
		if (extensionPoints == null) {
			return list;
		}

		for (Class<?> extensionPoint : extensionPoints) {
			if (c.isAssignableFrom(extensionPoint) &&
				(classFilter == null || classFilter.test((Class<T>) extensionPoint))) {
				list.add((Class<? extends T>) extensionPoint);
			}
		}
		return list;
	}

	public static <T> List<T> getInstances(Class<T> c) {
		return getInstances(c, DO_NOTHING_FILTER);
	}

	/**
	 * Get {@link ExtensionPointProperties#priority() priority-sorted} classes 
	 * instances that implement or derive from the given class
	 * 
	 * @param c the filter class
	 * @param filter A Predicate that tests class objects (that are already of type T)
	 * 			for further filtering, <code>null</code> is equivalent to "return true"
	 * @return {@link ExtensionPointProperties#priority() priority-sorted} list of 
	 * 			classes instances that implement or extend T and pass the filtering test performed by 
	 *          the predicate
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
	 * Searches the classpath and updates the list of available classes which
	 * satisfy the class filter.  Classes which
	 * data types, and language providers. When the search completes and was
	 * not cancelled, the change listeners are notified.
	 *
	 * @param forceRefresh if true the class cache is ignored and the search is performed
	 * 		  from scratch.
	 * @param monitor the progress monitor for the search.
	 * @throws CancelledException if the operation is cancelled
	 */
	public static void search(boolean forceRefresh, TaskMonitor monitor) throws CancelledException {

		if (hasSearched && !forceRefresh) {
			log.trace("Already searched for classes: using cached results");
			return;
		}

		if (Application.inSingleJarMode()) {
			log.trace("Single Jar Mode: using extensions from the jar file");
			loadExtensionClassesFromJar();
			return;
		}

		isSearching = true;

		loadExtensionPointSuffixes();

		extensionPoints = null;

		long t = (new Date()).getTime();

		log.trace("Searching for classes...");
		List<String> searchPaths = gatherSearchPaths();
		searcher = new ClassFinder(searchPaths, monitor);

		monitor.setMessage("Loading classes...");
		extensionPoints = searcher.getClasses(monitor);
		log.trace("Found extension classes {}", extensionPoints);
		if (extensionPoints.isEmpty()) {
			throw new AssertException("Unable to location extension points!");
		}

		hasSearched = true;
		isSearching = false;

		SystemUtilities.runSwingNow(() -> fireClassListChanged());

		t = (new Date()).getTime() - t;
		String finishedMessage = "Class search complete (" + t + " ms)";
		monitor.setMessage(finishedMessage);
		log.info(finishedMessage);
	}

	private static List<String> gatherSearchPaths() {
		String cp = System.getProperty("java.class.path");
		StringTokenizer st = new StringTokenizer(cp, File.pathSeparator);
		List<String> rawPaths = new ArrayList<>();
		while (st.hasMoreTokens()) {
			rawPaths.add(st.nextToken());
		}

		List<String> canonicalPaths = canonicalizePaths(rawPaths);
		return canonicalPaths;
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
			Msg.trace(ClassSearcher.class, "Invalid path '" + path + "'", e);
			return path;
		}
	}

	private static void loadExtensionClassesFromJar() {
		ResourceFile appRoot = Application.getApplicationRootDirectory();
		ResourceFile extensionClassesFile = new ResourceFile(appRoot, "EXTENSION_POINT_CLASSES");
		try {
			List<String> classNames = FileUtilities.getLines(extensionClassesFile);
			List<Class<?>> extensionClasses = new ArrayList<>();
			for (String className : classNames) {
				try {
					Class<?> clazz = Class.forName(className);
					extensionClasses.add(clazz);
				}
				catch (ClassNotFoundException e) {
					Msg.warn(ClassSearcher.class, "Can't load extension point: " + className);
				}
			}
			extensionPoints = Collections.unmodifiableList(extensionClasses);

		}
		catch (IOException e) {
			throw new AssertException("Unexpected IOException reading extension class file " +
				extensionClassesFile, e);
		}
	}

	private static void loadExtensionPointSuffixes() {
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
		buffy.append(')');
		extensionPointSuffixPattern = Pattern.compile(buffy.toString());
		log.trace("Using extension point pattern: {}", extensionPointSuffixPattern);
	}

	static boolean isExtensionPointName(String name) {
		if (name.indexOf("Test$") > 0 || name.endsWith("Test")) {
			return false;
		}
		int packageIndex = name.lastIndexOf('.');
		int innerClassIndex = name.lastIndexOf('$');
		int maximumIndex = StrictMath.max(packageIndex, innerClassIndex);
		if (maximumIndex > 0) {
			name = name.substring(maximumIndex + 1);
		}
		return extensionPointSuffixPattern.matcher(name).matches();
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
}
