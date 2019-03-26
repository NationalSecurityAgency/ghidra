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
import java.util.*;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

class ClassJar {

	/** 
	 * Pattern for matching jar files in a module lib dir
	 * <p>
	 * The pattern roughly states to accept any path that contains <tt>lib</tt> or 
	 * <tt>build/libs</tt>, ending in <tt>.jar</tt> (non-capturing) and then 
	 * grab that dir's parent and the name of the jar file.
	 */
	private static Pattern ANY_MODULE_LIB_JAR_FILE_PATTERN =
		Pattern.compile(".*/(.*)/(?:lib|build/libs)/(.+).jar");

	private String path;
	private long time;
	private Set<String> classNameList = new HashSet<>();
	private Set<Class<?>> classes = null;

	ClassJar(String path, TaskMonitor monitor) throws CancelledException {
		this.path = path;

		scan(monitor);
	}

	String getJarPath() {
		return path;
	}

	boolean rescan(TaskMonitor monitor) throws CancelledException {
		File file = new File(path);
		if (file.lastModified() != time) {
			scan(monitor);
			return true;
		}
		return false;
	}

	void getClasses(Set<Class<?>> list, TaskMonitor monitor) {
		if (classes == null) {
			ClassLoader classLoader = ClassSearcher.class.getClassLoader();
			classes = new HashSet<>();
			Iterator<String> iter = classNameList.iterator();
			while (iter.hasNext()) {
				String name = iter.next();
				try {
					monitor.setMessage("loading class: " + name);
					classes.add(Class.forName(name, true, classLoader));
				}
				catch (Throwable t) {
					Msg.showError(this, null, "Error loading class",
						"Error loading class " + name + ":", t);
				}
			}
		}
		list.addAll(classes);
	}

	private void scan(TaskMonitor monitor) throws CancelledException {
		classes = new HashSet<>();
		classNameList.clear();

		File file = new File(path);
		time = file.lastModified();

		try (JarFile jarFile = new JarFile(file)) {

			String pathName = jarFile.getName();
			int separatorIndex = pathName.lastIndexOf(File.separator);
			String jarFilename = pathName.substring(separatorIndex + 1);
			monitor.setMessage("Scanning jar: " + jarFilename);

			Enumeration<JarEntry> entries = jarFile.entries();
			while (entries.hasMoreElements()) {
				monitor.checkCanceled();
				processClassFiles(entries.nextElement());
			}
		}
		catch (IOException e) {
			Msg.error(this, "Error reading jarFile: " + path, e);
		}
	}

	static boolean ignoreJar(String pathName) {

		//
		// Note: keep this algorithm simple enough that users can add their own plugins via
		//       jar files.		
		//

		//
		// Dev Mode
		// 
		if (pathName.contains("ExternalLibraries")) {
			return true;
		}

		//
		// Production Mode - In production, only module lib jar files are scanned.
		//
		if (isModuleDependencyJar(pathName)) {
			return false;
		}

		return true;
	}

	static boolean isModuleDependencyJar(String pathName) {

		if (ClassSearcher.SEARCH_ALL_JARS) {
			return true; // this will search all jar files
		}

		String forwardSlashed = pathName.replaceAll("\\\\", "/");
		Matcher matcher = ANY_MODULE_LIB_JAR_FILE_PATTERN.matcher(forwardSlashed);
		if (!matcher.matches()) {
			return false;
		}

		String moduleName = matcher.group(1);
		String jarName = matcher.group(2);

		// handle a name match, as well as an extension jar (e.g., /Base/lib/Base_ext.jar)
		return jarName.startsWith(moduleName);
	}

	private void processClassFiles(JarEntry entry) {

		String name = entry.getName();
		if (!name.endsWith(".class")) {
			return;
		}
		name = name.substring(0, name.indexOf(".class"));
		name = name.replace('/', '.');

		Class<?> c = ClassFinder.loadExtensionPoint(path, name);
		if (c != null) {
			classNameList.add(name);
			classes.add(c);
		}
	}

	@Override
	public String toString() {
		return path;
	}
}
