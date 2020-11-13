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

import static ghidra.util.StringUtilities.*;

import java.io.File;
import java.io.IOException;
import java.util.*;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.io.FilenameUtils;

import generic.jar.ResourceFile;
import ghidra.framework.Application;
import ghidra.framework.preferences.Preferences;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import utility.application.ApplicationLayout;

class ClassJar extends ClassLocation {

	/** 
	 * Pattern for matching jar files in a module lib dir
	 * <p>
	 * The pattern roughly states to accept any path that contains <tt>lib</tt> or 
	 * <tt>build/libs</tt>, ending in <tt>.jar</tt> (non-capturing) and then 
	 * grab that dir's parent and the name of the jar file.
	 */
	private static final Pattern ANY_MODULE_LIB_JAR_FILE_PATTERN =
		Pattern.compile(".*/(.*)/(?:lib|build/libs)/(.+).jar");

	private static final String PATCH_DIR_PATH_FORWARD_SLASHED = getPatchDirPath();
	private static final Set<String> USER_PLUGIN_PATHS = loadUserPluginPaths();

	private String path;

	ClassJar(String path, TaskMonitor monitor) throws CancelledException {
		this.path = path;
		loadUserPluginPaths();

		scanJar(monitor);
	}

	@Override
	void getClasses(Set<Class<?>> set, TaskMonitor monitor) {
		checkForDuplicates(set);
		set.addAll(classes);
	}

	private void scanJar(TaskMonitor monitor) throws CancelledException {

		File file = new File(path);

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
		// Dev Mode - don't scan 3rd-party jar files
		//
		if (containsAnyIgnoreCase(pathName, "ExternalLibraries", "caches", "flatrepo")) {
			return true;
		}

		//
		// Dev Mode - let everything else through
		// 
		if (SystemUtilities.isInDevelopmentMode()) {
			return false;
		}

		//
		// Production Mode - old style (before Extensions) of user contributions
		//
		String forwardSlashedPathName = pathName.replaceAll("\\\\", "/");
		if (isUserPluginJar(forwardSlashedPathName)) {
			return false;
		}

		// 
		// Production Mode - allow users to enter code in the 'patch' directory
		//		
		if (isPatchJar(forwardSlashedPathName)) {
			return false;
		}

		//
		// Production Mode - In production, only module lib jar files are scanned
		//
		if (isModuleDependencyJar(forwardSlashedPathName)) {
			return false;
		}

		// this is typically a 3rd-party jar file
		return true;
	}

	private static boolean isUserPluginJar(String pathName) {
		return USER_PLUGIN_PATHS.contains(pathName);
	}

	// Note: the path is expected to be using forward slashes
	private static boolean isPatchJar(String pathName) {
		String jarDirectory = FilenameUtils.getFullPathNoEndSeparator(pathName);
		return jarDirectory.equalsIgnoreCase(PATCH_DIR_PATH_FORWARD_SLASHED);
	}

	// Note: the path is expected to be using forward slashes
	private static boolean isModuleDependencyJar(String pathName) {

		if (ClassSearcher.SEARCH_ALL_JARS) {
			return true; // this will search all jar files
		}

		// Note: the path is expected to be using forward slashes
		Matcher matcher = ANY_MODULE_LIB_JAR_FILE_PATTERN.matcher(pathName);
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
		if (!name.endsWith(CLASS_EXT)) {
			return;
		}
		name = name.substring(0, name.indexOf(CLASS_EXT));
		name = name.replace('/', '.');

		Class<?> c = ClassFinder.loadExtensionPoint(path, name);
		if (c != null) {
			classes.add(c);
		}
	}

	@Override
	public String toString() {
		return path;
	}

	private static String getPatchDirPath() {
		ApplicationLayout layout = Application.getApplicationLayout();
		ResourceFile patchDir = layout.getPatchDir();
		if (patchDir == null) {
			return "<no patch dir>"; // not in a distribution
		}
		String patchPath = patchDir.getAbsolutePath();
		String forwardSlashed = patchPath.replaceAll("\\\\", "/");
		return forwardSlashed;
	}

	private static Set<String> loadUserPluginPaths() {
		Set<String> result = new HashSet<>();
		String[] paths = Preferences.getPluginPaths();
		for (String pathName : paths) {
			// note: lower case because our client uses lower case for paths
			String forwardSlashed = pathName.replaceAll("\\\\", "/").toLowerCase();
			result.add(forwardSlashed);
		}
		return Collections.unmodifiableSet(result);
	}

}
