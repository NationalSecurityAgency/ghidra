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
package ghidra.app.util.importer;

import java.util.*;

import ghidra.framework.Platform;

/**
 * A simple class for managing the library search path
 * and avoiding duplicate directories.
 */
public class LibrarySearchPathManager {
	public final static String CURRENT_DIRECTORY = ".";

	private static List<String> pathList = createPathList();

	private static boolean hasBeenRestored;

	private static List<String> createPathList() {
		pathList = new ArrayList<>();
		loadJavaLibraryPath();
		return pathList;
	}

	private static void loadJavaLibraryPath() {
		addPath(CURRENT_DIRECTORY);//add current directory

		List<String> paths = Platform.CURRENT_PLATFORM.getAdditionalLibraryPaths();
		for (String path : paths) {
			addPath(path);
		}

		String libpath = System.getProperty("java.library.path");
		String libpathSep = System.getProperty("path.separator");

		StringTokenizer nizer = new StringTokenizer(libpath, libpathSep);
		while (nizer.hasMoreTokens()) {
			String path = nizer.nextToken();
			addPath(path);
		}
	}

	/**
	 * Returns an array of directories to search for libraries
	 * @return an array of directories to search for libraries
	 */
	public static String[] getLibraryPaths() {
		String[] paths = new String[pathList.size()];
		pathList.toArray(paths);
		return paths;
	}

	/**
	 * Returns an array of directories to search for libraries
	 * @return a list of directories to search for libraries
	 */
	public static List<String> getLibraryPathsList() {
		return new ArrayList<>(pathList);
	}

	/**
	 * Sets the directories to search for libraries
	 * @param paths the new library search paths
	 */
	public static void setLibraryPaths(String[] paths) {

		pathList.clear();
		addPath(CURRENT_DIRECTORY);//add current directory
		for (String path : paths) {
			addPath(path);
		}
	}

	/**
	 * Call this to restore paths that were previously persisted.  If you really need to change
	 * the paths <b>for the entire JVM</b>, then call {@link #setLibraryPaths(String[])}.
	 *
	 * @param paths the paths to restore
	 */
	public static void restoreLibraryPaths(String[] paths) {

		if (hasBeenRestored) {
			//
			// We code that restores paths from tool config files.  It is a mistake to do this
			// every time we load a tool, as the values can get out-of-sync if tools do not
			// save properly.  Logically, we only need to restore once.
			//
			return;
		}

		setLibraryPaths(paths);
	}

	/**
	 * Adds the specified path to the end of the path search list.
	 * @param path the path to add
	 * @return true if the path was appended, false if the path was a duplicate
	 */
	public static boolean addPath(String path) {
		if (pathList.indexOf(path) == -1) {
			pathList.add(path);
			return true;
		}
		return false;
	}

	/**
	 * Adds the path at the specified index in path search list.
	 * @param path the path to add
	 * @return true if the path was appended, false if the path was a duplicate
	 */
	public static boolean addPathAt(int index, String path) {
		if (pathList.indexOf(path) == -1) {
			pathList.add(index, path);
			return true;
		}
		return false;
	}

	/**
	 * Removes the path from the path search list.
	 * @param path the path the remove
	 * @return true if the path was removed, false if the path did not exist
	 */
	public static boolean removePath(String path) {
		if (path.equals(CURRENT_DIRECTORY)) {
			return false;
		}
		return pathList.remove(path);
	}

	/**
	 * Resets the library search path to match the system search paths.
	 */
	public static void reset() {
		pathList.clear();
		loadJavaLibraryPath();
	}

	/**
	 * Clears all paths.
	 */
	public static void clear() {
		pathList.clear();
	}
}
