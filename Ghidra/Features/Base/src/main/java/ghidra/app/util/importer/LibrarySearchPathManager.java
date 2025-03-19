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

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.util.*;

import ghidra.app.util.opinion.Loader;
import ghidra.formats.gfilesystem.*;
import ghidra.framework.Platform;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.Project;
import ghidra.framework.options.SaveState;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A simple class for managing the library search path and avoiding duplicate directories.
 */
public class LibrarySearchPathManager {

	private static final String LIBRARY_SEARCH_PATH_STATE_NAME = "Library Search Paths";
	private static Set<String> pathSet = initialize();

	/**
	 * Returns an array of library search paths
	 * 
	 * @return an array of library search paths
	 */
	public static synchronized String[] getLibraryPaths() {
		String[] paths = new String[pathSet.size()];
		pathSet.toArray(paths);
		return paths;
	}

	/**
	 * Returns a {@link List} of {@link FSRL}s to search for libraries
	 * 
	 * @param program The {@link Program} being loaded
	 * @param log The log
	 * @param monitor A cancellable monitor
	 * @return a {@link List} of {@link FSRL}s to search for libraries
	 * @throws CancelledException if the user cancelled the operation
	 */
	public static synchronized List<FSRL> getLibraryFsrlList(Program program, MessageLog log,
			TaskMonitor monitor) throws CancelledException {
		FileSystemService fsService = FileSystemService.getInstance();
		List<FSRL> fsrlList = new ArrayList<>();
		for (String path : pathSet) {
			monitor.checkCancelled();
			path = path.trim();
			FSRL fsrl = null;
			try {
				if (path.equals(".")) {
					FSRL providerFsrl = FSRL.fromProgram(program);
					if (providerFsrl != null) {
						try (RefdFile fileRef = fsService.getRefdFile(providerFsrl, monitor)) {
							GFile parentFile = fileRef.file.getParentFile();
							fsrl = parentFile.getFSRL();
						}
						catch (IOException e) {
							log.appendMsg("Skipping '.' search path: ", e.getMessage());
							continue;
						}
					}
				}
				else {
					fsrl = FSRL.fromString(path);
				}
			}
			catch (MalformedURLException e) {
				try {
					File f = new File(path);
					if (f.exists() && f.isAbsolute()) {
						fsrl = fsService.getLocalFSRL(f.getCanonicalFile());
					}
				}
				catch (IOException e2) {
					log.appendException(e2);
				}
			}
			if (fsrl != null) {
				fsrlList.add(fsrl);
			}
		}
		return fsrlList;
	}

	/**
	 * Sets the library search paths to the given array
	 * 
	 * @param paths the new library search paths
	 */
	public static synchronized void setLibraryPaths(String[] paths) {
		pathSet.clear();
		pathSet.addAll(Arrays.asList(paths));
		saveState();
	}

	/**
	 * Adds the specified library search path path to the end of the path search list
	 * 
	 * @param path the library search path to add
	 * @return true if the path was appended, false if the path was a duplicate
	 */
	public static synchronized boolean addPath(String path) {
		if (pathSet.contains(path)) {
			return false;
		}
		pathSet.add(path);
		saveState();
		return true;
	}

	/**
	 * Resets the library search path to the default values
	 */
	public static synchronized void reset() {
		pathSet = loadDefaultPaths();
		saveState();
	}

	private LibrarySearchPathManager() {
		// Prevent instantiation of utility class
	}

	private static synchronized Set<String> initialize() {
		Set<String> set = loadFromSavedState();
		if (set == null) {
			set = loadDefaultPaths();
		}
		return set;
	}

	private static synchronized Set<String> loadDefaultPaths() {
		Set<String> set = new LinkedHashSet<>();

		// Add program import location
		set.add(".");

		// Add platform specific locations
		Platform.CURRENT_PLATFORM.getAdditionalLibraryPaths().forEach(p -> set.add(p));

		// Add Java library path locations
		String libpath = System.getProperty("java.library.path");
		String libpathSep = System.getProperty("path.separator");
		StringTokenizer nizer = new StringTokenizer(libpath, libpathSep);
		while (nizer.hasMoreTokens()) {
			String path = nizer.nextToken();
			set.add(path);
		}

		return set;
	}

	private static synchronized Set<String> loadFromSavedState() {
		Project project = AppInfo.getActiveProject();
		if (project != null) {
			SaveState saveState = project.getSaveableData(Loader.OPTIONS_PROJECT_SAVE_STATE_KEY);
			if (saveState != null) {
				String[] paths = saveState.getStrings(LIBRARY_SEARCH_PATH_STATE_NAME, null);
				if (paths != null) {
					return new LinkedHashSet<String>(Arrays.asList(paths));
				}
			}
		}
		return null;
	}

	private static synchronized void saveState() {
		Project project = AppInfo.getActiveProject();
		if (project != null) {
			SaveState saveState = project.getSaveableData(Loader.OPTIONS_PROJECT_SAVE_STATE_KEY);
			if (saveState == null) {
				saveState = new SaveState();
				project.setSaveableData(Loader.OPTIONS_PROJECT_SAVE_STATE_KEY, saveState);
			}
			saveState.putStrings(LIBRARY_SEARCH_PATH_STATE_NAME, pathSet.toArray(new String[0]));
		}
	}
}
