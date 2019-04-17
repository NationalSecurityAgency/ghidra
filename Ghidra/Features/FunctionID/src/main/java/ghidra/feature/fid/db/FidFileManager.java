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
package ghidra.feature.fid.db;

import java.io.File;
import java.io.IOException;
import java.util.*;
import java.util.concurrent.CopyOnWriteArraySet;

import javax.swing.event.ChangeListener;

import generic.jar.ResourceFile;
import generic.util.Path;
import ghidra.framework.Application;
import ghidra.framework.preferences.Preferences;
import ghidra.program.model.lang.Language;
import ghidra.util.datastruct.WeakDataStructureFactory;
import ghidra.util.datastruct.WeakSet;
import ghidra.util.exception.VersionException;

/**
 * Manages the set of FidFiles for the application. This uses the singleton pattern and
 * all users of Fid databases must use this to get open Fid databases.  This ensures that
 * there is only one updateable Fid database open for any given FidFile.
 */
public class FidFileManager {

	private static final String SEPARATOR = ";";
	private static final String INACTIVE_FID_FILES = "FID.INACTIVE";
	private static final String USER_ADDED_FILES = "FID.USER.ADDED";

	private static FidFileManager THE_FID_FILE_MANAGER;

	private Set<FidFile> fidFiles;
	private WeakSet<ChangeListener> listeners;

	/**
	 * Returns the singleton instance of the FidFileManager.
	 */
	public static FidFileManager getInstance() {
		if (THE_FID_FILE_MANAGER == null) {
			THE_FID_FILE_MANAGER = new FidFileManager();
		}
		return THE_FID_FILE_MANAGER;
	}

	private FidFileManager() {
		listeners = WeakDataStructureFactory.createCopyOnWriteWeakSet();
		// findDeliveredFidFiles(); - too slow
		// restoreFromPreferences();
	}

	private Set<FidFile> loadFidFiles() {
		if (fidFiles == null) {
			findDeliveredFidFiles();
			restoreFromPreferences();
		}

		return fidFiles;
	}

	/**
	 * Add user FidDb file
	 * @param file
	 * @return FidFile or null if invalid
	 */
	public FidFile addUserFidFile(File file) {
		loadFidFiles();
		FidFile fidFile = findExistingFidFile(file);
		if (fidFile != null) {
			return fidFile;
		}

		fidFile = new FidFile(this, file, false);
		if (fidFile.isValidFile()) {
			fidFiles.add(fidFile);
			saveToPreferences();
			notifyListeners();
			return fidFile;
		}
		return null;
	}

	private FidFile findExistingFidFile(File file) {
		loadFidFiles();
		for (FidFile fidFile : fidFiles) {
			if (fidFile.getFile().equals(file)) {
				return fidFile;
			}
		}
		return null;
	}

	/**
	 * Returns a list of all the FidFiles know to the application.
	 */
	public List<FidFile> getFidFiles() {
		loadFidFiles();
		List<FidFile> files = new ArrayList<>(fidFiles);
		Collections.sort(files);
		return files;
	}

	/**
	 * Returns a list of all the user added (non installation) Fid files.  This will
	 * be files containing packed databases.
	 */
	public List<FidFile> getUserAddedFiles() {
		loadFidFiles();
		List<FidFile> files = new ArrayList<>();
		for (FidFile fidFile : fidFiles) {
			if (!fidFile.isInstalled()) {
				files.add(fidFile);
			}
		}
		Collections.sort(files);
		return files;
	}

	/**
	 * Opens all the Fid Databases applicable for the given language and returns a FidQueryService
	 * which is a convenience for querying multiple databases at the same time.
	 * @param language the language of the programs to be queried.
	 * @param openForUpdate if true, all non-installation databases will be open for update;
	 * otherwise they will be read-only.
	 * @return a FidQueryService which is a convenience for querying multiple databases at the same time.
	 * @throws VersionException if any of the fidFiles have a database Schema that is not the current version.
	 * @throws IOException if a general I/O error occurs.
	 */
	public FidQueryService openFidQueryService(Language language, boolean openForUpdate)
			throws VersionException, IOException {
		loadFidFiles();
		return new FidQueryService(fidFiles, language, openForUpdate);
	}

	/**
	 * Creates a new FidDatabse and FidFile.
	 * @param dbFile the file to where the fidDatabase should be created.  It must not exist.
	 * @throws IOException If the new FidFile database could not be created.
	 */
	public void createNewFidDatabase(File dbFile) throws IOException {
		FidDB.createNewFidDatabase(dbFile);
		FidFile newFidFile = new FidFile(this, dbFile, false);
		loadFidFiles();
		fidFiles.add(newFidFile);
		saveToPreferences();
		notifyListeners();
	}

	/**
	 * Removes the given FidFile from the application.  Note: this does not delete the file,
	 * it only removes it from the applications list of knows FidFiles.
	 * @param fidFile the fidFile to remove.
	 */
	public void removeUserFile(FidFile fidFile) {
		loadFidFiles();
		fidFiles.remove(fidFile);
		saveToPreferences();
		notifyListeners();
	}

	/**
	 * Returns true if any FidFile database known to the application can support the given language.
	 * @param language the language to test.
	 * @return  true if any FidFile database known to the application can support the given language.
	 */
	public boolean canQuery(Language language) {
		loadFidFiles();
		for (FidFile file : fidFiles) {
			if (file.isActive() && file.canProcessLanguage(language)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Adds a listener to be notified when the list of FidFiles change. NOTE: this object
	 * uses a weak set, so you can't pass anonymous listeners or they will be immediately
	 * garbage collected.
	 * @param listener the listener to be notified.
	 */
	public void addChangeListener(ChangeListener listener) {
		listeners.add(listener);
	}

	/**
	 * Removes a listener to be notified when the list of FidFiles change.
	 * @param listener the listener to no longer be notified.
	 */
	public void removeChangeListener(ChangeListener listener) {
		listeners.remove(listener);
	}

	private void saveToPreferences() {
		List<FidFile> userAddedFiles = getUserAddedFiles();
		saveFilesToPreferences(USER_ADDED_FILES, userAddedFiles);

		List<FidFile> inactiveFiles = getInactiveFiles();
		saveFilesToPreferences(INACTIVE_FID_FILES, inactiveFiles);
	}

	private void saveFilesToPreferences(String preferenceName, List<FidFile> files) {
		StringBuilder builder = new StringBuilder();
		for (FidFile file : files) {
			if (builder.length() > 0) {
				builder.append(SEPARATOR);
			}
			Path path = new Path(file.getFile());
			builder.append(path.getPathAsString());
		}
		Preferences.setProperty(preferenceName, builder.toString());
	}

	private List<FidFile> getInactiveFiles() {
		loadFidFiles();
		List<FidFile> list = new ArrayList<>();
		for (FidFile fidFile : fidFiles) {
			if (!fidFile.isActive()) {
				list.add(fidFile);
			}
		}
		return list;
	}

	private void restoreFromPreferences() {
		Set<File> userAddedFiles = getFilesFromPreference(USER_ADDED_FILES);
		addUserFidFiles(userAddedFiles);

		Set<File> excludedFiles = getFilesFromPreference(INACTIVE_FID_FILES);
		excludeFidFiles(excludedFiles);
	}

	private void addUserFidFiles(Set<File> userAddedFiles) {
		loadFidFiles();
		for (File file : userAddedFiles) {
			FidFile fidFile = new FidFile(this, file, false);
			if (fidFile.isValidFile()) {
				fidFiles.add(fidFile);
			}
		}
	}

	private void excludeFidFiles(Set<File> excludedFiles) {
		loadFidFiles();
		for (FidFile fidFile : fidFiles) {
			if (excludedFiles.contains(fidFile.getFile())) {
				fidFile.setActive(false);
			}
		}
	}

	private Set<File> getFilesFromPreference(String preferenceName) {
		Set<File> set = new HashSet<>();
		String concatenatedFilePaths = Preferences.getProperty(preferenceName, "", true);
		String[] filePaths = concatenatedFilePaths.split(SEPARATOR);
		for (String filePath : filePaths) {
			filePath = filePath.trim();
			if (filePath.length() == 0) {
				continue;
			}
			Path path = new Path(filePath);
			ResourceFile resourceFile = path.getPath();
			if (resourceFile.exists()) {
				set.add(resourceFile.getFile(false));
			}
		}
		return set;
	}

	private void findDeliveredFidFiles() {
		fidFiles = new CopyOnWriteArraySet<>();
		List<ResourceFile> foundFiles =
			Application.findFilesByExtensionInApplication(FidFile.FID_RAW_DATABASE_FILE_EXTENSION);
		for (ResourceFile resourceFile : foundFiles) {
			File file = resourceFile.getFile(true);
			FidFile fidFile = new FidFile(this, file, true);
			if (fidFile.isValidFile()) {
				fidFiles.add(fidFile);
			}
		}
	}

	void activeStateChanged(FidFile fidFile) {
		saveFilesToPreferences(INACTIVE_FID_FILES, getInactiveFiles());
	}

	private void notifyListeners() {
		for (ChangeListener listener : listeners) {
			listener.stateChanged(null);
		}
	}
}
