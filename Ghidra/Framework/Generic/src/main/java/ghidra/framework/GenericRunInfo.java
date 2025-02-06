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
package ghidra.framework;

import java.io.*;
import java.util.*;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import ghidra.framework.preferences.Preferences;
import util.CollectionUtils;
import utility.application.ApplicationLayout;
import utility.application.ApplicationUtilities;

public class GenericRunInfo {

	/** The name appended to application directories during testing */
	public static final String TEST_DIRECTORY_SUFFIX = "-Test";

	private static final Logger LOG = LogManager.getLogger(GenericRunInfo.class);

	/**
	 * Get all of the applications's settings directories 
	 * ({@code .<i>application_name_version</i>}) for various versions in descending order by the 
	 * modification time. In other words, {@code list.get(0)} will be the directory 
	 * with the most recent modification time. If two directories have the same time then the 
	 * directories will simply be sorted based on their pathnames as a string.
	 * <p>
	 * <b>Note: </b>This method ignores Test directories 
	 */
	private static List<File> getUserSettingsDirsByTime() {
		ApplicationLayout layout = Application.getApplicationLayout();
		File userSettingsDirectory = Application.getUserSettingsDirectory();

		List<File> appDirs =
			collectAllApplicationDirectories(userSettingsDirectory.getParentFile());

		// Search "legacy" user setting directory locations in case the user has upgraded from an
		// older version
		try {
			File legacyUserSettingsDirectory = ApplicationUtilities.getLegacyUserSettingsDir(
				layout.getApplicationProperties(), layout.getApplicationInstallationDir());
			appDirs.addAll(
				collectAllApplicationDirectories(legacyUserSettingsDirectory.getParentFile()));
		}
		catch (FileNotFoundException e) {
			// ignore
		}

		Comparator<File> modifyTimeComparator = (f1, f2) -> {

			//
			// We want to use a real file to tell the last time Ghidra was run, as we cannot
			// trust the directory's last modified time on all platforms
			// 
			File prefs1 = new File(f1, Preferences.APPLICATION_PREFERENCES_FILENAME);
			File prefs2 = new File(f2, Preferences.APPLICATION_PREFERENCES_FILENAME);
			if (!prefs1.exists() || !prefs2.exists()) {
				if (!prefs1.exists()) {
					if (!prefs2.exists()) {
						return 0; // neither file exists (user deleted?)
					}
					return 1; // prefs1 doesn't exist, but prefs2 does--prefer prefs2
				}
				return -1; // prefs1 exists--prefer prefs1
			}

			long modify1 = prefs1.lastModified();
			long modify2 = prefs2.lastModified();
			if (modify1 == modify2) {
				// If same time, compare parent dir names, which contain their version
				return f1.getName().compareTo(f2.getName());
			}
			return (modify1 < modify2) ? 1 : -1;
		};

		Collections.sort(appDirs, modifyTimeComparator);
		return appDirs;
	}

	private static List<File> collectAllApplicationDirectories(File dataDirectoryParentDir) {

		String settingsDirPrefix = "." + Application.getName().replaceAll("\\s", "").toLowerCase();
		FileFilter userDirFilter = f -> {
			String name = f.getName();
			return f.isDirectory() && name.startsWith(settingsDirPrefix) &&
				!name.endsWith(TEST_DIRECTORY_SUFFIX);
		};

		// The current directory structure--rooted under '.<application name>'.   For example,
		// /some/path/<user home>/.application_name/..application_name_application-version
		File[] userDirs = dataDirectoryParentDir.listFiles(userDirFilter);
		return CollectionUtils.asList(userDirs);
	}

	/**
	 * Searches previous Application Settings directories 
	 * ({@link #getUserSettingsDirsByTime()}) to find a file by the given name.   This is 
	 * useful for loading previous user settings, such as preferences.
	 * 
	 * <p>Note: this method will ignore any test versions of settings directories.
	 * 
	 * @param filename the name for which to seek; must be relative to a settings directory
	 * @return the most recent file matching that name found in a previous settings dir
	 */
	public static File getPreviousApplicationSettingsFile(String filename) {

		List<File> settingsDirs = getPreviousApplicationSettingsDirsByTime();
		for (File dir : settingsDirs) {
			String dirPath = dir.getPath();
			if (dirPath.endsWith("Test")) {
				continue; // Ignore any test directories.
			}

			String altFilePath = dirPath + File.separatorChar + filename;

			File file = new File(altFilePath);
			if (!file.exists()) {
				continue;
			}

			return file;
		}
		return null;
	}

	/**
	 * Searches previous Application Settings directories 
	 * ({@link #getUserSettingsDirsByTime()}) to find a settings directory containing
	 * files that match the given file filter.  This is 
	 * useful for loading previous directories of saved settings files of a particular type.
	 * 
	 * <p>Note: this method will ignore any test versions of settings directories.
	 * 
	 * @param dirName the name of a settings subdir; must be relative to a settings directory
	 * @param filter the file filter for the files of interest
	 * @return the most recent file matching that name and containing at least one file
	 * of the given type, in a previous version's settings directory.
	 */
	public static File getPreviousApplicationSettingsDir(String dirName, FileFilter filter) {

		List<File> settingsDirs = getPreviousApplicationSettingsDirsByTime();
		for (File dir : settingsDirs) {
			String dirPath = dir.getPath();
			if (dirPath.endsWith("Test")) {
				continue; // Ignore any test directories.
			}

			String altFilePath = dirPath + File.separatorChar + dirName;

			File altSettingsDir = new File(altFilePath);
			if (!altSettingsDir.exists()) {
				continue;
			}
			if (!altSettingsDir.isDirectory()) {
				continue;
			}
			File[] listFiles = altSettingsDir.listFiles(filter);
			if (listFiles != null && listFiles.length > 0) {
				return altSettingsDir;
			}
		}
		return null;
	}

	/** 
	 * This is the same as {@link #getUserSettingsDirsByTime()} except that it doesn't include the 
	 * current installation or installations with different release names
	 * 
	 * @return the list of previous directories, sorted by time
	 */
	public static List<File> getPreviousApplicationSettingsDirsByTime() {
		List<File> settingsDirs = new ArrayList<>();

		ApplicationIdentifier myIdentifier = new ApplicationIdentifier(
			Application.getApplicationLayout().getApplicationProperties());
		String myRelease = myIdentifier.getApplicationReleaseName();
		String myDirName = Application.getUserSettingsDirectory().getName();

		LOG.trace("Finding previous application settings directories for " + myIdentifier);

		for (File dir : getUserSettingsDirsByTime()) {

			// Ignore the currently active user settings directory.
			// By definition, it is not a previous one.
			String dirName = dir.getName();
			if (dirName.equals(myDirName)) {
				continue;
			}

			LOG.trace("\tchecking " + dirName);

			if (dirName.startsWith(".")) {
				dirName = dirName.substring(1);
			}

			try {
				// The current release name has to match for it to be considered				
				ApplicationIdentifier identifier = new ApplicationIdentifier(dirName);
				String release = identifier.getApplicationReleaseName();
				if (release.equals(myRelease)) {
					LOG.trace("\t\tkeeping");
					settingsDirs.add(dir);
				}
				else {
					LOG.trace("\t\tskipping");
				}
			}
			catch (IllegalArgumentException e) {
				// The directory name didn't contain a valid application identifier...skip it
				LOG.trace("\tdir does not have an application identifier - skipping");
			}
		}
		return settingsDirs;
	}

	/**
	 * Get the user's preferred projects directory.
	 * @return projects directory path.
	 */
	public static String getProjectsDirPath() {
		String path = Preferences.getProperty(Preferences.PROJECT_DIRECTORY, null, true);
		if (path != null && (new File(path)).isDirectory()) {
			return path;
		}
		return System.getProperty("user.home");
	}

	/**
	 * Set the user's current projects directory path.  Value is also retained
	 * within user's set of preferences.
	 * @param path projects directory path.
	 */
	public static void setProjectsDirPath(String path) {
		if (path != null && (new File(path)).isDirectory()) {
			Preferences.setProperty(Preferences.PROJECT_DIRECTORY, path);
		}
	}
}
