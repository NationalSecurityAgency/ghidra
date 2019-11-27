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

import java.io.File;
import java.io.FileFilter;
import java.util.*;

import ghidra.framework.preferences.Preferences;

public class GenericRunInfo {

	/** The name appended to application directories during testing */
	public static final String TEST_DIRECTORY_SUFFIX = "-Test";

	/**
	 * Get all of the applications's settings directories 
	 * (<tt>.<i>application_name_version</i></tt>) for various versions in descending order by the 
	 * modification time. In other words, <tt>list.get(0)</tt> will be the directory 
	 * with the most recent modification time. If two directories have the same time then the 
	 * directories will simply be sorted based on their pathnames as a string.
	 * <p>
	 * <b>Note: </b>This method ignores Test directories 
	 */
	private static List<File> getUserSettingsDirsByTime() {
		File userDataDirectory = Application.getUserSettingsDirectory();
		File userDataDirParentFile = userDataDirectory.getParentFile();

		List<File> applicationDirectories = collectAllApplicationDirectories(userDataDirParentFile);

		Comparator<File> userDirModifyComparator = (f1, f2) -> {

			//
			// We want to use a real file to tell the last time Ghidra was run, as we cannot
			// trust the directory's last modified time on all platforms
			// 
			File prefs1 = new File(f1, Preferences.APPLICATION_PREFERENCES_FILENAME);
			File prefs2 = new File(f2, Preferences.APPLICATION_PREFERENCES_FILENAME);
			if (!prefs1.exists() || !prefs2.exists()) {
				if (!prefs1.exists()) {
					if (!prefs2.exists()) {
						// neither file exists (user deleted?)
						return 0;
					}

					// prefs1 doesn't exist, but prefs2 does--prefer prefs2
					return 1;
				}

				// prefs1 exists--prefer prefs1
				return -1;
			}

			long modify1 = prefs1.lastModified();
			long modify2 = prefs2.lastModified();
			if (modify1 == modify2) {
				// If same time then compare names of the parent dirs, which have versions
				// in the name
				return f1.getName().compareTo(f2.getName());
			}
			return (modify1 < modify2) ? 1 : -1;
		};

		Collections.sort(applicationDirectories, userDirModifyComparator);
		return applicationDirectories;
	}

	private static List<File> collectAllApplicationDirectories(File dataDirectoryParentDir) {

		FileFilter userDirFilter = f -> {
			String name = f.getName();
			Application.getName();
			String userSettingsDirPrefix =
				"." + Application.getName().replaceAll("\\s", "").toLowerCase();

			return f.isDirectory() && name.startsWith(userSettingsDirPrefix) &&
				!name.endsWith(TEST_DIRECTORY_SUFFIX);
		};

		// The current directory structure--rooted under '.<application name>'.   For example,
		// /some/path/<user home>/.applicationname/.application-version
		File[] currentStyleUserDirs = dataDirectoryParentDir.listFiles(userDirFilter);

		// Old structure (applications used to be rooted under <user home>).  For example,
		// /some/path/<user home>/.application-version
		File userHomeDir = dataDirectoryParentDir.getParentFile();
		if (userHomeDir == null) {
			throw new IllegalArgumentException(
				"Must specify an absolute path; found instead: " + dataDirectoryParentDir);
		}

		File[] oldStyleUserDirs = userHomeDir.listFiles(userDirFilter);

		List<File> allDirs = new ArrayList<>();
		if (currentStyleUserDirs != null) {
			// should never be null, since the installation running this code will have a dir
			for (File file : currentStyleUserDirs) {
				allDirs.add(file);
			}
		}

		if (oldStyleUserDirs != null) {
			// should never be null--it's the user's home dir!
			for (File file : oldStyleUserDirs) {
				allDirs.add(file);
			}
		}

		return allDirs;
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

		for (File dir : getUserSettingsDirsByTime()) {

			// Ignore the currently active user settings directory.
			// By definition, it is not a previous one.
			String dirName = dir.getName();
			if (dirName.equals(myDirName)) {
				continue;
			}

			if (dirName.startsWith(".")) {
				dirName = dirName.substring(1);
			}

			try {
				// The current release name has to match for it to be considered				
				ApplicationIdentifier identifier = new ApplicationIdentifier(dirName);
				String release = identifier.getApplicationReleaseName();
				if (release.equals(myRelease)) {
					settingsDirs.add(dir);
				}
			}
			catch (IllegalArgumentException e) {
				// The directory name didn't contain a valid application identifier...skip it
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
