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
package utility.application;

import java.io.*;
import java.util.ArrayList;
import java.util.Collection;

import generic.jar.ResourceFile;
import ghidra.framework.*;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;

/**
 * Utility class for default application things.
 */
public class ApplicationUtilities {

	/**
	 * Searches for default application root directories.
	 * 
	 * @return A collection of discovered application root directories (could be empty).
	 */
	public static Collection<ResourceFile> findDefaultApplicationRootDirs() {
		Collection<ResourceFile> applicationRootDirs = new ArrayList<>();
		ResourceFile applicationRootDir = findPrimaryApplicationRootDir();
		if (applicationRootDir != null) {
			applicationRootDirs.add(applicationRootDir);
			if (SystemUtilities.isInTestingMode() || SystemUtilities.isInDevelopmentMode()) {
				applicationRootDirs.addAll(
					findApplicationRootDirsFromRepoConfig(applicationRootDir));
			}
		}
		return applicationRootDirs;
	}

	/**
	 * Finds the primary application root directory from the classpath.  The primary application
	 * root directory must contain an application.properties file.  No other application root
	 * directories may contain an application.properties file.
	 * 
	 * @return The primary application root directory, or null if it could not be found.
	 */
	private static ResourceFile findPrimaryApplicationRootDir() {
		String[] classpath = System.getProperty("java.class.path").split(File.pathSeparator);
		for (String pathEntry : classpath) {
			try {
				ResourceFile pathFile = new ResourceFile(new File(pathEntry).getCanonicalPath());
				while (pathFile != null && pathFile.exists()) {
					ResourceFile applicationPropertiesFile =
						new ResourceFile(pathFile, ApplicationProperties.PROPERTY_FILE);
					if (validateApplicationPropertiesFile(applicationPropertiesFile)) {
						return pathFile;
					}
					pathFile = pathFile.getParentFile();
				}
			}
			catch (IOException e) {
				Msg.error(ApplicationUtilities.class, "Invalid class path entry: " + pathEntry, e);
			}
		}
		return null;
	}

	/**
	 * Checks to make sure the given application properties file exists and is a valid format
	 * 
	 * @param applicationPropertiesFile The application properties file to validate
	 * @return true if the given application properties file exists and is a valid format;
	 *   otherwise, false
	 */
	private static boolean validateApplicationPropertiesFile(
			ResourceFile applicationPropertiesFile) {
		if (applicationPropertiesFile.isFile()) {
			try {
				ApplicationProperties applicationProperties =
					new ApplicationProperties(applicationPropertiesFile);
				if (!applicationProperties.getApplicationName().isEmpty()) {
					return true;
				}
			}
			catch (IOException e) {
				Msg.error(ApplicationUtilities.class,
					"Failed to read: " + applicationPropertiesFile, e);
			}
		}
		return false;
	}

	/**
	 * Finds all application root directories defined in the repository config file.
	 * 
	 * @param primaryApplicationRootDir The primary application root directory that may contain the
	 *   repository config file one directory up.
	 * @return A collection of defined application repository root directories.
	 */
	private static Collection<ResourceFile> findApplicationRootDirsFromRepoConfig(
			ResourceFile primaryApplicationRootDir) {
		Collection<ResourceFile> repoApplicationRootDirs = new ArrayList<>();
		ResourceFile repoConfigFile =
			new ResourceFile(primaryApplicationRootDir.getParentFile(), "ghidra.repos.config");
		if (repoConfigFile.isFile()) {
			try (BufferedReader reader =
				new BufferedReader(new FileReader(repoConfigFile.getFile(false)))) {
				String line = null;
				while ((line = reader.readLine()) != null) {
					line = line.trim();
					if (line.isEmpty() || line.startsWith("#")) {
						continue;
					}
					ResourceFile potentialApplicationRootDir =
						new ResourceFile(repoConfigFile.getParentFile().getParentFile(),
							line + File.separator + "Ghidra");
					if (potentialApplicationRootDir.isDirectory()) {
						repoApplicationRootDirs.add(potentialApplicationRootDir);
					}
				}
			}
			catch (IOException e) {
				Msg.error(ApplicationUtilities.class, "Failed to read: " + repoConfigFile);
			}
		}
		return repoApplicationRootDirs;
	}

	/**
	 * Gets the default application's user temp directory.
	 * 
	 * @param applicationProperties The application properties.
	 * @return The default application's user temp directory.
	 * @throws FileNotFoundException if the user temp directory could not be determined.
	 */
	public static File getDefaultUserTempDir(ApplicationProperties applicationProperties)
			throws FileNotFoundException {
		String tmpdir = System.getProperty("java.io.tmpdir");
		if (tmpdir == null || tmpdir.isEmpty()) {
			throw new FileNotFoundException("System property \"java.io.tmpdir\" is not set!");
		}
		return new File(tmpdir,
			SystemUtilities.getUserName() + "-" + applicationProperties.getApplicationName());
	}

	/**
	 * Gets the default application's user cache directory.
	 * 
	 * @param applicationProperties The application properties.
	 * @return The default application's user cache directory.
	 * @throws FileNotFoundException if the user cache directory could not be determined.
	 */
	public static File getDefaultUserCacheDir(ApplicationProperties applicationProperties)
			throws FileNotFoundException {

		// Look for preset cache directory
		String cachedir = System.getProperty("application.cachedir", "").trim();
		if (!cachedir.isEmpty()) {
			return new File(cachedir,
				SystemUtilities.getUserName() + "-" + applicationProperties.getApplicationName());
		}

		// Handle Windows specially
		if (OperatingSystem.CURRENT_OPERATING_SYSTEM == OperatingSystem.WINDOWS) {
			File localAppDataDir = null;
			String localAppDataDirPath = System.getenv("LOCALAPPDATA"); // e.g., /Users/myname/AppData/Local
			if (localAppDataDirPath != null && !localAppDataDirPath.isEmpty()) {
				localAppDataDir = new File(localAppDataDirPath);
			}
			else {
				String userHome = System.getProperty("user.home");
				if (userHome != null) {
					localAppDataDir = new File(userHome, "AppData\\Local");
					if (!localAppDataDir.isDirectory()) {
						localAppDataDir = new File(userHome, "Local Settings");
					}
				}
			}
			if (localAppDataDir != null && localAppDataDir.isDirectory()) {
				return new File(localAppDataDir, applicationProperties.getApplicationName());
			}
		}

		// Use user temp directory if platform specific scheme does not exist above or it failed
		return getDefaultUserTempDir(applicationProperties);
	}

	/**
	 * Gets the default application's user settings directory.
	 * 
	 * @param applicationProperties The application properties.
	 * @param installationDirectory The application installation directory.
	 * @return The application's user settings directory.
	 * @throws FileNotFoundException if the user settings directory could not be determined.
	 */
	public static File getDefaultUserSettingsDir(ApplicationProperties applicationProperties,
			ResourceFile installationDirectory) throws FileNotFoundException {

		String homedir = System.getProperty("user.home");
		if (homedir == null || homedir.isEmpty()) {
			throw new FileNotFoundException("System property \"user.home\" is not set!");
		}

		ApplicationIdentifier applicationIdentifier =
			new ApplicationIdentifier(applicationProperties);

		File userSettingsParentDir =
			new File(homedir, "." + applicationIdentifier.getApplicationName());

		String userSettingsDirName = "." + applicationIdentifier;

		if (SystemUtilities.isInDevelopmentMode()) {
			// Add the application's installation directory name to this variable, so that each 
			// branch's project user directory is unique.
			userSettingsDirName += "_location_" + installationDirectory.getName();
		}

		return new File(userSettingsParentDir, userSettingsDirName);
	}
}
