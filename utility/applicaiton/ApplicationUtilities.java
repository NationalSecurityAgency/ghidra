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
package utility.applicaiton;

import java.io.*;
import java.util.ArrayList;
import java.util.Collection;

import generic.jar.ResourceFile;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.ApplicationProperties;
import ghidra.framework.OperatingSystem;
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
		ResourceFile applicationRootDir = findApplicationRootDirFromClasspath();
		if (applicationRootDir != null) {
			applicationRootDirs.add(applicationRootDir);
			applicationRootDirs.addAll(findSiblingApplicationRootDirs(applicationRootDir));
		}
		return applicationRootDirs;
	}

	/**
	 * Finds an application root directory by looking at classpath entries.
	 * 
	 * @return An application root directory, or null if one could not be found.
	 */
	private static ResourceFile findApplicationRootDirFromClasspath() {
		String[] classpath = System.getProperty("java.class.path").split(File.pathSeparator);
		for (String pathEntry : classpath) {
			try {
				ResourceFile pathFile = new ResourceFile(new File(pathEntry).getCanonicalPath());
				while (pathFile != null && pathFile.exists()) {
					if (new ResourceFile(pathFile, ApplicationProperties.PROPERTY_FILE).exists()) {
						return pathFile;
					}
					pathFile = pathFile.getParentFile();
				}
			}
			catch (IOException e) {
				Msg.error(GhidraApplicationLayout.class, "Invalid class path entry: " + pathEntry,
					e);
			}
		}
		return null;
	}

	/**
	 * Finds all sibling application root directories of the given application root directory.
	 * This type of root directory is only relevant in testing or development mode.
	 * 
	 * @return A collection of sibling application root directories.  
	 */
	private static Collection<ResourceFile> findSiblingApplicationRootDirs(ResourceFile applicationRootDir) {
		Collection<ResourceFile> siblingApplicationRootDirs = new ArrayList<>();
		if (SystemUtilities.isInTestingMode() || SystemUtilities.isInDevelopmentMode()) {
			for (ResourceFile parent : applicationRootDir.getParentFile().getParentFile().listFiles()) {
				if (parent.equals(applicationRootDir.getParentFile())) {
					continue;
				}
				ResourceFile[] potentialAppRoots = parent.listFiles();
				if (potentialAppRoots == null) {
					continue;
				}
				for (ResourceFile potentialRoot : potentialAppRoots) {
					if (new ResourceFile(potentialRoot,
						ApplicationProperties.PROPERTY_FILE).exists()) {
						siblingApplicationRootDirs.add(potentialRoot);
						break;
					}
				}
			}
		}
		return siblingApplicationRootDirs;
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
		String cachedir = System.getProperty("application.cachedir");
		if (cachedir != null && !cachedir.isEmpty()) {
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

		String userSettingsDir = System.getProperty("user.home");
		if (userSettingsDir == null || userSettingsDir.isEmpty()) {
			throw new FileNotFoundException("System property \"user.home\" is not set!");
		}

		String prefix =
			"." + applicationProperties.getApplicationName().replaceAll("\\s", "").toLowerCase();

		File applicationParentDir = new File(userSettingsDir, prefix);
		String suffix = applicationProperties.getApplicationVersion();

		if (SystemUtilities.isInDevelopmentMode()) {
			// Add the appication's installation directory name to this variable, so that each 
			// branch's project user directory is unique.
			suffix += "_location_" + installationDirectory.getName();
		}

		return new File(applicationParentDir, prefix + "-" + suffix);
	}
}
