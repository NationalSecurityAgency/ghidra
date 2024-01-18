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
import utilities.util.FileUtilities;

/**
 * Utility class for default application things.
 */
public class ApplicationUtilities {

	/**
	 * Name of system property used to override the location of the user temporary directory
	 */
	public static final String PROPERTY_TEMP_DIR = "application.tempdir";

	/**
	 * Name of system property used to override the location of the user cache directory
	 */
	public static final String PROPERTY_CACHE_DIR = "application.cachedir";

	/**
	 * Name of system property used to override the location of the user settings directory
	 */
	public static final String PROPERTY_SETTINGS_DIR = "application.settingsdir";

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
	 * Gets the application's default user temp directory.
	 * <p>
	 * NOTE: This method creates the directory if it does not exist.
	 * 
	 * @param applicationName The application name.
	 * @return The application's default user temp directory. The returned {@link File} will 
	 *   represent an absolute path.
	 * @throws FileNotFoundException if the absolute path of the user temp directory could not be 
	 *   determined.
	 * @throws IOException if the user temp directory could not be created.
	 */
	public static File getDefaultUserTempDir(String applicationName)
			throws FileNotFoundException, IOException {

		String appName = applicationName.toLowerCase();

		// Look for Ghidra-specific system property
		File tempOverrideDir = getSystemPropertyFile(PROPERTY_TEMP_DIR, false);
		if (tempOverrideDir != null) {
			return createDir(
				new File(tempOverrideDir, getUserSpecificDirName(tempOverrideDir, appName)));
		}

		// Look for XDG environment variable
		File xdgRuntimeDir = getEnvFile(XdgUtils.XDG_RUNTIME_DIR, false);
		if (xdgRuntimeDir != null) {
			return createDir(
				new File(xdgRuntimeDir, getUserSpecificDirName(xdgRuntimeDir, appName)));
		}

		File javaTmpDir = getJavaTmpDir();
		return createDir(new File(getJavaTmpDir(), getUserSpecificDirName(javaTmpDir, appName)));
	}

	/**
	 * Gets the application's default user cache directory.
	 * <p>
	 * NOTE: This method creates the directory if it does not exist.
	 * 
	 * @param applicationProperties The application properties.
	 * @return The application's default user cache directory. The returned {@link File} will 
	 *   represent an absolute path.
	 * @throws FileNotFoundException if the absolute path of the user cache directory could not be 
	 *   determined.
	 * @throws IOException if the user cache directory could not be created.
	 */
	public static File getDefaultUserCacheDir(ApplicationProperties applicationProperties)
			throws FileNotFoundException, IOException {

		String appName = applicationProperties.getApplicationName().toLowerCase();

		// Look for Ghidra-specific system property
		File cacheOverrideDir = getSystemPropertyFile(PROPERTY_CACHE_DIR, false);
		if (cacheOverrideDir != null) {
			return createDir(
				new File(cacheOverrideDir, getUserSpecificDirName(cacheOverrideDir, appName)));
		}

		// Look for XDG environment variable
		File xdgCacheHomeDir = getEnvFile(XdgUtils.XDG_CACHE_HOME, false);
		if (xdgCacheHomeDir != null) {
			return createDir(
				new File(xdgCacheHomeDir, getUserSpecificDirName(xdgCacheHomeDir, appName)));
		}
		
		// Use platform-specific default location
		String userDirName = SystemUtilities.getUserName() + "-" + appName;

		try {
			return createDir(switch (OperatingSystem.CURRENT_OPERATING_SYSTEM) {
				case WINDOWS -> new File(getEnvFile("LOCALAPPDATA", true), appName);
				case LINUX -> new File("/var/tmp/" + userDirName);
				case FREE_BSD -> new File("/var/tmp/" + userDirName);
				case MAC_OS_X -> new File("/var/tmp/" + userDirName);
				default -> throw new FileNotFoundException(
					"Failed to find the user cache directory: Unsupported operating system.");
			});
		}
		catch (IOException e) {
			// Failed to create desired cache directory...use temp directory instead
			return getDefaultUserTempDir(applicationProperties.getApplicationName());
		}
	}

	/**
	 * Gets the application's default user settings directory.
	 * <p>
	 * NOTE: This method creates the directory if it does not exist.
	 * 
	 * @param applicationProperties The application properties.
	 * @param installationDirectory The application installation directory.
	 * @return The application's default user settings directory. The returned {@link File} will
	 *   represent an absolute path.
	 * @throws FileNotFoundException if the absolute path of the user settings directory could not 
	 *   be determined.
	 * @throws IOException if the user settings directory could not be created.
	 */
	public static File getDefaultUserSettingsDir(ApplicationProperties applicationProperties,
			ResourceFile installationDirectory) throws FileNotFoundException, IOException {

		String appName = applicationProperties.getApplicationName().toLowerCase();
		ApplicationIdentifier applicationIdentifier =
			new ApplicationIdentifier(applicationProperties);
		String versionedName = applicationIdentifier.toString();
		if (SystemUtilities.isInDevelopmentMode()) {
			// Add the application's installation directory name to this variable, so that each 
			// branch's project user directory is unique.
			versionedName += "_location_" + installationDirectory.getName();
		}

		// Look for Ghidra-specific system property
		File settingsOverrideDir = getSystemPropertyFile(PROPERTY_SETTINGS_DIR, false);
		if (settingsOverrideDir != null) {
			return createDir(new File(settingsOverrideDir,
				getUserSpecificDirName(settingsOverrideDir, appName) + "/" + versionedName));
		}

		// Look for XDG environment variable
		File xdgConfigHomeDir = getEnvFile(XdgUtils.XDG_CONFIG_HOME, false);
		if (xdgConfigHomeDir != null) {
			return createDir(new File(xdgConfigHomeDir,
				getUserSpecificDirName(xdgConfigHomeDir, appName) + "/" + versionedName));
		}

		File userHomeDir = getJavaUserHomeDir();
		String versionedSubdir = appName + "/" + versionedName;
		return createDir(switch (OperatingSystem.CURRENT_OPERATING_SYSTEM) {
			case WINDOWS -> new File(getEnvFile("APPDATA", true), versionedSubdir);
			case LINUX -> new File(userHomeDir, ".config/" + versionedSubdir);
			case FREE_BSD -> new File(userHomeDir, ".config/" + versionedSubdir);
			case MAC_OS_X -> new File(userHomeDir, "Library/" + versionedSubdir);
			default -> throw new FileNotFoundException(
				"Failed to find the user settings directory: Unsupported operating system.");
		});
	}

	/**
	 * Gets the application's legacy (pre-Ghida 11.1) user settings directory.
	 * <p>
	 * NOTE: This method does not create the directory.
	 * 
	 * @param applicationProperties The application properties.
	 * @param installationDirectory The application installation directory.
	 * @return The application's legacy user settings directory. The returned {@link File} will 
	 *   represent an absolute path.
	 * @throws FileNotFoundException if the absolute path of the legacy user settings directory 
	 *   could not be determined.
	 */
	public static File getLegacyUserSettingsDir(ApplicationProperties applicationProperties,
			ResourceFile installationDirectory) throws FileNotFoundException {

		ApplicationIdentifier applicationIdentifier =
			new ApplicationIdentifier(applicationProperties);

		File userSettingsParentDir =
			new File(getJavaUserHomeDir(), "." + applicationIdentifier.getApplicationName());

		String userSettingsDirName = "." + applicationIdentifier;

		if (SystemUtilities.isInDevelopmentMode()) {
			// Add the application's installation directory name to this variable, so that each 
			// branch's project user directory is unique.
			userSettingsDirName += "_location_" + installationDirectory.getName();
		}

		return new File(userSettingsParentDir, userSettingsDirName);
	}

	/**
	 * Gets Java's temporary directory in absolute form
	 * 
	 * @return Java's temporary directory in absolute form
	 * @throws FileNotFoundException if Java's temporary directory is not defined or it is not an
	 *   absolute path
	 */
	private static File getJavaTmpDir() throws FileNotFoundException {
		return getSystemPropertyFile("java.io.tmpdir", true);
	}

	/**
	 * Gets Java's user home directory in absolute form
	 * 
	 * @return Java's user home directory in absolute form
	 * @throws FileNotFoundException if Java's user home directory is not defined or it is not an
	 *   absolute path
	 */
	private static File getJavaUserHomeDir() throws FileNotFoundException {
		return getSystemPropertyFile("user.home", true);
	}

	/**
	 * Gets the absolute form {@link File} value of the system property by the given name
	 * 
	 * @param name The system property name
	 * @param required True if given system property is required to be set; otherwise, false
	 * @return The absolute form {@link File} value of the system property by the given name, or 
	 *   null if it isn't set
	 * @throws FileNotFoundException if the property value was not an absolute path, or if it is
	 *   required and not set
	 */
	private static File getSystemPropertyFile(String name, boolean required)
			throws FileNotFoundException {
		String path = System.getProperty(name);
		if (path == null || path.isBlank()) {
			if (required) {
				throw new FileNotFoundException(
					"Required system property \"%s\" is not set!".formatted(name));
			}
			return null;
		}
		path = path.trim();
		File file = new File(path);
		if (!file.isAbsolute()) {
			throw new FileNotFoundException(
				"System property \"%s\" is not an absolute path: \"%s\"".formatted(name, path));
		}
		return file;
	}

	/**
	 * Gets the absolute form {@link File} value of the environment variable by the given name
	 * 
	 * @param name The environment variable name
	 * @param required True if the given environment variable is required to be set; otherwise,
	 *   false
	 * @return The absolute form {@link File} value of the environment variable by the given name,
	 *   or null if it isn't set
	 * @throws FileNotFoundException if the property value was not an absolute path, or if it is
	 *   required and not set
	 */
	private static File getEnvFile(String name, boolean required) throws FileNotFoundException {
		String path = System.getenv(name);
		if (path == null || path.isBlank()) {
			if (required) {
				throw new FileNotFoundException(
					"Required environment variable \"%s\" is not set!".formatted(name));
			}
			return null;
		}
		path = path.trim();
		File file = new File(path);
		if (!file.isAbsolute()) {
			throw new FileNotFoundException(
				"Environment variable \"%s\" is not an absolute path: \"%s\"".formatted(name,
					path));
		}
		return file;
	}

	/**
	 * Gets a directory name that can be used to create a user-specific sub-directory in 
	 * {@code parentDir}. If the {@code parentDir} is contained within the user's home directory, 
	 * the given {@code appName} can simply be used since it will live in a user-specific location. 
	 * Otherwise, the user's name will get prepended to the {@code appName} so it does not collide 
	 * with other users' directories in the shared directory space.
	 * 
	 * @param parentDir The parent directory where we'd like to create a user-specific sub-directory
	 * @param appName The application name
	 * @return A directory name that can be used to create a user-specific sub-directory in 
	 *   {@code parentDir}.
	 * @throws FileNotFoundException if Java's user home directory is not defined or it is not an 
	 *   absolute path
	 */
	private static String getUserSpecificDirName(File parentDir, String appName)
			throws FileNotFoundException {
		String userSpecificDirName = appName;
		if (!FileUtilities.isPathContainedWithin(getJavaUserHomeDir(), parentDir)) {
			userSpecificDirName = SystemUtilities.getUserName() + "-" + appName;
		}
		return userSpecificDirName;
	}

	/**
	 * Creates the given {@link File directory} if it does not exist, and sets its permissions to
	 * owner-only
	 * 
	 * @param dir The directory to create
	 * @return The given directory
	 * @throws IOException if the directory failed to be created
	 */
	private static File createDir(File dir) throws IOException {
		if (dir != null) {
			if (!FileUtilities.mkdirs(dir)) {
				throw new IOException("Failed to create directory: " + dir);
			}
			FileUtilities.setOwnerOnlyPermissions(dir);
		}
		return dir;
	}
}
