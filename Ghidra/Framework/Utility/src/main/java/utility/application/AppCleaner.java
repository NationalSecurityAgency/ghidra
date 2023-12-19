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

import static utility.application.ApplicationUtilities.*;
import static utility.application.XdgUtils.*;

import java.io.File;
import java.util.*;

import generic.jar.ResourceFile;
import ghidra.GhidraApplicationLayout;
import ghidra.GhidraLaunchable;
import ghidra.framework.ApplicationProperties;
import ghidra.framework.OperatingSystem;
import ghidra.util.SystemUtilities;
import utilities.util.FileUtilities;

/**
 * Interactive utility to discover and delete artifacts that Ghidra lays down on the filesystem
 */
public class AppCleaner implements GhidraLaunchable {

	/**
	 * Launches the {@link AppCleaner}
	 * 
	 * @param layout The application layout to use for the launch
	 * @param args One argument is expected: the name of the application to clean.  All other
	 *   arguments are ignored.
	 * @throws Exception if there was a problem with the launch
	 */
	@Override
	public void launch(GhidraApplicationLayout layout, String[] args) throws Exception {

		if (args.length != 1) {
			System.out.println("Expected 1 argument but got " + args.length);
			System.exit(1);
		}

		String appName = args[0];
		System.out.println("\nDiscovering " + appName + " artifact directories....");

		// Discover directories
		Set<File> discoveredSet = new LinkedHashSet<>();
		discoveredSet.addAll(findSettingsDirs(appName, layout));
		discoveredSet.addAll(findCacheDirs(appName, layout));
		discoveredSet.addAll(findTempDirs(appName, layout));
		List<File> discoveredDirs = new ArrayList<>(discoveredSet);

		// Exit if we didn't discover any directories
		if (discoveredDirs.isEmpty()) {
			System.out.println("NONE FOUND");
			return;
		}

		// Output discovered directories and prompt user
		File potentialParentDir = null;
		for (int i = 0; i < discoveredDirs.size(); i++) {
			File d = discoveredDirs.get(i);
			File parentDir = d.getParentFile();
			boolean indent = parentDir.equals(potentialParentDir);
			System.out.println("%2d)%s %s".formatted(i + 1, indent ? "   " : "", d));
			if (!indent) {
				potentialParentDir = d;
			}
		}
		System.out.println("*) All");
		System.out.println("0) Exit");
		System.out.print("Enter a directory to delete: ");

		// Get user choice and delete
		String choice = null;
		try (Scanner scanner = new Scanner(System.in)){ 
			List<File> failures = new ArrayList<>();
			choice = scanner.nextLine().trim();
			switch (choice) {
				case "0":
					System.out.println("Exiting...");
					return;
				case "*":
					for (File dir : discoveredDirs) {
						if (dir.isDirectory()) {
							if (!FileUtilities.deleteDir(dir)) {
								failures.add(dir);
							}
						}
					}
					break;
				default:
					File dir = discoveredDirs.get(Integer.parseInt(choice) - 1);
					if (!FileUtilities.deleteDir(dir)) {
						failures.add(dir);
					}
			}
			System.out.println(failures.isEmpty() ? "SUCCESS" : "Failed to delete:");
			failures.forEach(dir -> System.out.println("   " + dir));
		}
		catch (NoSuchElementException e) {
			// User likely hit ctrl+c to exit
		}
		catch (NumberFormatException | IndexOutOfBoundsException e) {
			System.out.println("Invalid entry: \"" + choice + "\"");
		}
	}

	/**
	 * Finds user settings directories
	 * 
	 * @param appName The name of the application
	 * @param layout The layout
	 * @return A {@link Set} of discovered user settings directories, ordered such that
	 *   parent directories are directly followed by their subdirectories, if applicable
	 * @see ApplicationUtilities#getDefaultUserSettingsDir(ApplicationProperties, ResourceFile)
	 * @see ApplicationUtilities#getLegacyUserSettingsDir(ApplicationProperties, ResourceFile)
	 */
	private Set<File> findSettingsDirs(String appName, ApplicationLayout layout) {
		Set<File> discoveredDirs = new LinkedHashSet<>();
		appName = appName.toLowerCase();
		String userNameAndAppName = SystemUtilities.getUserName() + "-" + appName;

		// Legacy default settings directory
		getDirFromProperty("user.home", "." + appName).ifPresent(dir -> {
			discoveredDirs.add(dir);
			discoveredDirs.addAll(getSubdirs(dir));
		});

		// Current default settings directory
		File settingsDir = layout.getUserSettingsDir();
		File settingsParentDir = settingsDir.getParentFile();
		if (settingsParentDir != null && (settingsParentDir.getName().equals(appName) ||
			settingsParentDir.getName().equals(userNameAndAppName))) {
			discoveredDirs.add(settingsParentDir);
			discoveredDirs.addAll(getSubdirs(settingsParentDir));
		}

		// Application system property override (likely not set for AppCleaner)
		getDirFromProperty(PROPERTY_SETTINGS_DIR, appName).ifPresent(dir -> {
			discoveredDirs.add(dir);
			discoveredDirs.addAll(getSubdirs(dir));
		});
		getDirFromProperty(PROPERTY_SETTINGS_DIR, userNameAndAppName).ifPresent(dir -> {
			discoveredDirs.add(dir);
			discoveredDirs.addAll(getSubdirs(dir));
		});

		// XDG environment variable override		
		getDirFromEnv(XDG_CONFIG_HOME, appName).ifPresent(dir -> {
			discoveredDirs.add(dir);
			discoveredDirs.addAll(getSubdirs(dir));
		});
		getDirFromEnv(XDG_CONFIG_HOME, userNameAndAppName).ifPresent(dir -> {
			discoveredDirs.add(dir);
			discoveredDirs.addAll(getSubdirs(dir));
		});

		return discoveredDirs;
	}

	/**
	 * Finds user cache directories
	 * 
	 * @param appName The name of the application
	 * @param layout The layout
	 * @return A {@link Set} of discovered user cache directories, ordered such that
	 *   parent directories are directly followed by their subdirectories, if applicable
	 * @see ApplicationUtilities#getDefaultUserCacheDir(ApplicationProperties)
	 */
	private Set<File> findCacheDirs(String appName, ApplicationLayout layout) {
		Set<File> discoveredDirs = new LinkedHashSet<>();

		// Legacy cache directories
		if (OperatingSystem.CURRENT_OPERATING_SYSTEM.equals(OperatingSystem.WINDOWS)) {
			getDirFromEnv("LOCALAPPDATA", appName).ifPresent(discoveredDirs::add);
		}
		else {
			String legacyName = SystemUtilities.getUserName() + "-" + appName;
			getDirFromProperty("java.io.tmpdir", legacyName).ifPresent(discoveredDirs::add);
		}

		// Newer cache directories always use a lowercase application name
		appName = appName.toLowerCase();
		String userNameAndAppName = SystemUtilities.getUserName() + "-" + appName;

		// Current cache directories
		File cacheDir = layout.getUserCacheDir();
		if (cacheDir != null && cacheDir.isDirectory()) {
			discoveredDirs.add(cacheDir);
		}

		// Application system property override (likely not set for AppCleaner)
		getDirFromProperty(PROPERTY_CACHE_DIR, appName).ifPresent(discoveredDirs::add);
		getDirFromProperty(PROPERTY_CACHE_DIR, userNameAndAppName).ifPresent(discoveredDirs::add);

		// XDG environment variable override
		getDirFromEnv(XDG_CACHE_HOME, appName).ifPresent(discoveredDirs::add);
		getDirFromEnv(XDG_CACHE_HOME, userNameAndAppName).ifPresent(discoveredDirs::add);

		return discoveredDirs;
	}

	/**
	 * Finds user temp directories
	 * 
	 * @param appName The name of the application
	 * @param layout The layout
	 * @return A {@link Set} of discovered user temp directories, ordered such that
	 *   parent directories are directly followed by their subdirectories, if applicable
	 * @see ApplicationUtilities#getDefaultUserTempDir(String)
	 */
	private Set<File> findTempDirs(String appName, ApplicationLayout layout) {
		Set<File> discoveredDirs = new LinkedHashSet<>();

		// Legacy temp directories
		String legacyName = SystemUtilities.getUserName() + "-" + appName;
		if (OperatingSystem.CURRENT_OPERATING_SYSTEM.equals(OperatingSystem.WINDOWS)) {
			getDirFromEnv("TEMP", legacyName).ifPresent(discoveredDirs::add);
		}
		else {
			getDirFromProperty("java.io.tmpdir", legacyName).ifPresent(discoveredDirs::add);
		}

		// Newer temp directories always use a lowercase application name
		appName = appName.toLowerCase();
		String userNameAndAppName = SystemUtilities.getUserName() + "-" + appName;

		// Current temp directories
		File tempDir = layout.getUserTempDir();
		if (tempDir != null && tempDir.isDirectory()) {
			discoveredDirs.add(tempDir);
		}

		// Application system property override (likely not set for AppCleaner)
		getDirFromProperty(PROPERTY_TEMP_DIR, appName).ifPresent(discoveredDirs::add);
		getDirFromProperty(PROPERTY_TEMP_DIR, userNameAndAppName).ifPresent(discoveredDirs::add);

		// XDG environment variable override
		getDirFromEnv(XDG_RUNTIME_DIR, appName).ifPresent(discoveredDirs::add);
		getDirFromEnv(XDG_RUNTIME_DIR, userNameAndAppName).ifPresent(discoveredDirs::add);

		return discoveredDirs;
	}

	/**
	 * Gets the subdirectory of the given name found within the directory specified by the given 
	 * system property
	 * 
	 * @param propertyName The name of the system property
	 * @param subdirName The name of the subdirectory within the directory specified by the given
	 *   system property
	 * @return The subdirectory of the given name found within the directory specified by the given 
	 *   systemProperty
	 */
	private Optional<File> getDirFromProperty(String propertyName, String subdirName) {
		String path = System.getProperty(propertyName, "").trim();
		if (!path.isEmpty()) {
			File dir = new File(path, subdirName);
			if (dir.isDirectory()) {
				return Optional.of(dir);
			}
		}
		return Optional.empty();
	}

	/**
	 * Gets the subdirectory of the given name found within the directory specified by the given 
	 * environment variable
	 * 
	 * @param envName The name of the environment variable
	 * @param subdirName The name of the subdirectory within the directory specified by the given
	 *   environment variable
	 * @return The subdirectory of the given name found within the directory specified by the given 
	 *   environment variable
	 */
	private Optional<File> getDirFromEnv(String envName, String subdirName) {
		String path = System.getenv(envName);
		if (path != null && !path.isBlank()) {
			File dir = new File(path, subdirName);
			if (dir.isDirectory()) {
				return Optional.of(dir);
			}
		}
		return Optional.empty();
	}

	/**
	 * Gets the direct sub-directories of the given directory (non-recursive)
	 * 
	 * @param dir The directory to get the sub-directories of
	 * @return The direct sub-directories of the given directory
	 */
	private List<File> getSubdirs(File dir) {
		File[] listing = dir.listFiles(File::isDirectory);
		return listing != null ? Arrays.asList(listing) : List.of();

	}

}
