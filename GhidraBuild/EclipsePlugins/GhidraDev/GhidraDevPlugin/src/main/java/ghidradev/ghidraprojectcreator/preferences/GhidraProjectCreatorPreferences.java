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
package ghidradev.ghidraprojectcreator.preferences;

import java.io.File;
import java.util.*;
import java.util.stream.Collectors;

import org.eclipse.buildship.core.GradleDistribution;
import org.eclipse.jface.preference.IPreferenceStore;

import ghidradev.Activator;

/**
 * Ghidra project creator preference definitions and related utility methods.
 */
public class GhidraProjectCreatorPreferences {

	/**
	 * Paths to the Ghidra installation directories.
	 */
	static final String GHIDRA_INSTALL_PATHS = "ghidradev.ghidraInstallPaths";

	/**
	 * Path to the default Ghidra installation directory.
	 */
	static final String GHIDRA_DEFAULT_INSTALL_PATH = "ghidradev.ghidraDefaultInstallPath";

	/**
	 * Path to the last used Ghidra project root directory.
	 */
	static final String GHIDRA_LAST_PROJECT_ROOT_PATH = "ghidradev.ghidraLastProjectRootPath";

	/**
	 * The last used Gradle distribution.
	 */
	static final String GHIDRA_LAST_GRADLE_DISTRIBUTION = "ghidradev.ghidraLastGradleDistribution";

	/**
	 * Gets the set of Ghidra installation directories that's defined in the preferences.
	 * 
	 * @return The set of Ghidra installation directories that's defined in the preferences.
	 */
	public static Set<File> getGhidraInstallDirs() {
		IPreferenceStore prefs = Activator.getDefault().getPreferenceStore();
		String ghidraInstallDirPaths = prefs.getString(GHIDRA_INSTALL_PATHS);
		if (ghidraInstallDirPaths.isEmpty()) {
			return Collections.emptySet();
		}
		return Arrays.stream(ghidraInstallDirPaths.split(File.pathSeparator)).map(
			p -> new File(p)).collect(Collectors.toSet());
	}

	/**
	 * Sets the set of Ghidra installation directories that's defined in the preferences.
	 * 
	 * @param dirs The set of Ghidra installation directories that's defined in the preferences.
	 */
	public static void setGhidraInstallDirs(Set<File> dirs) {
		IPreferenceStore prefs = Activator.getDefault().getPreferenceStore();
		String paths = dirs.stream().map(dir -> dir.getAbsolutePath()).collect(
			Collectors.joining(File.pathSeparator));
		prefs.setValue(GHIDRA_INSTALL_PATHS, paths);
	}

	/**
	 * Gets the default Ghidra installation directory that's defined in the preferences.
	 * 
	 * @return The default Ghidra installation directory that's defined in the preferences.
	 *   Could be null if a default is not defined.
	 */
	public static File getGhidraDefaultInstallDir() {
		IPreferenceStore prefs = Activator.getDefault().getPreferenceStore();
		String ghidraDefaultInstallDirPath = prefs.getString(GHIDRA_DEFAULT_INSTALL_PATH);
		if (ghidraDefaultInstallDirPath.isEmpty()) {
			return null;
		}
		return new File(ghidraDefaultInstallDirPath);
	}

	/**
	 * Sets the default Ghidra installation directory that's defined in the preferences.
	 * 
	 * @param dir The default Ghidra installation directory that's defined in the preferences.
	 *   Could be null if there is no default.
	 */
	public static void setDefaultGhidraInstallDir(File dir) {
		IPreferenceStore prefs = Activator.getDefault().getPreferenceStore();
		prefs.setValue(GHIDRA_DEFAULT_INSTALL_PATH, dir != null ? dir.getAbsolutePath() : "");
	}

	/**
	 * Gets the last used Ghidra project root path that's defined in the preferences.
	 * 
	 * @return The last used Ghidra project root path that's defined in the preferences.
	 *   Could be the empty string.
	 */
	public static String getGhidraLastProjectRootPath() {
		IPreferenceStore prefs = Activator.getDefault().getPreferenceStore();
		return prefs.getString(GHIDRA_LAST_PROJECT_ROOT_PATH);
	}

	/**
	 * Sets the last used Ghidra project root path that's defined in the preferences.
	 * 
	 * @param path The last used Ghidra project root path that's defined in the preferences.
	 */
	public static void setGhidraLastProjectRootPath(String path) {
		IPreferenceStore prefs = Activator.getDefault().getPreferenceStore();
		prefs.setValue(GHIDRA_LAST_PROJECT_ROOT_PATH, path);
	}

	/**
	 * Gets the last used Ghidra Gradle distribution that's defined in the preferences.
	 * 
	 * @return The last used Ghidra Gradle distribution that's defined in the preferences.
	 *   Could be null if there is no last used distribution.
	 */
	public static GradleDistribution getGhidraLastGradleDistribution() {
		IPreferenceStore prefs = Activator.getDefault().getPreferenceStore();
		String pref = prefs.getString(GHIDRA_LAST_GRADLE_DISTRIBUTION);
		if (pref != null && !pref.isEmpty()) {
			try {
				return GradleDistribution.fromString(pref);
			}
			catch (Exception e) {
				// Failed to parse the string for some reason.  Fall through to null.
			}
		}
		return null;
	}

	/**
	 * Sets the last used Ghidra Gradle distribution that's defined in the preferences.
	 * 
	 * @param gradleDistribution The last used Ghidra Gradle distribution that's defined in the 
	 *   preferences.  Could be null if the preference should be set to the default.
	 */
	public static void setGhidraLastGradleDistribution(GradleDistribution gradleDistribution) {
		IPreferenceStore prefs = Activator.getDefault().getPreferenceStore();
		if (gradleDistribution != null) {
			prefs.setValue(GHIDRA_LAST_GRADLE_DISTRIBUTION, gradleDistribution.toString());
		}
		else {
			prefs.setToDefault(GHIDRA_LAST_GRADLE_DISTRIBUTION);
		}
	}
}
