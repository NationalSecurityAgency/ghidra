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
import java.util.HashSet;
import java.util.Set;

import org.eclipse.core.resources.ResourcesPlugin;
import org.eclipse.core.runtime.preferences.AbstractPreferenceInitializer;
import org.eclipse.jface.preference.IPreferenceStore;

import ghidradev.Activator;

/**
 * Class used to initialize default preference values.
 */
public class GhidraProjectCreatorPreferenceInitializer extends AbstractPreferenceInitializer {

	@Override
	public void initializeDefaultPreferences() {
		IPreferenceStore store = Activator.getDefault().getPreferenceStore();
		store.setDefault(GhidraProjectCreatorPreferences.GHIDRA_INSTALL_PATHS, "");
		store.setDefault(GhidraProjectCreatorPreferences.GHIDRA_DEFAULT_INSTALL_PATH, "");
		store.setDefault(GhidraProjectCreatorPreferences.GHIDRA_LAST_PROJECT_ROOT_PATH,
			ResourcesPlugin.getWorkspace().getRoot().getLocation().toOSString());
		store.setDefault(GhidraProjectCreatorPreferences.GHIDRA_LAST_GRADLE_DISTRIBUTION, "");

		// If Ghidra launched Eclipse, automatically add in that Ghidra's location (if it doesn't 
		// already exist) as a convenience to the user.
		File ghidraInstallDir = Activator.getDefault().getGhidraInstallDir();
		if (ghidraInstallDir != null) {
			Set<File> dirs = new HashSet<>(GhidraProjectCreatorPreferences.getGhidraInstallDirs());
			if (!dirs.contains(ghidraInstallDir)) {
				if (dirs.isEmpty()) {
					GhidraProjectCreatorPreferences.setDefaultGhidraInstallDir(ghidraInstallDir);
				}
				dirs.add(ghidraInstallDir);
				GhidraProjectCreatorPreferences.setGhidraInstallDirs(dirs);
			}
		}
	}
}
