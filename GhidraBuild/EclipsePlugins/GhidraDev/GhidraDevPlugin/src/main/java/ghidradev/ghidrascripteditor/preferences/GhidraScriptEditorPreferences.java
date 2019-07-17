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
package ghidradev.ghidrascripteditor.preferences;

import org.eclipse.jface.preference.IPreferenceStore;

import ghidradev.Activator;

/**
 * Ghidra script editor preference definitions and related utility methods.
 */
public class GhidraScriptEditorPreferences {

	/**
	 * Whether or not the script editor feature is enabled.
	 */
	static final String GHIDRA_SCRIPT_EDITOR_ENABLED = "ghidradev.scriptEditorEnabled";

	/**
	 * Port used for script editor.
	 */
	static final String GHIDRA_SCRIPT_EDITOR_PORT_NUMBER = "ghidradev.scriptEditorPortNumber";

	/**
	 * Gets whether or not the script editor feature is enabled.
	 * 
	 * @return True if the script editor feature is enabled; otherwise, false.
	 */
	public static boolean isScriptEditorEnabled() {
		IPreferenceStore prefs = Activator.getDefault().getPreferenceStore();
		return prefs.getBoolean(GHIDRA_SCRIPT_EDITOR_ENABLED);
	}

	/**
	 * Sets whether or not the script editor feature is enabled.
	 * 
	 * @param enabled True to enable the script editor feature; false to disable it.
	 */
	public static void setScriptEditorEnabled(boolean enabled) {
		IPreferenceStore prefs = Activator.getDefault().getPreferenceStore();
		prefs.setValue(GHIDRA_SCRIPT_EDITOR_ENABLED, enabled);
	}

	/**
	 * Gets the port used for script editor.
	 * 
	 * @return The port used for script editor.  Will return -1 if the port is not set.
	 */
	public static int getScriptEditorPort() {
		IPreferenceStore prefs = Activator.getDefault().getPreferenceStore();
		try {
			return Integer.parseInt(prefs.getString(GHIDRA_SCRIPT_EDITOR_PORT_NUMBER));
		}
		catch (NumberFormatException e) {
			return -1;
		}
	}
}
