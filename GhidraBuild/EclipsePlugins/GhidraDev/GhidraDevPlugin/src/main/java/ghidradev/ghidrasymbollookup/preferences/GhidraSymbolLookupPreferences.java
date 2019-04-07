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
package ghidradev.ghidrasymbollookup.preferences;

import org.eclipse.jface.preference.IPreferenceStore;

import ghidradev.Activator;

/**
 * Ghidra symbol lookup preference definitions and related utility methods.
 */
public class GhidraSymbolLookupPreferences {

	/**
	 * Whether or not the symbol lookup feature is enabled.
	 */
	static final String GHIDRA_SYMBOL_LOOKUP_ENABLED = "ghidradev.symbolLookupEnabled";

	/**
	 * Name of CDT project that will be used for symbol lookup. 
	 */
	static final String GHIDRA_SYMBOL_LOOKUP_PROJECT_NAME = "ghidradev.symbolLookupProjectName";

	/**
	 * Port used for symbol lookup.
	 */
	static final String GHIDRA_SYMBOL_LOOKUP_PORT_NUMBER = "ghidradev.symbolLookupPortNumber";

	/**
	 * Gets whether or not the symbol lookup feature is enabled.
	 * 
	 * @return True if the symbol lookup feature is enabled; otherwise, false.
	 */
	public static boolean isSymbolLookupEnabled() {
		IPreferenceStore prefs = Activator.getDefault().getPreferenceStore();
		return prefs.getBoolean(GHIDRA_SYMBOL_LOOKUP_ENABLED);
	}

	/**
	 * Sets whether or not the symbol lookup feature is enabled.
	 * 
	 * @param enabled True to enable the symbol lookup feature; false to disable it.
	 */
	public static void setSymbolLookupEnabled(boolean enabled) {
		IPreferenceStore prefs = Activator.getDefault().getPreferenceStore();
		prefs.setValue(GHIDRA_SYMBOL_LOOKUP_ENABLED, enabled);
	}

	/**
	 * Gets the name of the CDT project that used for symbol lookup.
	 * 
	 * @return The name of the CDT project used for symbol lookup, or null
	 *   if one hasn't been set.
	 */
	public static String getSymbolLookupProjectName() {
		IPreferenceStore prefs = Activator.getDefault().getPreferenceStore();
		String name = prefs.getString(GHIDRA_SYMBOL_LOOKUP_PROJECT_NAME);
		if (name.isEmpty()) {
			return null;
		}
		return name;
	}

	/**
	 * Gets the port used for symbol lookup.
	 * 
	 * @return The port used for symbol lookup.  Will return -1 if the port is not set.
	 */
	public static int getSymbolLookupPort() {
		IPreferenceStore prefs = Activator.getDefault().getPreferenceStore();
		try {
			return Integer.parseInt(prefs.getString(GHIDRA_SYMBOL_LOOKUP_PORT_NUMBER));
		}
		catch (NumberFormatException e) {
			return -1;
		}
	}
}
