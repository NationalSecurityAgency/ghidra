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

import org.eclipse.core.runtime.preferences.AbstractPreferenceInitializer;
import org.eclipse.jface.preference.IPreferenceStore;

import ghidradev.Activator;

/**
 * Class used to initialize default preference values.
 */
public class GhidraSymbolLookupPreferenceInitializer extends AbstractPreferenceInitializer {

	@Override
	public void initializeDefaultPreferences() {
		IPreferenceStore store = Activator.getDefault().getPreferenceStore();
		store.setDefault(GhidraSymbolLookupPreferences.GHIDRA_SYMBOL_LOOKUP_ENABLED, false);
		store.setDefault(GhidraSymbolLookupPreferences.GHIDRA_SYMBOL_LOOKUP_PROJECT_NAME, "");
		store.setDefault(GhidraSymbolLookupPreferences.GHIDRA_SYMBOL_LOOKUP_PORT_NUMBER, "12322");
	}
}
