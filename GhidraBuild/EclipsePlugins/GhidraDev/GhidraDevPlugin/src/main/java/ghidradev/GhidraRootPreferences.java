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
package ghidradev;

import org.eclipse.jface.preference.IPreferenceStore;

/**
 * General preference definitions and related utility methods.
 */
public class GhidraRootPreferences {

	/**
	 * Whether or not we have requested consent to open network ports.
	 */
	static final String GHIDRA_REQUESTED_OPEN_PORT_CONSENT = "ghidradev.requestedOpenPortConsent";

	/**
	 * Gets whether or not consent was requested to open network ports.
	 * 
	 * @return True if consent was requested to open network ports; otherwise, false.
	 */
	public static boolean requestedConsentToOpenPorts() {
		IPreferenceStore prefs = Activator.getDefault().getPreferenceStore();
		return prefs.getBoolean(GHIDRA_REQUESTED_OPEN_PORT_CONSENT);
	}

	/**
	 * Sets whether or not the user has given consent to open network ports. 
	 * 
	 * @param requested True if consent was requested to open network ports; otherwise, false.
	 */
	public static void setOpenPortConsentRequest(boolean requested) {
		IPreferenceStore prefs = Activator.getDefault().getPreferenceStore();
		prefs.setValue(GHIDRA_REQUESTED_OPEN_PORT_CONSENT, requested);
	}
}
