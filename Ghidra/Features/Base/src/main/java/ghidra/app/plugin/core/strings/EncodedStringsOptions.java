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
package ghidra.app.plugin.core.strings;

import java.lang.Character.UnicodeScript;
import java.util.Set;

import ghidra.app.services.StringValidatorService;
import ghidra.docking.settings.Settings;
import ghidra.program.model.data.AbstractStringDataType;
import ghidra.util.SystemUtilities;

record EncodedStringsOptions(
		AbstractStringDataType stringDT,
		Settings settings,
		String charsetName,
		Set<UnicodeScript> requiredScripts,
		Set<UnicodeScript> allowedScripts,
		boolean excludeStringsWithErrors,
		boolean excludeNonStdCtrlChars,
		boolean alignStartOfString,
		int charSize,
		int minStringLength,
		boolean breakOnRef,
		StringValidatorService stringValidator,
		boolean requireValidString) {

	boolean equivalentStringCreationOptions(EncodedStringsOptions other) {
		// check only the options that would change how strings are created / read from memory
		// or produce values that are immutable in the table Row object
		return other != null && stringDT.equals(other.stringDT) &&
			equalValues(settings, other.settings) && charsetName.equals(other.charsetName) &&
			alignStartOfString == other.alignStartOfString && charSize == other.charSize &&
			stringValidator == other.stringValidator && breakOnRef == other.breakOnRef;

	}

	private static boolean equalValues(Settings s1, Settings s2) {
		Set<String> s1names = Set.of(s1.getNames());
		Set<String> s2names = Set.of(s2.getNames());
		if (!s1names.equals(s2names)) {
			return false;
		}
		for (String name : s1.getNames()) {
			Object s1val = s1.getValue(name);
			Object s2val = s2.getValue(name);
			if (!SystemUtilities.isEqual(s1val, s2val)) {
				return false;
			}
		}
		return true;
	}

}
