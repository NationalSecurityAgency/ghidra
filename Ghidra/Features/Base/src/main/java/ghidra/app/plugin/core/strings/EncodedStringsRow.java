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
import java.util.EnumSet;
import java.util.Set;

import ghidra.program.model.data.StringDataInstance;

record EncodedStringsRow(StringDataInstance sdi, StringInfo stringInfo, int refCount,
		int offcutCount, boolean validString) {

	boolean matches(EncodedStringsOptions options, EncodedStringsFilterStats stats) {
		stats.total++;

		String str = stringInfo.stringValue();
		if (options.minStringLength() > 0 && str.length() < options.minStringLength()) {
			stats.stringLength++;
			return false;
		}
		if (options.excludeStringsWithErrors() && stringInfo.hasCodecError()) {
			stats.codecErrors++;
			return false;
		}
		if (options.excludeNonStdCtrlChars() && stringInfo.hasNonStdCtrlChars()) {
			stats.nonStdCtrlChars++;
			return false;
		}

		stringInfo.scripts()
				.forEach(foundScript -> stats.foundScriptCounts.merge(foundScript, 1,
					(prevValue, newValue) -> prevValue + newValue));

		if (options.requiredScripts() != null && !options.requiredScripts().isEmpty()) {
			if (!stringInfo.scripts().containsAll(options.requiredScripts())) {
				stats.requiredScripts++;
				return false;
			}
		}
		if (options.allowedScripts() != null) {
			Set<UnicodeScript> scripts = EnumSet.copyOf(stringInfo.scripts());
			scripts.removeAll(CharacterScriptUtils.IGNORED_SCRIPTS);
			scripts.removeAll(options.requiredScripts());

			boolean hadLatin = scripts.remove(UnicodeScript.LATIN);
			boolean hadCommon = scripts.remove(UnicodeScript.COMMON);
			scripts.removeAll(options.allowedScripts());
			if (!scripts.isEmpty()) {
				stats.otherScripts += 1;
				return false;
			}
			if (hadLatin && !options.allowedScripts().contains(UnicodeScript.LATIN)) {
				stats.latinScript++;
				return false;
			}
			if (hadCommon && !options.allowedScripts().contains(UnicodeScript.COMMON)) {
				stats.commonScript++;
				return false;
			}
		}
		if (options.requireValidString() && options.stringValidator() != null && !validString) {
			stats.failedStringModel++;
			return false;
		}
		return true;
	}

}
