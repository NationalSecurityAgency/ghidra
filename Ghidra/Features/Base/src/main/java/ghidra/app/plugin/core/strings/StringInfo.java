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
import java.util.*;

import ghidra.util.StringUtilities;

/**
 * Information about a string.
 * 
 * @param stringValue string itself
 * @param scripts set of scripts (alphabets) that the string is made of
 * @param stringFeatures set of informational flags about various conditions found in the string
 */
public record StringInfo(
		String stringValue,
		Set<UnicodeScript> scripts,
		Set<StringInfoFeature> stringFeatures) {

	private static final Set<Character> STD_CTRL_CHARS = Set.of('\n', '\t', '\r');

	/**
	 * Creates a {@link StringInfo} instance
	 * 
	 * @param s string
	 * @return new {@link StringInfo} instance
	 */
	public static StringInfo fromString(String s) {
		s = Objects.requireNonNullElse(s, "");
		EnumSet<UnicodeScript> scripts = EnumSet.noneOf(UnicodeScript.class);
		EnumSet<StringInfoFeature> features = EnumSet.noneOf(StringInfoFeature.class);

		s.codePoints().forEach(codePoint -> {
			try {
				UnicodeScript script = Character.UnicodeScript.of(codePoint);
				if (script == UnicodeScript.UNKNOWN) {
					features.add(StringInfoFeature.CODEC_ERROR); // TODO: are we mis-using this enum to signal bad character?
				}
				else {
					scripts.add(script);
				}

				if (codePoint == StringUtilities.UNICODE_REPLACEMENT) {
					features.add(StringInfoFeature.CODEC_ERROR);
				}
				if ((codePoint < 32 && !STD_CTRL_CHARS.contains((char) codePoint)) ||
					!Character.isDefined(codePoint)) {
					features.add(StringInfoFeature.NON_STD_CTRL_CHARS);
				}
			}
			catch (IllegalArgumentException e) {
				// ignore this codepoint
			}
		});
		return new StringInfo(s, scripts, features);
	}

	public boolean hasCodecError() {
		return stringFeatures.contains(StringInfoFeature.CODEC_ERROR);
	}

	public boolean hasNonStdCtrlChars() {
		return stringFeatures.contains(StringInfoFeature.NON_STD_CTRL_CHARS);
	}

}
