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

import static java.lang.Character.UnicodeScript.*;

import java.awt.Font;
import java.lang.Character.UnicodeScript;
import java.util.*;

public class CharacterScriptUtils {
	/**
	 * Scripts that are not helpful to use when filtering strings
	 */
	public static final List<UnicodeScript> IGNORED_SCRIPTS = List.of(INHERITED, UNKNOWN);

	/**
	 * The {@link UnicodeScript} value that represents the "ANY" choice.  This is a bit of a hack
	 * and re-uses the INHERITED enum value for this purpose.
	 */
	public static final UnicodeScript ANY_SCRIPT_ALIAS = UnicodeScript.INHERITED;

	/**
	 * Premade examples of characters from each specified script, using info from
	 * https://omniglot.com/language/phrases/hovercraft.htm and
	 * google translate, similar to lorem ipsum placeholding text.
	 * <p>
	 * Encoded using escape sequences to avoid any mangling by ASCII processing.
	 * <p>
	 * Scripts not in this map will have an example created from the first couple of characters
	 * from their unicode block that are visible to the user with their current font.
	 */
	static Map<UnicodeScript, String> PREMADE_EXAMPLES = Map.of(
		COMMON, "0-9,!?",
		ARABIC,
		"\u062d\u064e\u0648\u0651\u0627\u0645\u062a\u064a \u0645\u064f\u0645\u0652\u062a\u0650\u0644\u0626\u0629 \u0628\u0650\u0623\u064e\u0646\u0652\u0642\u064e\u0644\u064e\u064a\u0652\u0633\u0648\u0646",
		CYRILLIC,
		"\u041c\u043e\u0451 \u0441\u0443\u0434\u043d\u043e \u043d\u0430 \u0432\u043e\u0437\u0434\u0443",
		HAN, "\u6211\u7684\u6c23\u588a\u8239\u88dd\u6eff\u4e86\u9c3b\u9b5a",
		HANGUL,
		"\uc81c \ud638\ubc84\ud06c\ub798\ud504\ud2b8\uac00 \uc7a5\uc5b4\ub85c \uac00\ub4dd\ud574\uc694",
		KATAKANA,
		"\u79c1\u306e\u30db\u30d0\u30fc\u30af\u30e9\u30d5\u30c8\u306f\u9c3b\u3067\u3044\u3063\u3071\u3044\u3067\u3059" // mix of han, hiragana, katakana
	);

	/**
	 * Builds a map of example character sequences for every current UnicodeScript, where the
	 * specified font can display the characters of that script.
	 * 
	 * @param f {@link Font}
	 * @param maxExampleLen length of the character sequence to generate
	 * @return map of unicodescript-to-string
	 */
	public static Map<UnicodeScript, String> getDisplayableScriptExamples(Font f,
			int maxExampleLen) {
		Map<UnicodeScript, String> result = new HashMap<>();
		for (int i = 0; i < Character.MAX_CODE_POINT; i++) {
			if (!Character.isISOControl(i)) {
				UnicodeScript us = UnicodeScript.of(i);
				String s = result.getOrDefault(us, "");
				if (s.length() < maxExampleLen && f.canDisplay(i)) {
					// Note: waiting until after f.canDisplay ensures we don't add PREMADEs if not displayable
					String premade = PREMADE_EXAMPLES.get(us);
					s = premade == null ? s + Character.toString(i) : premade;
					result.put(us, s);
				}
			}
		}
		return result;
	}

}
