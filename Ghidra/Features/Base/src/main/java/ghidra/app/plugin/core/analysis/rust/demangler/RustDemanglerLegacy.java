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
package ghidra.app.plugin.core.analysis.rust.demangler;

import java.util.ArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class RustDemanglerLegacy {
	public static String demangle(String symbol) {
		if (symbol.startsWith("_ZN")) { // Expected
			symbol = symbol.substring(3);
		}
		else if (symbol.startsWith("ZN")) {
			// On windows, dbghelp may strip leading underscore
			symbol = symbol.substring(2);
		}
		else if (symbol.startsWith("__ZN")) {
			// On macOS, symbols are prefixed with an extra _
			symbol = symbol.substring(4);
		}
		else {
			return null;
		}

		// Should only contain ASCII characters
		if (!symbol.matches("\\A\\p{ASCII}*\\z")) {
			return null;
		}

		ArrayList<String> elements = new ArrayList<String>();
		char[] chars = symbol.toCharArray();
		int i = 0;

		while (chars[i] != 'E') {
			if (chars[i] < '0' || chars[i] > '9') {
				return null;
			}

			int l = 0;
			while (chars[i + l] >= '0' && chars[i + l] <= '9') {
				l += 1;
			}

			String lengthString = symbol.substring(i, i + l);
			int length = Integer.parseInt(lengthString);
			String element = symbol.substring(i + l, i + l + length);
			elements.add(element);
			i = i + l + length;
		}

		for (int j = 0; j < elements.size(); j++) {
			String element = elements.get(j);
			element = element.replace("$SP$", "@");
			element = element.replace("$BP$", "*");
			element = element.replace("$RF$", "&");
			element = element.replace("$LT$", "<");
			element = element.replace("$GT$", ">");
			element = element.replace("$LP$", "(");
			element = element.replace("$RP$", ")");
			element = element.replace("$C$", ",");
			
			// Ghidra uses :: between namespace names
			element = element.replace("..", "::");

			int k = 0;
			while (k < element.length()) {
				if (element.charAt(k) == '$') {
					int l = k + 1;
					while (element.charAt(l) != '$') {
						l += 1;
					}

					l += 1;

					String inner = element.substring(k, l);
					if (inner.startsWith("$u")) {
						int num = Integer.parseInt(element.substring(k + 2, l - 1), 16);
						char newChar = (char) num;
						element = element.substring(0, k) + newChar + element.substring(l);
					}
				}

				k += 1;
			}

			elements.set(j, element);
		}
		
		// remove the last hash
		if (elements.size() > 1) {
			String string = elements.get(elements.size()-1);
			if (isUID(string)) {
				elements.remove(elements.size()-1);
			}
		}

		return String.join("::", elements);
	}

	/**
	 * Pattern to identify a legacy rust hash id suffix
	 * 
	 * Legacy mangled rust symbols:
	 * - start with _ZN
	 * - end withe E or E.
	 * - have a 16 digit hash that starts with 17h
	 * 
	 * The demangled string has the leading '17' and trailing 'E|E.' removed.
	 * 
	 * Sample: std::io::Read::read_to_end::hb85a0f6802e14499
	 */
	private static final Pattern RUST_LEGACY_HASHID_PATTERN =
		Pattern.compile("h[0-9a-f]{16}");

	private static boolean isUID(String string) {
		string = string.trim();
		Matcher m = RUST_LEGACY_HASHID_PATTERN.matcher(string);
		return m.matches();
	}
}
