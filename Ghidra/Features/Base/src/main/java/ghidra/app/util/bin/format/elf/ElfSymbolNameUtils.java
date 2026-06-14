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
package ghidra.app.util.bin.format.elf;

import ghidra.program.model.symbol.SymbolUtilities;

public class ElfSymbolNameUtils {

	/**
	 * Converts a string with possible invalid characters into a valid symbol string.
	 * <p>
	 * See {@link #getBadElfSymbolStringCodePointReplacement(int, int)}
	 * 
	 * @param str symbol string to fix, null ok
	 * @return original str instance if already valid, otherwise fixed value
	 */
	public static String replaceInvalidChars(String str) {
		return SymbolUtilities.replaceInvalidChars(str,
			ElfSymbolNameUtils::getBadElfSymbolStringCodePointReplacement);
	}

	/**
	 * Returns a replacement value for any bad code points found in an Elf symbol string.
	 *  
	 * @param index index of the bad code point in the original string
	 * @param cp the bad code point
	 * @return replacement value to use instead of the bad code point
	 */
	public static String getBadElfSymbolStringCodePointReplacement(int index, int cp) {
		if (cp < 0x20) {
			// Format as ^Control character for consistency with readelf
			// will range between ^@ .. ^_  (0..31)
			return "^%c".formatted('@' + cp);
		}
		else if (cp == 0x7F) {
			// Format as ^? character for consistency with readelf
			return "^?";
		}
		else if (cp == ' ') {
			return "_";
		}
		else {
			return null; // omit the bad codepoint that caused this callback to be invoked
		}
	}

}
