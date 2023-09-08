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
package ghidra.app.plugin.core.terminal.vt;

/**
 * A legacy style charset
 * 
 * <p>
 * Finding the particulars for these online has not been fun, so these are implemented on an
 * as-needed basis. There's probably a simple translation to some unicode code pages, since those
 * seem to be ordered by some of these legacy character sets. The default implementation for each
 * charset will just be equivalent to US-ASCII. There's a lot of plumbing missing around these, two.
 * For example, I'm assuming that switching to "the alternate charset" means using G1 instead of G0.
 * I've not read carefully enough to know how G2 or G3 are used.
 * 
 * <p>
 * It'd be nice to just use UTF-8, but the application would have to agree.
 */
public enum VtCharset {
	UK,
	USASCII,
	FINNISH,
	SWEDISH,
	GERMAN,
	FRENCH_CANADIAN,
	FRENCH,
	ITALIAN,
	SPANISH,
	DUTCH,
	GREEK,
	TURKISH,
	PORTUGESE,
	HEBREW,
	SWISS,
	NORWEGIAN_DANISH,

	DEC_SPECIAL_LINES {
		@Override
		public char mapChar(char c) {
			switch (c) {
				case 'j':
					return '\u2518'; // 1pt lower-right corner
				case 'k':
					return '\u2510'; // 1pt upper-right corner
				case 'l':
					return '\u250C'; // 1pt upper-left corner
				case 'm':
					return '\u2514'; // 1pt lower-left corner
				case 'q':
					return '\u2500'; // 1pt horizontal line
				case 'x':
					return '\u2502'; // 1pt vertical line
			}
			return super.mapChar(c);
		}
	},
	DEC_SUPPLEMENTAL,
	DEC_TECHNICAL,

	DEC_HEBREW,
	DEC_GREEK,
	DEC_TURKISH,
	DEC_SUPPLEMENTAL_GRAPHICS,
	DEC_CYRILLIC,
	;

	/**
	 * The designation for a charset slot
	 * 
	 * <p>
	 * It seems the terminal allows for the selection of 4 alternative charsets, the first of which
	 * G0 is the default or primary.
	 */
	public enum G {
		G0('('), G1(')'), G2('*'), G3('-');

		public final byte b;

		/**
		 * Construct a charset slot designator
		 * 
		 * @param b the byte in the control sequence that identifies this slot
		 */
		private G(char b) {
			this.b = (byte) b;
		}
	}

	/**
	 * Map a character, as decoded using US-ASCII, into the actual character for the character set.
	 * 
	 * @param c the character from US-ASCII.
	 * @return the mapped character
	 */
	public char mapChar(char c) {
		return c;
	}
}
