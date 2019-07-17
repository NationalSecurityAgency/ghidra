/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.framework.options;

import java.awt.Font;

/**
 * A wrapper object for registering fonts as options.
 */

class WrappedFont implements WrappedOption {
	private static final String FAMILY = "family";
	private static final String SIZE = "size";
	private static final String STYLE = "style";
	private Font font;

	/**
	 * Constructs a WrappedOption for a font.
	 * @param font font to wrap
	 */
	WrappedFont(Font font) {
		this.font = font;
	}

	/** 
	 * Default constructor.
	 * @see java.lang.Object#Object()
	 */
	public WrappedFont() {
		// for reflection
	}

	@Override
	public Object getObject() {
		return font;
	}

	/**
	 * Reads the saved Font information and reconstructs the font.
	 */
	@Override
	public void readState(SaveState saveState) {
		String family = saveState.getString(FAMILY, "monospaced");
		int size = saveState.getInt(SIZE, 12);
		int style = saveState.getInt(STYLE, Font.PLAIN);
		font = new Font(family, style, size);
	}

	/**
	 * Saves the Font information so that it can be reconstructed.
	 */
	@Override
	public void writeState(SaveState saveState) {
		String family = font.getFamily();
		int pos = family.indexOf(".");
		if (pos > 0) {
			family = family.substring(0, pos);
		}
		saveState.putString(FAMILY, family);
		saveState.putInt(SIZE, font.getSize());
		saveState.putInt(STYLE, font.getStyle());
	}

	@Override
	public OptionType getOptionType() {
		return OptionType.FONT_TYPE;
	}
}
