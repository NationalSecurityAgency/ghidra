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
package generic.theme;

import java.awt.Font;
import java.text.ParseException;
import java.util.List;

/**
 * Class that can transform one font into another. For example if want a font that is the same
 * basic font as some other font, but is just a different size,style, or family, you use a
 * FontModifier
 */
public class FontModifier {
	private String family;
	private Integer style;
	private Integer size;

	private FontModifier() {

	}

	/**
	 * Creates a new FontModifier that can change a given font by one or more font properties.
	 * @param family if non-null, modifies a font to use this family
	 * @param style if non-null, modifies a font to use this style
	 * @param size if non-null, modifies a font to be this size
	 */
	public FontModifier(String family, Integer style, Integer size) {
		this.family = family;
		this.style = style;
		this.size = size;
	}

	/**
	 * Sets the family for modifying a font
	 * @param newFamily the font family to use when modifying fonts
	 */
	public void addFamilyModifier(String newFamily) {
		if (family != null) {
			throw new IllegalStateException("Multiple font family names specified");
		}
		this.family = newFamily;
	}

	/**
	 * Sets the font size modifier
	 * @param newSize the size to use when modifying fonts
	 */
	public void addSizeModfier(int newSize) {
		if (size != null) {
			throw new IllegalStateException("Multiple font sizes specified");
		}
		this.size = newSize;
	}

	/**
	 * Sets the font stle modifier. This can be called multiple times to bold and italicize.
	 * @param newStyle the style to use for the font.
	 */
	public void addStyleModifier(int newStyle) {
		if (style == null) {
			style = newStyle;
			return;
		}
		if (style == Font.PLAIN || newStyle == Font.PLAIN) {
			throw new IllegalStateException("Attempted to set incompable styles");
		}
		style = style | newStyle;
	}

	/**
	 * Returns a modified font for the given font.
	 * @param font the font to be modified
	 * @return a new modified font
	 */
	public Font modify(Font font) {
		if (family == null) {
			if (style != null && size != null) {
				return font.deriveFont(style, size);
			}
			else if (style != null) {
				return font.deriveFont(style);
			}
			return font.deriveFont((float) size);
		}
		int newStyle = style != null ? style : font.getStyle();
		int newSize = size != null ? size : font.getSize();
		return new Font(family, newStyle, newSize);
	}

	/**
	 * Returns a string that can be parsed by the {@link #parse(String)} method of this class
	 * @return a string that can be parsed by the {@link #parse(String)} method of this class
	 */
	public String getSerializationString() {
		StringBuilder builder = new StringBuilder();
		if (family != null) {
			builder.append("[" + family + "]");
		}
		if (size != null) {
			builder.append("[" + size + "]");
		}
		if (style != null) {
			switch (style.intValue()) {
				case Font.PLAIN:
					builder.append("[plain]");
					break;
				case Font.BOLD:
					builder.append("[bold]");
					break;
				case Font.ITALIC:
					builder.append("[italic]");
					break;
				case Font.BOLD | Font.ITALIC:
					builder.append("[bold][italic]");
					break;
			}
		}

		return builder.toString();
	}

	/**
	 * Parses the given string as one or more font modifiers
	 * @param value the string to parse as modifiers
	 * @return a FontModifier as specified by the given string
	 * @throws ParseException if The value can't be parsed
	 */
	public static FontModifier parse(String value) throws ParseException {
		List<String> modifierValues = ThemeValueUtils.parseGroupings(value, '[', ']');
		if (modifierValues.isEmpty()) {
			return null;
		}
		FontModifier modifier = new FontModifier();
		for (String modifierString : modifierValues) {
			if (setSize(modifier, modifierString)) {
				continue;
			}
			if (setStyle(modifier, modifierString)) {
				continue;
			}
			setFamily(modifier, modifierString);
		}
		if (modifier.hadModifications()) {
			return modifier;
		}
		return null;
	}

	private static void setFamily(FontModifier modifier, String modifierString)
			throws ParseException {
		try {
			modifier.addFamilyModifier(modifierString);
		}
		catch (IllegalStateException e) {
			throw new ParseException("Multiple Font Families specfied", 0);
		}

	}

	private boolean hadModifications() {
		return family != null || size != null || style != null;
	}

	private static boolean setStyle(FontModifier modifier, String modifierString)
			throws ParseException {
		int style = FontValue.getStyle(modifierString);
		if (style >= 0) {
			try {
				modifier.addStyleModifier(style);
			}
			catch (IllegalStateException e) {
				throw new ParseException("Illegal style combination", 0);
			}
			return true;
		}
		return false;
	}

	private static boolean setSize(FontModifier modifier, String modifierString) {
		try {
			int size = Integer.parseInt(modifierString);
			modifier.addSizeModfier(size);
			return true;
		}
		catch (NumberFormatException e) {
			return false;
		}
	}

}
