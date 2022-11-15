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

import ghidra.util.Msg;

/**
 * A class for storing {@link Font} values that have a String id (e.g. font.foo.bar) and either
 * a concrete font or a reference id which is the String id of another FontValue that it
 * will inherit its font from. So if this class's font value is non-null, the refId will be null
 * and if the class's refId is non-null, then the font value will be null.
 */
public class FontValue extends ThemeValue<Font> {
	static final String FONT_ID_PREFIX = "font.";
	public static final Font LAST_RESORT_DEFAULT = new Font("monospaced", Font.PLAIN, 12);
	private static final String EXTERNAL_PREFIX = "[font]";
	private FontModifier modifier;

	/**
	 * Constructor used when the FontValue will have a direct {@link Font} value. The refId
	 * will be null.
	 * @param id the id for this FontValue
	 * @param value the {@link Font} to associate with the given id
	 */
	public FontValue(String id, Font value) {
		super(id, null, value);
	}

	/**
	 * Constructor used when the FontValue will inherit its {@link Font} from another FontValue. The
	 * font value field will be null.
	 * @param id the id for this FontValue
	 * @param refId the id of another FontValue that this FontValue will inherit from
	 */
	public FontValue(String id, String refId) {
		super(id, refId, null);
	}

	private FontValue(String id, String refId, FontModifier modifier) {
		super(id, refId, null);
		this.modifier = modifier;
	}

	@Override
	public Font get(GThemeValueMap values) {
		Font font = super.get(values);
		if (modifier != null) {
			return modifier.modify(font);
		}
		return font;
	}

	@Override
	public String getSerializationString() {
		String outputId = toExternalId(id);
		return outputId + " = " + getValueOutput();
	}

	private String getValueOutput() {
		if (referenceId != null) {
			String refId = toExternalId(referenceId);
			if (modifier != null) {
				return refId + modifier.getSerializationString();
			}
			return refId;
		}
		return fontToString(value);
	}

	/**
	 * Converts a file to a string.
	 * @param font the font to convert to a String
	 * @return a String that represents the font
	 */
	public static String fontToString(Font font) {
		return String.format("%s-%s-%s", font.getName(), getStyleString(font), font.getSize());
	}

	/** 
	 * Returns true if the given key string is a valid external key for a font value
	 * @param key the key string to test
	 * @return true if the given key string is a valid external key for a font value
	 */
	public static boolean isFontKey(String key) {
		return key.startsWith(FONT_ID_PREFIX) || key.startsWith(EXTERNAL_PREFIX);
	}

	/**
	 * Parses the value string into a font or reference and creates a new FontValue using
	 * the given key and the parse results.
	 * @param key the key to associate the parsed value with
	 * @param value the font value to parse
	 * @return a FontValue with the given key and the parsed value
	 * @throws ParseException 
	 */
	public static FontValue parse(String key, String value) throws ParseException {
		String id = fromExternalId(key);

		value = clean(value);

		if (isFontKey(value)) {
			return getRefFontValue(id, value);
		}
		Font font = parseFont(value);
		return font == null ? null : new FontValue(id, font);
	}

	/**
	 * Returns the Font style int for the given style string
	 * @param styleString the string to convert to a Font style int
	 * @return the Font style int for the given style string
	 */
	public static int getStyle(String styleString) {
		if ("plain".equalsIgnoreCase(styleString)) {
			return Font.PLAIN;
		}
		if ("bold".equalsIgnoreCase(styleString)) {
			return Font.BOLD;
		}
		if ("italic".equalsIgnoreCase(styleString)) {
			return Font.ITALIC;
		}
		if ("bolditalic".equalsIgnoreCase(styleString)) {
			return Font.BOLD | Font.ITALIC;
		}
		return -1;
	}

	@Override
	protected FontValue getReferredValue(GThemeValueMap values, String refId) {
		return values.getFont(refId);
	}

	@Override
	protected Font getUnresolvedReferenceValue(String id, String unresolvedId) {
		Msg.warn(this,
			"Could not resolve indirect font path for \"" + unresolvedId +
				"\" for primary id \"" + id + "\", using last resort default");
		return LAST_RESORT_DEFAULT;
	}

	private static String toExternalId(String internalId) {
		if (internalId.startsWith(FONT_ID_PREFIX)) {
			return internalId;
		}
		return EXTERNAL_PREFIX + internalId;
	}

	private static String fromExternalId(String externalId) {
		if (externalId.startsWith(EXTERNAL_PREFIX)) {
			return externalId.substring(EXTERNAL_PREFIX.length());
		}
		return externalId;
	}

	private static Font parseFont(String value) {
		int sizeIndex = value.lastIndexOf("-");
		int styleIndex = value.lastIndexOf("-", sizeIndex - 1);
		if (sizeIndex <= 0 || styleIndex <= 0) {
			return null;
		}
		String sizeString = value.substring(sizeIndex + 1);
		String styleString = value.substring(styleIndex + 1, sizeIndex);
		String familyName = value.substring(0, styleIndex);

		try {
			int size = Integer.parseInt(sizeString);
			int style = getStyle(styleString);
			if (style >= 0) {
				return new Font(familyName, style, size);
			}
		}
		catch (NumberFormatException e) {
			// parse failed, return null
		}
		return null;
	}

	private static FontValue getRefFontValue(String id, String value) throws ParseException {
		if (value.startsWith(EXTERNAL_PREFIX)) {
			value = value.substring(EXTERNAL_PREFIX.length());
		}
		int modIndex = value.indexOf("[");
		if (modIndex < 0) {
			return new FontValue(id, fromExternalId(value));
		}
		String refId = value.substring(0, modIndex).trim();
		FontModifier modifier = FontModifier.parse(value.substring(modIndex));
		return new FontValue(id, refId, modifier);
	}

	private static String clean(String value) {
		value = value.trim();
		if (value.startsWith("(")) {
			value = value.substring(1);
		}
		if (value.endsWith(")")) {
			value = value.substring(0, value.length() - 1);
		}
		return value;
	}

	private static String getStyleString(Font font) {
		boolean bold = font.isBold();
		boolean italic = font.isItalic();
		if (bold && italic) {
			return "BOLDITALIC";
		}
		if (bold) {
			return "BOLD";
		}
		if (italic) {
			return "ITALIC";
		}
		return "PLAIN";
	}

	@Override
	public void installValue(ThemeManager themeManager) {
		themeManager.setFont(this);
	}

}
