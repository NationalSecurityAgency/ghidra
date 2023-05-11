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
package ghidra.util;

import java.awt.Color;
import java.util.HashMap;
import java.util.Map;

/**
 * Class for web color support. This class defines many of the colors used by html. This class
 * includes methods for converting a color to a string (name or hex value) and for converting
 * those strings back to a color.
 */
public abstract class WebColors {
	private static final Map<String, Color> nameToColorMap = new HashMap<>();
	private static final Map<Integer, String> colorToNameMap = new HashMap<>();

	//@formatter:off
	public static final Color BLACK = registerColor("Black", Color.black);
	public static final Color NAVY = registerColor("Navy", Color.decode("0x000080"));
	public static final Color DARK_BLUE = registerColor("DarkBlue", Color.decode("0x00008B"));
	public static final Color MEDIUM_BLUE = registerColor("MediumBlue", Color.decode("0x0000CD"));
	public static final Color BLUE = registerColor("Blue", Color.decode("0x0000FF"));
	public static final Color DARK_GREEN = registerColor("DarkGreen", Color.decode("0x006400"));
	public static final Color GREEN = registerColor("Green", Color.decode("0x008000"));
	public static final Color TEAL = registerColor("Teal", Color.decode("0x008080"));
	public static final Color DARK_CYAN = registerColor("DarkCyan", Color.decode("0x008B8B"));
	public static final Color DEEP_SKY_BLUE = registerColor("DeepSkyBlue", Color.decode("0x00BFFF"));
	public static final Color DARK_TURQUOSE = registerColor("DarkTurquoise", Color.decode("0x00CED1"));
	public static final Color LIME = registerColor("Lime", Color.decode("0x00FF00"));
	public static final Color SPRING_GREEN = registerColor("SpringGreen", Color.decode("0x00FF7F"));
	public static final Color AQUA = registerColor("Aqua", Color.decode("0x00FFFF"));
	public static final Color CYAN = registerColor("Cyan", Color.decode("0x00FFFF"));
	public static final Color MIDNIGHT_BLUE = registerColor("MidnightBlue", Color.decode("0x191970"));
	public static final Color DOGER_BLUE = registerColor("DodgerBlue", Color.decode("0x1E90FF"));
	public static final Color LIGHT_SEA_GREEN = registerColor("LightSeaGreen", Color.decode("0x20B2AA"));
	public static final Color FOREST_GREEN = registerColor("ForestGreen", Color.decode("0x228B22"));
	public static final Color SEA_GREEN = registerColor("SeaGreen", Color.decode("0x2E8B57"));
	public static final Color DARK_SLATE_GRAY = registerColor("DarkSlateGray", Color.decode("0x2F4F4F"));
	public static final Color LIME_GREEN = registerColor("LimeGreen", Color.decode("0x32CD32"));
	public static final Color TURQUOISE = registerColor("Turquoise", Color.decode("0x40E0D0"));
	public static final Color ROYAL_BLUE = registerColor("RoyalBlue", Color.decode("0x4169E1"));
	public static final Color STEEL_BLUE = registerColor("SteelBlue", Color.decode("0x4682B4"));
	public static final Color DARK_SLATE_BLUE = registerColor("DarkSlateBlue", Color.decode("0x483D8B"));
	public static final Color INDIGO = registerColor("Indigo", Color.decode("0x4B0082"));
	public static final Color CADET_BLUE = registerColor("CadetBlue", Color.decode("0x5F9EA0"));
	public static final Color REBECCA_PURPLE = registerColor("RebeccaPurple", Color.decode("0x663399"));
	public static final Color DIM_GRAY = registerColor("DimGray", Color.decode("0x696969"));
	public static final Color SLATE_BLUE = registerColor("SlateBlue", Color.decode("0x6A5ACD"));
	public static final Color OLIVE_DRAB = registerColor("OliveDrab", Color.decode("0x6B8E23"));
	public static final Color SLATE_GRAY = registerColor("SlateGray", Color.decode("0x708090"));
	public static final Color LAWN_GREEN = registerColor("LawnGreen", Color.decode("0x7CFC00"));
	public static final Color CHARTREUSE = registerColor("Chartreuse", Color.decode("0x7FFF00"));
	public static final Color AQUAMARINE = registerColor("Aquamarine", Color.decode("0x7FFFD4"));
	public static final Color MAROON = registerColor("Maroon", Color.decode("0x800000"));
	public static final Color PURPLE = registerColor("Purple", Color.decode("0x800080"));
	public static final Color OLIVE = registerColor("Olive", Color.decode("0x808000"));
	public static final Color GRAY = registerColor("Gray", Color.decode("0x808080"));
	public static final Color SYY_BLUE = registerColor("SkyBlue", Color.decode("0x87CEEB"));
	public static final Color LIGHT_SKY_BLUE = registerColor("LightSkyBlue", Color.decode("0x87CEFA"));
	public static final Color BLUE_VIOLET = registerColor("BlueViolet", Color.decode("0x8A2BE2"));
	public static final Color DARK_RED = registerColor("DarkRed", Color.decode("0x8B0000"));
	public static final Color DARK_MAGENTA = registerColor("DarkMagenta", Color.decode("0x8B008B"));
	public static final Color SADDLE_BROWN = registerColor("SaddleBrown", Color.decode("0x8B4513"));
	public static final Color DARK_SEA_GREEN = registerColor("DarkSeaGreen", Color.decode("0x8FBC8F"));
	public static final Color LIGHT_GREEN = registerColor("LightGreen", Color.decode("0x90EE90"));
	public static final Color MEDIUM_PURPLE = registerColor("MediumPurple", Color.decode("0x9370DB"));
	public static final Color DARK_VIOLET = registerColor("DarkViolet", Color.decode("0x9400D3"));
	public static final Color PALE_GREEN = registerColor("PaleGreen", Color.decode("0x98FB98"));
	public static final Color DARK_ORCHID = registerColor("DarkOrchid", Color.decode("0x9932CC"));
	public static final Color YELLOW_GREEN = registerColor("YellowGreen", Color.decode("0x9ACD32"));
	public static final Color SIENNA = registerColor("Sienna", Color.decode("0xA0522D"));
	public static final Color BROWN = registerColor("Brown", Color.decode("0xA52A2A"));
	public static final Color DARK_GRAY = registerColor("DarkGray", Color.decode("0xA9A9A9"));
	public static final Color LIGHT_BLUE = registerColor("LightBlue", Color.decode("0xADD8E6"));
	public static final Color GREEN_YELLOW = registerColor("GreenYellow", Color.decode("0xADFF2F"));
	public static final Color PALE_TURQUOISE = registerColor("PaleTurquoise", Color.decode("0xAFEEEE"));
	public static final Color POWDER_BLUE = registerColor("PowderBlue", Color.decode("0xB0E0E6"));
	public static final Color FIRE_BRICK = registerColor("FireBrick", Color.decode("0xB22222"));
	public static final Color DARK_GOLDENROD = registerColor("DarkGoldenRod", Color.decode("0xB8860B"));
	public static final Color MEDIUM_ORCHID = registerColor("MediumOrchid", Color.decode("0xBA55D3"));
	public static final Color ROSY_BROWN = registerColor("RosyBrown", Color.decode("0xBC8F8F"));
	public static final Color DARK_KHAKI = registerColor("DarkKhaki", Color.decode("0xBDB76B"));
	public static final Color SILVER = registerColor("Silver", Color.decode("0xC0C0C0"));
	public static final Color INDIAN_RED = registerColor("IndianRed", Color.decode("0xCD5C5C"));
	public static final Color PERU = registerColor("Peru", Color.decode("0xCD853F"));
	public static final Color CHOCOLATE = registerColor("Chocolate", Color.decode("0xD2691E"));
	public static final Color TAN = registerColor("Tan", Color.decode("0xD2B48C"));
	public static final Color LIGHT_GRAY = registerColor("LightGray", Color.decode("0xD3D3D3"));
	public static final Color THISTLE = registerColor("Thistle", Color.decode("0xD8BFD8"));
	public static final Color ORCHID = registerColor("Orchid", Color.decode("0xDA70D6"));
	public static final Color GOLDEN_ROD = registerColor("GoldenRod", Color.decode("0xDAA520"));
	public static final Color PALE_VIOLET_RED = registerColor("PaleVioletRed", Color.decode("0xDB7093"));
	public static final Color CRIMSON = registerColor("Crimson", Color.decode("0xDC143C"));
	public static final Color GAINSBORO = registerColor("Gainsboro", Color.decode("0xDCDCDC"));
	public static final Color PLUM = registerColor("Plum", Color.decode("0xDDA0DD"));
	public static final Color BURLYWOOD = registerColor("BurlyWood", Color.decode("0xDEB887"));
	public static final Color LIGHT_CYAN = registerColor("LightCyan", Color.decode("0xE0FFFF"));
	public static final Color LAVENDER = registerColor("Lavender", Color.decode("0xE6E6FA"));
	public static final Color DARK_SALMON = registerColor("DarkSalmon", Color.decode("0xE9967A"));
	public static final Color VIOLET = registerColor("Violet", Color.decode("0xEE82EE"));
	public static final Color PALE_GOLDENROD = registerColor("PaleGoldenRod", Color.decode("0xEEE8AA"));
	public static final Color LIGHT_CORAL = registerColor("LightCoral", Color.decode("0xF08080"));
	public static final Color KHAKE = registerColor("Khaki", Color.decode("0xF0E68C"));
	public static final Color ALICE_BLUE = registerColor("AliceBlue", Color.decode("0xF0F8FF"));
	public static final Color HONEY_DEW = registerColor("HoneyDew", Color.decode("0xF0FFF0"));
	public static final Color AZURE = registerColor("Azure", Color.decode("0xF0FFFF"));
	public static final Color SANDY_BROWN = registerColor("SandyBrown", Color.decode("0xF4A460"));
	public static final Color WHEAT = registerColor("Wheat", Color.decode("0xF5DEB3"));
	public static final Color BEIGE = registerColor("Beige", Color.decode("0xF5F5DC"));
	public static final Color WHITE_SMOKE = registerColor("WhiteSmoke", Color.decode("0xF5F5F5"));
	public static final Color MINT_CREAM = registerColor("MintCream", Color.decode("0xF5FFFA"));
	public static final Color GHOST_WHITE = registerColor("GhostWhite", Color.decode("0xF8F8FF"));
	public static final Color SALMON = registerColor("Salmon", Color.decode("0xFA8072"));
	public static final Color ANTIQUE_WHITE = registerColor("AntiqueWhite", Color.decode("0xFAEBD7"));
	public static final Color LINEN = registerColor("Linen", Color.decode("0xFAF0E6"));
	public static final Color OLDLACE = registerColor("OldLace", Color.decode("0xFDF5E6"));
	public static final Color RED = registerColor("Red", Color.decode("0xFF0000"));
	public static final Color FUCHSIA = registerColor("Fuchsia", Color.decode("0xFF00FF"));
	public static final Color MAGENTA = registerColor("Magenta", Color.decode("0xFF00FF"));
	public static final Color DEEP_PINK = registerColor("DeepPink", Color.decode("0xFF1493"));
	public static final Color ORANGE_RED = registerColor("OrangeRed", Color.decode("0xFF4500"));
	public static final Color TOMATO = registerColor("Tomato", Color.decode("0xFF6347"));
	public static final Color HOT_PINK = registerColor("HotPink", Color.decode("0xFF69B4"));
	public static final Color CORAL = registerColor("Coral", Color.decode("0xFF7F50"));
	public static final Color DARK_ORANGE = registerColor("DarkOrange", Color.decode("0xFF8C00"));
	public static final Color LIGHT_SALMON = registerColor("LightSalmon", Color.decode("0xFFA07A"));
	public static final Color ORANGE = registerColor("Orange", Color.decode("0xFFA500"));
	public static final Color LIGHT_PINK = registerColor("LightPink", Color.decode("0xFFB6C1"));
	public static final Color PINK = registerColor("Pink", Color.decode("0xFFC0CB"));
	public static final Color GOLD = registerColor("Gold", Color.decode("0xFFD700"));
	public static final Color PEACH_PUFF = registerColor("PeachPuff", Color.decode("0xFFDAB9"));
	public static final Color NAVAJO_WHITE = registerColor("NavajoWhite", Color.decode("0xFFDEAD"));
	public static final Color MOCCASIN = registerColor("Moccasin", Color.decode("0xFFE4B5"));
	public static final Color BISQUE = registerColor("Bisque", Color.decode("0xFFE4C4"));
	public static final Color MISTY_ROSE = registerColor("MistyRose", Color.decode("0xFFE4E1"));
	public static final Color BLANCHED_ALMOND = registerColor("BlanchedAlmond", Color.decode("0xFFEBCD"));
	public static final Color PAPAYA_WHIP = registerColor("PapayaWhip", Color.decode("0xFFEFD5"));
	public static final Color LAVENDER_BLUSH = registerColor("LavenderBlush", Color.decode("0xFFF0F5"));
	public static final Color SEASHELL = registerColor("SeaShell", Color.decode("0xFFF5EE"));
	public static final Color CORNSILK = registerColor("Cornsilk", Color.decode("0xFFF8DC"));
	public static final Color LEMON_CHIFFON = registerColor("LemonChiffon", Color.decode("0xFFFACD"));
	public static final Color FLORAL_WHITE = registerColor("FloralWhite", Color.decode("0xFFFAF0"));
	public static final Color SNOW = registerColor("Snow", Color.decode("0xFFFAFA"));
	public static final Color YELLOW = registerColor("Yellow", Color.decode("0xFFFF00"));
	public static final Color LIGHT_YELLOW = registerColor("LightYellow", Color.decode("0xFFFFE0"));
	public static final Color IVORY = registerColor("Ivory", Color.decode("0xFFFFF0"));
	public static final Color WHITE = registerColor("White", Color.decode("0xFFFFFF"));
	public static final Color MEDIUM_SPRING_GREEN = registerColor("MediumSpringGreen", Color.decode("0x00FA9A"));
	public static final Color LIGHT_GOLDENROD = registerColor("LightGoldenRodYellow", Color.decode("0xFAFAD2"));
	public static final Color MEDIUM_VIOLET_RED = registerColor("MediumVioletRed", Color.decode("0xC71585"));
	public static final Color LIGHT_STEEL_BLUE = registerColor("LightSteelBlue", Color.decode("0xB0C4DE"));
	public static final Color LIGHT_SLATE_GRAY = registerColor("LightSlateGray", Color.decode("0x778899"));
	public static final Color MEDIUM_SLATE_BLUE = registerColor("MediumSlateBlue", Color.decode("0x7B68EE"));
	public static final Color MEDIUM_SEA_GREEN = registerColor("MediumSeaGreen", Color.decode("0x3CB371"));
	public static final Color MEDUM_AQUA_MARINE = registerColor("MediumAquaMarine", Color.decode("0x66CDAA"));
	public static final Color MEDIUM_TURQOISE = registerColor("MediumTurquoise", Color.decode("0x48D1CC"));
	public static final Color DARK_OLIVE_GREEN = registerColor("DarkOliveGreen", Color.decode("0x556B2F"));
	public static final Color CORNFLOWER_BLUE = registerColor("CornflowerBlue", Color.decode("0x6495ED"));
	//@formatter:on

	// cannot instantiate nor extend
	private WebColors() {
	}

	/**
	 * Tries to find a color for the given String value. The String value can either be
	 * a hex string (see {@link Color#decode(String)}) or a web color name as defined
	 * above
	 *
	 * @param value the string value to interpret as a color
	 * @param defaultColor a default color to return if the string can't be converted to a color
	 * @return a color for the given string value or the default color if the string can't be translated
	 */
	public static Color getColorOrDefault(String value, Color defaultColor) {
		Color color = getColor(value);
		return color != null ? color : defaultColor;
	}

	/**
	 * Converts a color to a string value. If there is a defined color for the given color value,
	 * the color name will be returned. Otherwise, it will return a hex string for the color as
	 * follows. If the color has an non-opaque alpha value, it will be of the form #rrggbb. If
	 * it has an alpha value,then the format will be #rrggbbaa.
	 *
	 * @param color the color to convert to a string.
	 * @return the string representation for the given color.
	 */
	public static String toString(Color color) {
		return toString(color, true);
	}

	/**
	 * Converts a color to a string value.  If the color is a WebColor and the useNameIfPossible
	 * is true, the name of the color will be returned. OOtherwise, it will return a hex string for the color as
	 * follows. If the color has an non-opaque alpha value, it will be of the form #rrggbb. If
	 * it has an alpha value ,then the format will be #rrggbbaa.
	 *
	 * @param color the color to convert to a string.
	 * @param useNameIfPossible if true, the name of the color will be returned if the color is
	 * a WebColor
	 * @return the string representation for the given color.
	 */
	public static String toString(Color color, boolean useNameIfPossible) {
		if (useNameIfPossible) {
			String name = colorToNameMap.get(color.getRGB());
			if (name != null) {
				return name;
			}
		}
		return toHexString(color);
	}

	public static String toColorName(Color color) {
		return colorToNameMap.get(color.getRGB());
	}

	/**
	 * Returns the hex value string for the given color 
	 * @param color the color
	 * @return the string
	 */
	public static String toHexString(Color color) {
		int rgb = color.getRGB() & 0xffffff; //mask off any alpha value
		int alpha = color.getAlpha();
		if (alpha != 0xff) {
			return String.format("#%06x%02x", rgb, alpha);
		}
		return String.format("#%06x", rgb);
	}

	/**
	 * Returns the rgb value string for the given color
	 * @param color the color
	 * @return the string
	 */
	public static String toRgbString(Color color) {
		int r = color.getRed();
		int g = color.getGreen();
		int b = color.getBlue();
		int a = color.getAlpha();

		String rgb = r + "," + g + "," + b;

		if (a != 0xff) {
			return "rgba(" + rgb + "," + a + ")";
		}
		return "rgb(" + rgb + ")";
	}

	/**
	 * Returns the WebColor name for the given color. Returns null if the color is not a WebColor
	 * @param color the color to lookup a WebColor name.
	 * @return the WebColor name for the given color. Returns null if the color is not a WebColor
	 */
	public static String toWebColorName(Color color) {
		return colorToNameMap.get(color.getRGB());
	}

	private static Color registerColor(String name, Color color) {
		nameToColorMap.put(name.toLowerCase(), color);
		colorToNameMap.put(color.getRGB(), name);
		return color;
	}

	/**
	 * Attempts to convert the given string into a color in a most flexible manner. It first checks
	 * if the given string matches the name of a known web color as defined above. If so it
	 * returns that color. Otherwise it tries to parse the string in any one of the following
	 * formats:
	 * <pre>
	 * #rrggbb
	 * #rrggbbaa
	 * 0xrrggbb
	 * 0xrrggbbaa
	 * rgb(red, green, blue)
	 * rgba(red, green, alpha)
	 * </pre>
	 * In the hex digit formats, the hex digits "rr", "gg", "bb", "aa" represent the values for red,
	 * green, blue, and alpha, respectively. In the "rgb" and "rgba" formats the red, green, and
	 * blue values are all integers between 0-255, while the alpha value is a float value from 0.0 to
	 * 1.0.
	 * <BR><BR>
	 * @param colorString the color name
	 * @return a color for the given string or null
	 */
	public static Color getColor(String colorString) {
		String value = colorString.trim().toLowerCase();
		Color color = nameToColorMap.get(value.toLowerCase());
		if (color != null) {
			return color;
		}

		return parseColor(value);
	}

	private static Color parseColor(String colorString) {
		if (colorString.startsWith("#") || colorString.startsWith("0x")) {
			return parseHexColor(colorString);
		}

		if (colorString.startsWith("rgba(")) {
			return parseRgbaColor(colorString);
		}
		return parseRgbColor(colorString);
	}

	/**
	 * Parses the given string into a color. The string must be in one of the following formats:
	 * <pre>
	 * #rrggbb
	 * #rrggbbaa
	 * 0xrrggbb
	 * 0xrrggbbaa
	 * </pre>
	 *
	 * Each of the hex digits "rr", "gg", "bb", and "aa" specify the red, green, blue, and alpha
	 * values respectively.
	 * <br><br>
	 *
	 * @param hexString the string to parse into a color.
	 * @return the parsed Color or null if the input string was invalid.
	 */
	private static Color parseHexColor(String hexString) {
		String value = hexString.trim();
		if (value.startsWith("#")) {
			value = value.substring(1);
		}
		else if (value.startsWith("0x")) {
			value = value.substring(2);
		}
		else {
			return null;
		}

		if (value.length() != 8 && value.length() != 6) {
			return null;
		}

		boolean hasAlpha = value.length() == 8;
		if (hasAlpha) {
			// alpha value is the last 2 digits, Color wants alpha to be in upper bits so re-arrange
			value = value.substring(6) + value.substring(0, 6);
		}

		try {
			long colorValue = Long.parseLong(value, 16);
			return new Color((int) colorValue, hasAlpha);
		}
		catch (NumberFormatException e) {
			return null;
		}
	}

	/**
	 * Parses the given string into a color. The string must be in one of the following formats:
	 * <pre>
	 * rgb(red, green, blue)
	 * rgb(red, green, blue, alpha)
	 * </pre>
	 * Each of the values "red", "green", "blue", and "alpha" must be integer values between 0-255
	 * <br><br>
	 * @param rgbString the string to parse into a color.
	 * @return the parsed Color or null if the input string was invalid.
	 */
	private static Color parseRgbColor(String rgbString) {
		String value = rgbString.trim().replaceAll(" ", "");
		if (value.startsWith("rgb(") && value.endsWith(")")) {
			value = value.substring(4, value.length() - 1);
		}

		// strip off to comma separated values		
		String[] split = value.split(",");
		if (split.length != 3) {
			return null;
		}
		try {
			int red = Integer.parseInt(split[0]);
			int green = Integer.parseInt(split[1]);
			int blue = Integer.parseInt(split[2]);
			return new Color(red, green, blue);
		}
		catch (IllegalArgumentException e) {
			return null;
		}
	}

	private static Color parseRgbaColor(String rgbaString) {
		String value = rgbaString.replaceAll(" ", "");
		if (value.startsWith("rgba(") && value.endsWith(")")) {
			value = value.substring(5, value.length() - 1);
		}

		// strip off to comma separated values		
		value = value.replaceAll(" ", "");
		String[] split = value.split(",");
		if (split.length != 4) {
			return null;
		}
		try {
			int red = Integer.parseInt(split[0]);
			int green = Integer.parseInt(split[1]);
			int blue = Integer.parseInt(split[2]);
			int alpha = parseAlpha(split[3]);
			return new Color(red, green, blue, alpha);
		}
		catch (IllegalArgumentException e) {
			return null;
		}
	}

	private static int parseAlpha(String string) {
		// alpha strings can either be a float between 0.0 and 1.0 or an integer from 0 to 255.
		// if it is a float, treat that value as a percentage of the 255 max value
		// if it is an int, don't allow the value to be bigger than 255.
		if (string.contains(".")) {
			float value = Float.parseFloat(string);
			return (int) (value * 0xff + 0.5) & 0xff;  // convert to value in range (0-255)
		}
		return Integer.parseInt(string) & 0xff;	// truncate any bits that would make it bigger than 255
	}
}
