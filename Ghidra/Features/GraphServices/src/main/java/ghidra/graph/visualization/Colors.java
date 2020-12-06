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
package ghidra.graph.visualization;

import static java.util.Map.*;

import java.awt.Color;
import java.awt.Paint;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.service.graph.Attributed;

/**
 * support for coercing colors from attributes or color names
 */
public abstract class Colors {

	private static final Pattern HEX_PATTERN = Pattern.compile("(0x|#)[0-9A-Fa-f]{6}");

    // cannot instantiate nor extend
    private Colors() {
    }

    /**
     * a map of well-known 'web' color names to colors
     */
    static Map<String, Color> WEB_COLOR_MAP = Map.ofEntries(
            entry("Black", Color.decode("0x000000")),
            entry("Navy", Color.decode("0x000080")),
            entry("DarkBlue", Color.decode("0x00008B")),
            entry("MediumBlue", Color.decode("0x0000CD")),
            entry("Blue", Color.decode("0x0000FF")),
            entry("DarkGreen", Color.decode("0x006400")),
            entry("Green", Color.decode("0x008000")),
            entry("Teal", Color.decode("0x008080")),
            entry("DarkCyan", Color.decode("0x008B8B")),
            entry("DeepSkyBlue", Color.decode("0x00BFFF")),
            entry("DarkTurquoise", Color.decode("0x00CED1")),
            entry("MediumSpringGreen", Color.decode("0x00FA9A")),
            entry("Lime", Color.decode("0x00FF00")),
            entry("SpringGreen", Color.decode("0x00FF7F")),
            entry("Aqua", Color.decode("0x00FFFF")),
            entry("Cyan", Color.decode("0x00FFFF")),
            entry("MidnightBlue", Color.decode("0x191970")),
            entry("DodgerBlue", Color.decode("0x1E90FF")),
            entry("LightSeaGreen", Color.decode("0x20B2AA")),
            entry("ForestGreen", Color.decode("0x228B22")),
            entry("SeaGreen", Color.decode("0x2E8B57")),
            entry("DarkSlateGray", Color.decode("0x2F4F4F")),
            entry("DarkSlateGrey", Color.decode("0x2F4F4F")),
            entry("LimeGreen", Color.decode("0x32CD32")),
            entry("MediumSeaGreen", Color.decode("0x3CB371")),
            entry("Turquoise", Color.decode("0x40E0D0")),
            entry("RoyalBlue", Color.decode("0x4169E1")),
            entry("SteelBlue", Color.decode("0x4682B4")),
            entry("DarkSlateBlue", Color.decode("0x483D8B")),
            entry("MediumTurquoise", Color.decode("0x48D1CC")),
            entry("Indigo", Color.decode("0x4B0082")),
            entry("DarkOliveGreen", Color.decode("0x556B2F")),
            entry("CadetBlue", Color.decode("0x5F9EA0")),
            entry("CornflowerBlue", Color.decode("0x6495ED")),
            entry("RebeccaPurple", Color.decode("0x663399")),
            entry("MediumAquaMarine", Color.decode("0x66CDAA")),
            entry("DimGray", Color.decode("0x696969")),
            entry("DimGrey", Color.decode("0x696969")),
            entry("SlateBlue", Color.decode("0x6A5ACD")),
            entry("OliveDrab", Color.decode("0x6B8E23")),
            entry("SlateGray", Color.decode("0x708090")),
            entry("SlateGrey", Color.decode("0x708090")),
            entry("LightSlateGray", Color.decode("0x778899")),
            entry("LightSlateGrey", Color.decode("0x778899")),
            entry("MediumSlateBlue", Color.decode("0x7B68EE")),
            entry("LawnGreen", Color.decode("0x7CFC00")),
            entry("Chartreuse", Color.decode("0x7FFF00")),
            entry("Aquamarine", Color.decode("0x7FFFD4")),
            entry("Maroon", Color.decode("0x800000")),
            entry("Purple", Color.decode("0x800080")),
            entry("Olive", Color.decode("0x808000")),
            entry("Gray", Color.decode("0x808080")),
            entry("Grey", Color.decode("0x808080")),
            entry("SkyBlue", Color.decode("0x87CEEB")),
            entry("LightSkyBlue", Color.decode("0x87CEFA")),
            entry("BlueViolet", Color.decode("0x8A2BE2")),
            entry("DarkRed", Color.decode("0x8B0000")),
            entry("DarkMagenta", Color.decode("0x8B008B")),
            entry("SaddleBrown", Color.decode("0x8B4513")),
            entry("DarkSeaGreen", Color.decode("0x8FBC8F")),
            entry("LightGreen", Color.decode("0x90EE90")),
            entry("MediumPurple", Color.decode("0x9370DB")),
            entry("DarkViolet", Color.decode("0x9400D3")),
            entry("PaleGreen", Color.decode("0x98FB98")),
            entry("DarkOrchid", Color.decode("0x9932CC")),
            entry("YellowGreen", Color.decode("0x9ACD32")),
            entry("Sienna", Color.decode("0xA0522D")),
            entry("Brown", Color.decode("0xA52A2A")),
            entry("DarkGray", Color.decode("0xA9A9A9")),
            entry("DarkGrey", Color.decode("0xA9A9A9")),
            entry("LightBlue", Color.decode("0xADD8E6")),
            entry("GreenYellow", Color.decode("0xADFF2F")),
            entry("PaleTurquoise", Color.decode("0xAFEEEE")),
            entry("LightSteelBlue", Color.decode("0xB0C4DE")),
            entry("PowderBlue", Color.decode("0xB0E0E6")),
            entry("FireBrick", Color.decode("0xB22222")),
            entry("DarkGoldenRod", Color.decode("0xB8860B")),
            entry("MediumOrchid", Color.decode("0xBA55D3")),
            entry("RosyBrown", Color.decode("0xBC8F8F")),
            entry("DarkKhaki", Color.decode("0xBDB76B")),
            entry("Silver", Color.decode("0xC0C0C0")),
            entry("MediumVioletRed", Color.decode("0xC71585")),
            entry("IndianRed", Color.decode("0xCD5C5C")),
            entry("Peru", Color.decode("0xCD853F")),
            entry("Chocolate", Color.decode("0xD2691E")),
            entry("Tan", Color.decode("0xD2B48C")),
            entry("LightGray", Color.decode("0xD3D3D3")),
            entry("LightGrey", Color.decode("0xD3D3D3")),
            entry("Thistle", Color.decode("0xD8BFD8")),
            entry("Orchid", Color.decode("0xDA70D6")),
            entry("GoldenRod", Color.decode("0xDAA520")),
            entry("PaleVioletRed", Color.decode("0xDB7093")),
            entry("Crimson", Color.decode("0xDC143C")),
            entry("Gainsboro", Color.decode("0xDCDCDC")),
            entry("Plum", Color.decode("0xDDA0DD")),
            entry("BurlyWood", Color.decode("0xDEB887")),
            entry("LightCyan", Color.decode("0xE0FFFF")),
            entry("Lavender", Color.decode("0xE6E6FA")),
            entry("DarkSalmon", Color.decode("0xE9967A")),
            entry("Violet", Color.decode("0xEE82EE")),
            entry("PaleGoldenRod", Color.decode("0xEEE8AA")),
            entry("LightCoral", Color.decode("0xF08080")),
            entry("Khaki", Color.decode("0xF0E68C")),
            entry("AliceBlue", Color.decode("0xF0F8FF")),
            entry("HoneyDew", Color.decode("0xF0FFF0")),
            entry("Azure", Color.decode("0xF0FFFF")),
            entry("SandyBrown", Color.decode("0xF4A460")),
            entry("Wheat", Color.decode("0xF5DEB3")),
            entry("Beige", Color.decode("0xF5F5DC")),
            entry("WhiteSmoke", Color.decode("0xF5F5F5")),
            entry("MintCream", Color.decode("0xF5FFFA")),
            entry("GhostWhite", Color.decode("0xF8F8FF")),
            entry("Salmon", Color.decode("0xFA8072")),
            entry("AntiqueWhite", Color.decode("0xFAEBD7")),
            entry("Linen", Color.decode("0xFAF0E6")),
            entry("LightGoldenRodYellow", Color.decode("0xFAFAD2")),
            entry("OldLace", Color.decode("0xFDF5E6")),
            entry("Red", Color.decode("0xFF0000")),
            entry("Fuchsia", Color.decode("0xFF00FF")),
            entry("Magenta", Color.decode("0xFF00FF")),
            entry("DeepPink", Color.decode("0xFF1493")),
            entry("OrangeRed", Color.decode("0xFF4500")),
            entry("Tomato", Color.decode("0xFF6347")),
            entry("HotPink", Color.decode("0xFF69B4")),
            entry("Coral", Color.decode("0xFF7F50")),
            entry("DarkOrange", Color.decode("0xFF8C00")),
            entry("LightSalmon", Color.decode("0xFFA07A")),
            entry("Orange", Color.decode("0xFFA500")),
            entry("LightPink", Color.decode("0xFFB6C1")),
            entry("Pink", Color.decode("0xFFC0CB")),
            entry("Gold", Color.decode("0xFFD700")),
            entry("PeachPuff", Color.decode("0xFFDAB9")),
            entry("NavajoWhite", Color.decode("0xFFDEAD")),
            entry("Moccasin", Color.decode("0xFFE4B5")),
            entry("Bisque", Color.decode("0xFFE4C4")),
            entry("MistyRose", Color.decode("0xFFE4E1")),
            entry("BlanchedAlmond", Color.decode("0xFFEBCD")),
            entry("PapayaWhip", Color.decode("0xFFEFD5")),
            entry("LavenderBlush", Color.decode("0xFFF0F5")),
            entry("SeaShell", Color.decode("0xFFF5EE")),
            entry("Cornsilk", Color.decode("0xFFF8DC")),
            entry("LemonChiffon", Color.decode("0xFFFACD")),
            entry("FloralWhite", Color.decode("0xFFFAF0")),
            entry("Snow", Color.decode("0xFFFAFA")),
            entry("Yellow", Color.decode("0xFFFF00")),
            entry("LightYellow", Color.decode("0xFFFFE0")),
            entry("Ivory", Color.decode("0xFFFFF0")),
            entry("White", Color.decode("0xFFFFFF"))
    );

    /**
     * a blue that is not as dark as {@code Color.blue}
     */
    private static Color blue = new Color(100, 100, 255);

	/**
	 * a yellow that is darker than {@code Color.yellow}
	 */
	private static Color darkerYellow = new Color(225, 225, 0);

    /**
     * these are vertex or edge types that have defined colors
     * (the keys are the property values for the vertex/edge keys:
     * VertexType and EdgeType)
     */
    public static Map<String,Paint> VERTEX_TYPE_TO_COLOR_MAP =
            Map.ofEntries(
                    entry("Body", blue),
                    entry("Entry", WEB_COLOR_MAP.get("DarkOrange")),
                    entry("Exit", Color.magenta),
                    entry("Switch", Color.cyan),
                    entry("Bad",Color.red),
                    entry("Entry-Nexus",Color.white),
                    entry("External",Color.green),
                    entry("Folder",WEB_COLOR_MAP.get("DarkOrange")),
                    entry("Fragment",WEB_COLOR_MAP.get("Purple")),
                    entry("Data",Color.pink)
            );

    /**
     * these are vertex or edge types that have defined colors
     * (the keys are the property values for the vertex/edge keys:
     * VertexType and EdgeType)
     */
    public static Map<String,Paint> EDGE_TYPE_TO_COLOR_MAP =
            Map.ofEntries(

                    entry("Entry", Color.gray), // white??
                    entry("Fall-Through", Color.blue),
                    entry("Conditional-Call", WEB_COLOR_MAP.get("DarkOrange")),
                    entry("Unconditional-Call", WEB_COLOR_MAP.get("DarkOrange")),
                    entry("Computed",Color.cyan),
                    entry("Indirection",Color.pink),
                    entry("Unconditional-Jump", Color.green),
                    entry("Conditional-Jump", darkerYellow),
                    entry("Terminator", WEB_COLOR_MAP.get("Purple")),
                    entry("Conditional-Return", WEB_COLOR_MAP.get("Purple"))
            );


	/**
	 * Determine a color for the given {@link Attributed} object.
	 * <P>
	 * The attributed object can be an vertex or an edge. This method examines the attributes
	 * and tries to find an attribute that has a color mapping.  Otherwise it returns a default
	 * color
	 * @param attributed the vertex or edge for which to determine a color
	 * @return the color to paint the given Attributed
	 */
	public static Paint getColor(Attributed attributed) {
		Map<String, String> map = attributed.getAttributeMap();
        // if there is a 'VertexType' attribute key, use its value to choose a predefined color
		if (map.containsKey("VertexType")) {
			String typeValue = map.get("VertexType");
            return VERTEX_TYPE_TO_COLOR_MAP.getOrDefault(typeValue, Color.blue);
         }
        // if there is an 'EdgeType' attribute key, use its value to choose a predefined color
		if (map.containsKey("EdgeType")) {
			String typeValue = map.get("EdgeType");
            return EDGE_TYPE_TO_COLOR_MAP.getOrDefault(typeValue, Color.green);
        }
        // if there is a 'Color' attribute key, use its value (either a color name or an RGB hex string)
        // to choose a color
		if (map.containsKey("Color")) {
			String colorName = map.get("Color");
            if (WEB_COLOR_MAP.containsKey(colorName)) {
                return WEB_COLOR_MAP.get(colorName);
			}
			// if the value matches an RGB hex string, turn that into a color
			Color c = getHexColor(colorName);
			if (c != null) {
				return c;
			}
        }
        // default value when nothing else matches
        return Color.green;
    }

	public static Color getHexColor(String hexString) {
		Matcher matcher = HEX_PATTERN.matcher(hexString);
		if (matcher.matches()) {
			return Color.decode(hexString);
		}
		return null;
	}
}
