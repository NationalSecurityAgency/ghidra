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

import static generic.theme.SystemThemeIds.*;

import java.awt.Color;

/**
 * This class contains many suitable default values for commonly used concepts.  See each static
 * class below.
 * <P>
 * The values in this class can be used where standard colors are desired.   For example, where
 * clients used to hard-code black for the font color:
 * <PRE>
 * <CODE>
 * JLabel label = new JLabel():
 * label.setColor(Color.BLACK);
 * </CODE>
 * </PRE>
 * Can instead be programmed to use the system's current theme font color instead:
 * <PRE>
 * <CODE>
 * import generic.theme.GThemeDefaults.Colors;
 *
 * ...
 *
 * JLabel label = new JLabel():
 * label.setColor(Colors.FOREGROUND);
 * </CODE>
 * </PRE>
 * Note that in the second example, you can use the shorthand version of the values in this class
 * as long as you import them correctly.  This means you do not have to use this form:
 * <PRE>
 * <CODE>
 * component.setColor(GThemeDefaults.Colors.FOREGROUND);
 * </CODE>
 * </PRE>
 *
 *
 *
 */
public class GThemeDefaults {

	public static class Ids {
		public static class Fonts {
			public static final String MONOSPACED = "font.monospaced";
		}
	}

	/**
	 * Colors mapped to common system widget concepts, such as foreground, background, border, etc.
	 */
	public static class Colors {
		//@formatter:off

		// generic color concepts
		public static final GColor BACKGROUND = new GColor("color.bg");
		public static final GColor FOREGROUND = new GColor("color.fg");
		public static final GColor FOREGROUND_DISABLED = new GColor("color.fg.disabled");
		public static final GColor CURSOR = new GColor("color.cursor.focused");
		public static final GColor ERROR = new GColor("color.fg.error");
		public static final GColor BORDER = new GColor(BG_BORDER_ID);
		//@formatter:on

		/**
		 * Color values to use for tables
		 */
		public static class Tables {
			//@formatter:off
			public static final GColor ERROR_SELECTED = new GColor("color.fg.error.table.selected");
			public static final GColor ERROR_UNSELECTED = new GColor("color.fg.error.table.unselected");
			public static final GColor UNEDITABLE_SELECTED = new GColor("color.fg.table.uneditable.selected");
			public static final GColor UNEDITABLE_UNSELECTED = new GColor("color.fg.table.uneditable.unselected");
			//@formatter:on
		}

		/**
		 * Color values to use with tooltips
		 */
		public static class Tooltips {
			@SuppressWarnings("hiding") // we know there is another 'BACKGROUND' field in this file
			public static final GColor BACKGROUND = new GColor(BG_TOOLTIP_ID);
			@SuppressWarnings("hiding") // we know there is another 'FOREGROUND' field in this file
			public static final GColor FOREGROUND = new GColor(FG_TOOLTIP_ID);
		}

		/**
		 * 'Messages' is primarily used by system dialogs to display status.  That the colors are
		 * used for foregrounds is implied.
		 */
		public static class Messages {
			//@formatter:off
			public static final GColor NORMAL = new GColor("color.fg.messages.normal");
			@SuppressWarnings("hiding") // we know there is another 'ERROR' field in this file
			public static final GColor ERROR = new GColor("color.fg.messages.error");
			public static final GColor HINT = new GColor("color.fg.messages.hint");
			public static final GColor WARNING = new GColor("color.fg.messages.warning");
			//@formatter:on

		}

		/**
		 * Generic palette colors, using color names, that may be changed along with the theme.
		 * These are not all defined palette colors, but some of the more commonly used colors.
		 */
		public static class Palette {

			/** Transparent color */
			public static final Color NO_COLOR = getColor("nocolor");

			public static final GColor BLACK = getColor("black");
			public static final GColor BLUE = getColor("blue");
			public static final GColor CYAN = getColor("cyan");
			public static final GColor DARK_GRAY = getColor("darkgray");
			public static final GColor GOLD = getColor("gold");
			public static final GColor GRAY = getColor("gray");
			public static final GColor GREEN = getColor("green");
			public static final GColor LAVENDER = getColor("lavender");
			public static final GColor LIGHT_GRAY = getColor("lightgray");
			public static final GColor LIME = getColor("lime");
			public static final GColor MAGENTA = getColor("magenta");
			public static final GColor MAROON = getColor("maroon");
			public static final GColor ORANGE = getColor("orange");
			public static final GColor PINK = getColor("pink");
			public static final GColor PURPLE = getColor("purple");
			public static final GColor RED = getColor("red");
			public static final GColor SILVER = getColor("silver");
			public static final GColor WHITE = getColor("white");
			public static final GColor YELLOW = getColor("yellow");

			/**
			 * Returns a new {@link GColor} for the given palette name.
			 * <p>
			 * For a list of supported palette IDs, see {@code gui.palette.theme.properties}.
			 * <p>
			 * It is preferred to use the static colors defined in {@link Palette} when possible, as
			 * it prevents excess object creation.  This method should be used when the desired
			 * palette color is not in that list.  Further, this method should only be called once
			 * per use, such as when initializing a constant value.
			 *
			 * @param name the palette entry name
			 * @return the GColor
			 */
			public static GColor getColor(String name) {
				return new GColor("color.palette." + name);
			}
		}
	}
}
