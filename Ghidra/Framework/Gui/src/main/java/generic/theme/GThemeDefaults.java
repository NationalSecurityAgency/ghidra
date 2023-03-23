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

/** TODO doc how clients should use this in their code, with
 *
 *
 *  Colors.BACKGROUND
 *  Colors.Java.BORDER
 */
public class GThemeDefaults {
	public static class Ids {

		public static class Fonts {
			public static final String MONOSPACED = "font.monospaced";
		}
	}

	/**
	 * Colors mapped to system values
	 */
	public static class Colors {
		//@formatter:off

		// standard color concepts defined by LookAndFeel
		public static final GColor BG_CONTROL = new GColor(BG_CONTROL_ID);
		public static final GColor BG_VIEW = new GColor(BG_VIEW_ID);
		public static final GColor BG_TOOLTIP = new GColor(BG_TOOLTIP_ID);
		public static final GColor BG_VIEW_SELECTED = new GColor(BG_VIEW_SELECTED_ID);
		public static final GColor BG_BORDER = new GColor(BG_BORDER_ID);

		public static final GColor FG_CONTROL = new GColor(FG_CONTROL_ID);
		public static final GColor FG_VIEW = new GColor(FG_VIEW_ID);
		public static final GColor FG_TOOLTIP = new GColor(FG_TOOLTIP_ID);
		public static final GColor FG_VIEW_SELECTED = new GColor(FG_VIEW_SELECTED_ID);
		public static final GColor FG_DISABLED = new GColor(FG_DISABLED_ID);

		// generic color concepts
		public static final GColor BACKGROUND = new GColor("color.bg");
		public static final GColor CURSOR = new GColor("color.cursor.focused");
		public static final GColor DISABLED = new GColor("color.palette.disabled");
		public static final GColor ERROR = new GColor("color.fg.error");
		public static final GColor FOREGROUND = new GColor("color.fg");
		public static final GColor FOREGROUND_DISABLED = new GColor("color.fg.disabled");
		//@formatter:on

		public static class Java {
			public static final GColor BORDER = BG_BORDER;
		}

		public static class Tables {
			//@formatter:off
			public static final GColor FG_ERROR_SELECTED = new GColor("color.fg.error.table.selected");
			public static final GColor FG_ERROR_UNSELECTED = new GColor("color.fg.error.table.unselected");
			public static final GColor FG_UNEDITABLE_SELECTED = new GColor("color.fg.table.uneditable.selected");
			public static final GColor FG_UNEDITABLE_UNSELECTED = new GColor("color.fg.table.uneditable.unselected");
			public static final GColor FG_UNSELECTED = new GColor("color.fg.table");
			public static final GColor FG_SELECTED = new GColor("color.fg.table.unselected");
			//@formatter:on
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
		 * Generic palette colors, using color names, that may be changed along with the theme
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
			 * For a list of supported palette IDs, see {@code docking.palette.theme.properties}.
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
