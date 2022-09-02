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

import java.awt.Color;

/** TODO doc how clients should use this in their code, with
 * 
 *  
 *  Colors.BACKGROUND
 *  Colors.Java.BORDER
 */
public class GThemeDefaults {
	public static final String STANDARD_DEFAULTS = "Standard Defaults";  // core defaults map name
	public static final String DARK = "Dark";          // defaults map name for dark based themes

	public static class Ids {

		public static class Java {
			public static final String BORDER = "system.color.border"; // TODO
		}
	}

	/**
	 * Colors mapped to system values
	 */
	public static class Colors {

		// generic color concepts
		//@formatter:off
		public static final GColor BACKGROUND = new GColor("color.bg");
		public static final GColor CURSOR = new GColor("color.cursor.focused");
		public static final GColor DISABLED = new GColor("color.palette.disabled");
		public static final GColor ERROR = new GColor("color.fg.error");
		public static final GColor FOREGROUND = new GColor("color.fg");
		public static final GColor FOREGROUND_DISABLED = new GColor("color.fg.disabled");		
		public static final GColor TOOLTIP_BACKGROUND = new GColor("color.bg.tooltip");
		//@formatter:on

		public static class Java {
			public static final GColor BORDER = new GColor(Ids.Java.BORDER);
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

		public static class Dialogs {
			//@formatter:off
			public static final GColor FG_MESSAGE_NORMAL = new GColor("color.fg.dialog.status.normal");
			public static final GColor FG_MESSAGE_ERROR = new GColor("color.fg.dialog.status.error");
			//@formatter:on

		}

		/**
		 * Generic palette colors, using color names, that may be changed along with the theme
		 */
		public static class Palette {

			/** Transparent color */
			public static final Color NO_COLOR = palette("nocolor");

			public static final GColor BLACK = palette("black");
			public static final GColor BLUE = palette("blue");
			public static final GColor CYAN = palette("cyan");
			public static final GColor GOLD = palette("gold");
			public static final GColor GRAY = palette("gray");
			public static final GColor GREEN = palette("green");
			public static final GColor LIGHT_GRAY = palette("lightgray");
			public static final GColor LIME = palette("lime");
			public static final GColor MAGENTA = palette("magenta");
			public static final GColor ORANGE = palette("orange");
			public static final GColor PINK = palette("pink");
			public static final GColor RED = palette("red");
			public static final GColor WHITE = palette("white");
			public static final GColor YELLOW = palette("yellow");

			private static GColor palette(String name) {
				return new GColor("color.palette." + name);
			}
		}

	}

}
