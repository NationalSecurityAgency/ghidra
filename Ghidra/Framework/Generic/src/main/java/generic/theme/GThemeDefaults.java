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

		public static final String COLOR_BG = "color.bg"; // TODO do we need this?; rename to use 'background'?

		public static class Java {
			public static final String BORDER = "Component.borderColor"; // TODO
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
			public static final GColor FG_ERROR_SELECTED =
				new GColor("color.fg.error.table.selected");
			public static final GColor FG_ERROR_UNSELECTED =
				new GColor("color.fg.error.table.unselected");

			public static final GColor FG_UNEDITABLE_SELECTED =
				new GColor("color.fg.table.uneditable.selected");
			public static final GColor FG_UNEDITABLE_UNSELECTED =
				new GColor("color.fg.table.uneditable.unselected");
		}

		public static class Dialogs {
			public static final GColor FG_MESSAGE_NORMAL =
				new GColor("color.fg.dialog.status.normal");
			public static final GColor FG_MESSAGE_ERROR =
				new GColor("color.fg.dialog.status.error");

		}

		/**
		 * Generic palette colors, using color names, that may be changed along with the theme
		 */
		public static class Palette {

			/** Transparent color */
			public static final Color NO_COLOR = new GColor("color.palette.nocolor");

			public static final GColor BLACK = new GColor("color.palette.black");
			public static final GColor BLUE = new GColor("color.palette.blue");
			public static final GColor CYAN = new GColor("color.palette.cyan");
			public static final GColor GOLD = new GColor("color.palette.gold");
			public static final GColor GRAY = new GColor("color.palette.gray");
			public static final GColor GREEN = new GColor("color.palette.green");
			public static final GColor LIGHT_GRAY = new GColor("color.palette.lightgray");
			public static final GColor LIME = new GColor("color.palette.lime");
			public static final GColor MAGENTA = new GColor("color.palette.magenta");
			public static final GColor ORANGE = new GColor("color.palette.orange");
			public static final GColor PINK = new GColor("color.palette.pink");
			public static final GColor RED = new GColor("color.palette.red");
			public static final GColor WHITE = new GColor("color.palette.white");
			public static final GColor YELLOW = new GColor("color.palette.yellow");

		}

	}

}
