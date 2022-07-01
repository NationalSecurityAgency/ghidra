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
package docking.theme;

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
		public static final GColor TOOLTIP_BACKGROUND = new GColor("color.bg.tooltip");
		//@formatter:on

		public static class Java {
			public static final Color BORDER = new GColor(Ids.Java.BORDER);
		}

		/**
		 * Generic palette colors, using color names, that may be changed along with the theme
		 */
		public static class Palette {
			public static final Color NO_COLOR = new GColor("color.palette.nocolor");

			public static final Color BLACK = new GColor("color.palette.black");
			public static final Color CYAN = new GColor("color.palette.cyan");
			public static final Color RED = new GColor("color.palette.red");
			public static final Color WHITE = new GColor("color.palette.white");

		}

	}

}
