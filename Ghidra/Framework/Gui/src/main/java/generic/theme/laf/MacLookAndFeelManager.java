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
package generic.theme.laf;

import java.awt.*;

import javax.swing.BorderFactory;
import javax.swing.UIDefaults;
import javax.swing.border.*;

import generic.theme.*;

/**
 * Manages installing and updating the Mac Aqua look and feel.  This is where we make look and
 * feel changes specific to the Mac Aqua look and feel, so that it works with the theming feature.
 */
public class MacLookAndFeelManager extends LookAndFeelManager {

	public MacLookAndFeelManager(ApplicationThemeManager themeManager) {
		super(LafType.MAC, themeManager);
	}

	@Override
	protected UiDefaultsMapper createUiDefaultsMapper(UIDefaults defaults) {
		return new MacUiDefaultsMapper(defaults);
	}

	private static class MacUiDefaultsMapper extends UiDefaultsMapper {

		protected MacUiDefaultsMapper(UIDefaults defaults) {
			super(defaults);
		}

		/**
		 * Fix incorrectly defined default color values. These colors were not used before, but 
		 * they are now that we override the Mac Aqua Look and Feel painters.
		 * @return the extracted resource properties from the Mac Aqua Look and Feel with overridden
		 * values for the menu selection colors
		 */
		@Override
		protected GThemeValueMap extractColorFontAndIconValuesFromDefaults() {

			// This is the default menu selection color used by Mac Aqua Look and Feel menu
			// painters. This color is different than the color defined in the UI manager.  To 
			// keep the colors consistent with the default behavior, we need to override the value  
			// in the UI manager with this color.
			Color menuSelectionColor = new Color(0, 103, 214);

			GThemeValueMap map = super.extractColorFontAndIconValuesFromDefaults();
			map.addColor(new ColorValue("Menu.selectionBackground", menuSelectionColor));
			map.addColor(new ColorValue("MenuBar.selectionBackground", menuSelectionColor));
			map.addColor(new ColorValue("MenuItem.selectionBackground", menuSelectionColor));
			map.addColor(new ColorValue("PopupMenu.selectionBackground", menuSelectionColor));
			map.addColor(new ColorValue("ComboBox.selectionBackground", menuSelectionColor));
			map.addColor(
				new ColorValue("RadioButtonMenuItem.selectionBackground", menuSelectionColor));
			map.addColor(
				new ColorValue("CheckBoxMenuItem.selectionBackground", menuSelectionColor));

			/*
			 	When using the 'system' appearance on a Mac, with the native OS using dark mode, 
			 	tab text becomes hard to read. The colors we use here to fix the issue are the Max 
			 	OSX Laf colors used when not using the 'system' appearance.
			 */
			if (isNativeOrDarkMode()) {

				Color color = new Color(0, 0, 0, 216);
				map.addColor(new ColorValue("TabbedPane.selectedTabTitleNormalColor", color));
				map.addColor(new ColorValue("TabbedPane.selectedTabTitlePressedColor", color));

				// In light mode, the selected tab has a lighter background. In dark mode, the 
				// background is the same. Update the foreground to differentiate the selected from
				// non-selected tabs.
				color = new Color(0, 0, 0, 100);
				map.addColor(new ColorValue("TabbedPane.nonSelectedTabTitleNormalColor", color));
			}

			return map;
		}

		/**
		 * Overridden to change the Mac menu painters.  The default painters do not honor 
		 * the color values set by the Look and Feel. We override the painters by using
		 * either a Java border or our own painters that will use the theme colors.
		 * @param currentValues the values to install into the LookAndFeel UiDefaults map
		 */
		@Override
		public void installValuesIntoUIDefaults(GThemeValueMap currentValues) {
			super.installValuesIntoUIDefaults(currentValues);

			defaults.put("MenuBar.backgroundPainter", BorderFactory.createEmptyBorder());

			defaults.put("MenuBar.selectedBackgroundPainter",
				new BackgroundBorder(new GColor("laf.color.MenuBar.selectionBackground")));
			defaults.put("MenuItem.selectedBackgroundPainter",
				new BackgroundBorder(new GColor("laf.color.MenuItem.selectionBackground")));

			/*
			 	When using the 'system' appearance on a Mac, with the native OS using dark mode, 
			 	the table headers become black and hard to read.  The color comes from the AquaUI
			 	'painter' system, which uses a border painter to control the background.  This 
			 	bypasses our theming.  We work around that issue here by using a simple line border,
			 	which allows our renderer to paint its background color.
			 */
			if (isNativeOrDarkMode()) {

				Border innerBorder = BorderFactory.createEmptyBorder(1, 1, 1, 1);
				Border outerBorder =
					BorderFactory.createLineBorder(new GColor("system.color.bg.border"));
				CompoundBorder compoundBorder =
					BorderFactory.createCompoundBorder(outerBorder, innerBorder);
				defaults.put("TableHeader.cellBorder", compoundBorder);
			}

		}
	}

	private static boolean isNativeOrDarkMode() {
		// The user may not be in dark mode when 'system' is set, but the way we change the colors
		// is acceptable in light mode.
		String appearance = System.getProperty("apple.awt.application.appearance", "");
		return "system".equals(appearance) || "NSAppearanceNameDarkAqua".equals(appearance);
	}

	/**
	 * Background painter for selected menu items. 
	 */
	private static class BackgroundBorder extends EmptyBorder {
		private GColor color;

		public BackgroundBorder(GColor color) {
			super(0, 0, 0, 0);
			this.color = color;
		}

		@Override
		public void paintBorder(Component c, Graphics g, int x, int y, int width, int height) {
			g.setColor(color);
			g.fillRect(x, y, width, height);
		}
	}
}
