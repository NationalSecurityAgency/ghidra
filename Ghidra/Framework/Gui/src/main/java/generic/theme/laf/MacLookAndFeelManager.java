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
import javax.swing.border.EmptyBorder;

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
		}
	}

	/**
	 * Background painter for selected menu items. 
	 */
	private static class BackgroundBorder extends EmptyBorder {
		private GColor selectedMenuBacgroundColor;

		public BackgroundBorder(GColor color) {
			super(0, 0, 0, 0);
			this.selectedMenuBacgroundColor = color;
		}

		public void paintBorder(Component c, Graphics g, int x, int y, int width, int height) {
			g.setColor(selectedMenuBacgroundColor);
			g.fillRect(x, y, width, height);
		}
	}
}
