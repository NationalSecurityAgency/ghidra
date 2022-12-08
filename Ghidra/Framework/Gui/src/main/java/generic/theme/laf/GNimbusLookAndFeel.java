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

import java.awt.Color;
import java.awt.Font;
import java.util.List;

import javax.swing.*;
import javax.swing.plaf.FontUIResource;
import javax.swing.plaf.nimbus.NimbusLookAndFeel;

import generic.theme.*;
import generic.theme.laf.nimbus.SelectedTreePainter;

/**
 * Extends the {@link NimbusLookAndFeel} to intercept the {@link #getDefaults()}. Nimbus does 
 * not honor changes to the UIDefaults after it is installed as the active
 * {@link LookAndFeel}, so we have to make the changes at the time the UIDefaults are installed. 
 *
 * To get around this issue, we extend the NimbusLookAndFeel
 * so that we can install our GColors and overridden properties as Nimbus is being installed,
 * specifically during the call to the getDefaults() method. For all other Look And Feels, the
 * GColors and overridden properties are changed in the UIDefaults after the Look And Feel is
 * installed, so they don't need to extends the Look and Feel class.
 *  
 * Also, note that Nimbus needs to be reinstalled every time we need to make a change to any of the
 * UIDefaults values, since it does not respond to changes other than when first installed.
 */
public class GNimbusLookAndFeel extends NimbusLookAndFeel {
	private ApplicationThemeManager themeManager;

	GNimbusLookAndFeel(ApplicationThemeManager themeManager) {
		this.themeManager = themeManager;
	}

	@Override
	public UIDefaults getDefaults() {
		UIDefaults defaults = super.getDefaults();

		installCustomPainters(defaults);

		GThemeValueMap javaDefaults = extractJavaDefaults(defaults);

		// replace all colors with GColors
		for (ColorValue colorValue : javaDefaults.getColors()) {
			String id = colorValue.getId();
			defaults.put(id, themeManager.getGColorUiResource(id));
		}

		// put fonts back into defaults in case they have been changed by the current theme
		for (FontValue fontValue : javaDefaults.getFonts()) {
			String id = fontValue.getId();
			Font font = themeManager.getFont(id);
			defaults.put(id, new FontUIResource(font));
		}

		// put icons back into defaults in case they have been changed by the current theme
		for (IconValue iconValue : javaDefaults.getIcons()) {
			String id = iconValue.getId();
			// because some icons are weird, put raw icons into defaults, only use GIcons for
			// setting Icons explicitly on components
			Icon icon = themeManager.getIcon(id);
			defaults.put(id, icon);
		}

		defaults.put("Label.textForeground", themeManager.getGColorUiResource("Label.foreground"));
		themeManager.refreshGThemeValues();
		return defaults;
	}

	private void installCustomPainters(UIDefaults defaults) {
		defaults.put("Tree:TreeCell[Enabled+Selected].backgroundPainter",
			new SelectedTreePainter());
		defaults.put("Tree:TreeCell[Focused+Selected].backgroundPainter",
			new SelectedTreePainter());
	}

	protected GThemeValueMap extractJavaDefaults(UIDefaults defaults) {
		GThemeValueMap javaDefaults = new GThemeValueMap();

		List<String> colorIds =
			LookAndFeelManager.getLookAndFeelIdsForType(defaults, Color.class);
		for (String id : colorIds) {
			Color color = defaults.getColor(id);
			ColorValue value = new ColorValue(id, color);
			javaDefaults.addColor(value);
		}
		List<String> fontIds =
			LookAndFeelManager.getLookAndFeelIdsForType(defaults, Font.class);
		for (String id : fontIds) {
			Font font = defaults.getFont(id);
			FontValue value = new FontValue(id, LookAndFeelManager.fromUiResource(font));
			javaDefaults.addFont(value);
		}
		List<String> iconIds =
			LookAndFeelManager.getLookAndFeelIdsForType(defaults, Icon.class);
		for (String id : iconIds) {
			Icon icon = defaults.getIcon(id);
			javaDefaults.addIcon(new IconValue(id, icon));
		}
		// need to set javaDefalts now to trigger building currentValues so the when
		// we create GColors below, they can be resolved. 
		themeManager.setJavaDefaults(javaDefaults);
		return javaDefaults;
	}
}
