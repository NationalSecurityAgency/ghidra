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

import javax.swing.Icon;
import javax.swing.UIDefaults;
import javax.swing.plaf.FontUIResource;
import javax.swing.plaf.nimbus.NimbusLookAndFeel;

import generic.theme.*;

/**
 * Extends the NimbusLookAndFeel to intercept the {@link #getDefaults()}. To get Nimbus
 * to use our indirect values, we have to get in early.
 */
public class GNimbusLookAndFeel extends NimbusLookAndFeel {

	@Override
	public UIDefaults getDefaults() {
		UIDefaults defaults = super.getDefaults();
		GThemeValueMap javaDefaults = extractJavaDefaults(defaults);

		// replace all colors with GColors
		for (ColorValue colorValue : javaDefaults.getColors()) {
			String id = colorValue.getId();
			defaults.put(id, Gui.getGColorUiResource(id));
		}

		// put fonts back into defaults in case they have been changed by the current theme
		for (FontValue fontValue : javaDefaults.getFonts()) {
			String id = fontValue.getId();
			Font font = Gui.getFont(id);
			defaults.put(id, new FontUIResource(font));
		}

		// put icons back into defaults in case they have been changed by the current theme
		for (IconValue iconValue : javaDefaults.getIcons()) {
			String id = iconValue.getId();
			// because some icons are weird, put raw icons into defaults, only use GIcons for
			// setting Icons explicitly on components
			Icon icon = Gui.getRawIcon(id, true);
			defaults.put(id, icon);
		}

		defaults.put("Label.textForeground", Gui.getGColorUiResource("Label.foreground"));
		GColor.refreshAll();
		GIcon.refreshAll();
		return defaults;
	}

	protected GThemeValueMap extractJavaDefaults(UIDefaults defaults) {
		GThemeValueMap javaDefaults = new GThemeValueMap();

		List<String> colorIds =
			LookAndFeelInstaller.getLookAndFeelIdsForType(defaults, Color.class);
		for (String id : colorIds) {
			Color color = defaults.getColor(id);
			ColorValue value = new ColorValue(id, color);
			javaDefaults.addColor(value);
		}
		List<String> fontIds =
			LookAndFeelInstaller.getLookAndFeelIdsForType(defaults, Font.class);
		for (String id : fontIds) {
			Font font = defaults.getFont(id);
			FontValue value = new FontValue(id, LookAndFeelInstaller.fromUiResource(font));
			javaDefaults.addFont(value);
		}
		List<String> iconIds =
			LookAndFeelInstaller.getLookAndFeelIdsForType(defaults, Icon.class);
		for (String id : iconIds) {
			Icon icon = defaults.getIcon(id);
			javaDefaults.addIcon(new IconValue(id, icon));
		}
		// need to set javaDefalts now to trigger building currentValues so the when
		// we create GColors below, they can be resolved. 
		Gui.setJavaDefaults(javaDefaults);

		return javaDefaults;
	}
}
