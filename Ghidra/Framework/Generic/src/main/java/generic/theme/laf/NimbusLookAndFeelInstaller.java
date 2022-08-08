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
import java.util.List;

import javax.swing.*;
import javax.swing.plaf.nimbus.NimbusLookAndFeel;

import generic.theme.*;

public class NimbusLookAndFeelInstaller extends LookAndFeelInstaller {

	public NimbusLookAndFeelInstaller() {
		super(LafType.NIMBUS);
	}

	@Override
	protected void installLookAndFeel() throws UnsupportedLookAndFeelException {
		UIManager.setLookAndFeel(new GNimbusLookAndFeel());
	}

	@Override
	protected void installJavaDefaults() {
		// do nothing - already handled by installing extended NimbusLookAndFeel
	}

	@Override
	protected void fixupLookAndFeelIssues() {
		super.fixupLookAndFeelIssues();

		// fix scroll bar grabber disappearing.  See https://bugs.openjdk.java.net/browse/JDK-8134828
		// This fix looks like it should not cause harm even if the bug is fixed on the jdk side.
		UIDefaults defaults = UIManager.getDefaults();
		defaults.put("ScrollBar.minimumThumbSize", new Dimension(30, 30));

		// (see NimbusDefaults for key values that can be changed here)
	}

	/**
	 * Extends the NimbusLookAndFeel to intercept the {@link #getDefaults()}. To get Nimbus
	 * to use our indirect values, we have to get in early.
	 */
	static class GNimbusLookAndFeel extends NimbusLookAndFeel {

		@Override
		public UIDefaults getDefaults() {
			UIDefaults defaults = super.getDefaults();
			GThemeValueMap javaDefaults = extractJavaDefaults(defaults);

			// need to set javaDefalts now to trigger building currentValues so the when
			// we create GColors below, they can be resolved. 
			Gui.setJavaDefaults(javaDefaults);

			// replace all colors with GColors
			for (ColorValue colorValue : javaDefaults.getColors()) {
				String id = colorValue.getId();
				defaults.put(id, Gui.getGColorUiResource(id));
			}

			GTheme theme = Gui.getActiveTheme();

			// only replace fonts that have been changed by the theme
			for (FontValue fontValue : theme.getFonts()) {
				String id = fontValue.getId();
				Font font = Gui.getFont(id);
				defaults.put(id, font);
			}

			// only replace icons that have been changed by the theme
			for (IconValue iconValue : theme.getIcons()) {
				String id = iconValue.getId();
				Icon icon = Gui.getRawIcon(id, true);
				defaults.put(id, icon);
			}

			defaults.put("Label.textForeground", Gui.getGColorUiResource("Label.foreground"));
			GColor.refreshAll();
			GIcon.refreshAll();
			return defaults;
		}

		private GThemeValueMap extractJavaDefaults(UIDefaults defaults) {
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
				FontValue value = new FontValue(id, font);
				javaDefaults.addFont(value);
			}
			List<String> iconIds =
				LookAndFeelInstaller.getLookAndFeelIdsForType(defaults, Icon.class);
			for (String id : iconIds) {
				Icon icon = defaults.getIcon(id);
				javaDefaults.addIcon(new IconValue(id, icon));
			}

			return javaDefaults;
		}

	}

}
