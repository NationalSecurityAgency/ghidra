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
import ghidra.util.Msg;

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
		// do nothing - already handled by extended NimbusLookAndFeel
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
			GThemeValueMap javaDefaults = new GThemeValueMap();

			UIDefaults defaults = super.getDefaults();
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
			Msg.debug(LookAndFeelInstaller.class, "Icons found: " + iconIds.size());
			for (String id : iconIds) {
				Icon icon = defaults.getIcon(id);
				javaDefaults.addIcon(new IconValue(id, icon));
			}

			Gui.setJavaDefaults(javaDefaults);
			for (String id : colorIds) {
				defaults.put(id, Gui.getGColorUiResource(id));
			}
//			for (String id : iconIds) {
//				GIconUIResource icon = Gui.getGIconUiResource(id);
//				if (icon.getId().equals("Menu.arrowIcon")) {
//					defaults.put(id, new IconWrappedImageIcon(Gui.getRawIcon(id, false)));
//				}
//				else {
//					defaults.put(id, Gui.getGIconUiResource(id));
//				}
//			}

//			javaDefaults.addColor(new ColorValue("Label.textForground", "Label.foreground"));
			defaults.put("Label.textForeground", Gui.getGColorUiResource("Label.foreground"));
			GColor.refreshAll();
			GIcon.refreshAll();
			return defaults;
		}

	}

}
