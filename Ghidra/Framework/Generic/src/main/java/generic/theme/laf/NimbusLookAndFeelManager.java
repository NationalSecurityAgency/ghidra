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

import java.awt.Dimension;
import java.util.Set;

import javax.swing.*;

import generic.theme.*;
import ghidra.util.exception.AssertException;

/**
 * Nimbus {@link LookAndFeelManager}. Specialized so that it can return the Nimbus installer and
 * do specialized updating when icons or fonts change. Basically, needs to re-install a new
 * instance of the Nimbus LookAndFeel each time a font or icon changes
 */
public class NimbusLookAndFeelManager extends LookAndFeelManager {

	public NimbusLookAndFeelManager(ApplicationThemeManager themeManager) {
		super(LafType.NIMBUS, themeManager);

		// establish system color specific to Nimbus
		systemToLafMap.addColor(new ColorValue(SYSTEM_BORDER_COLOR_ID, "nimbusBorder"));
	}

	@Override
	public void resetAll(GThemeValueMap javaDefaults) {
		themeManager.refreshGThemeValues();
		reinstallNimubus();
	}

	@Override
	public void fontsChanged(Set<String> affectedJavaIds) {
		if (!affectedJavaIds.isEmpty()) {
			reinstallNimubus();
		}
		updateAllRegisteredComponentFonts();
		repaintAll();
	}

	@Override
	public void iconsChanged(Set<String> affectedJavaIds, Icon newIcon) {
		if (!affectedJavaIds.isEmpty()) {
			reinstallNimubus();
		}
		themeManager.refreshGThemeValues();
		repaintAll();
	}

	private void reinstallNimubus() {
		try {
			UIManager.setLookAndFeel(new GNimbusLookAndFeel(themeManager) {
				@Override
				protected GThemeValueMap extractJavaDefaults(UIDefaults defaults) {
					return themeManager.getJavaDefaults();
				}
			});
		}
		catch (UnsupportedLookAndFeelException e) {
			throw new AssertException("This can't happen, we are just re-installing the same L&F");
		}
		updateComponentUis();
	}

	@Override
	protected void doInstallLookAndFeel() throws UnsupportedLookAndFeelException {
		UIManager.setLookAndFeel(new GNimbusLookAndFeel(themeManager));
	}

	@Override
	protected GThemeValueMap extractJavaDefaults() {
		// The GNimbusLookAndFeel already extracted the java defaults and installed them in the Gui
		return themeManager.getJavaDefaults();
	}

	@Override
	protected ThemeGrouper getThemeGrouper() {
		return new NimbusThemeGrouper();
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

	@Override
	protected void installPropertiesBackIntoUiDefaults(GThemeValueMap javaDefaults) {
		// do nothing, this was handled when we overrode the getDefaults() method in the 
		// GNimubusLookAndFeel
	}
}
