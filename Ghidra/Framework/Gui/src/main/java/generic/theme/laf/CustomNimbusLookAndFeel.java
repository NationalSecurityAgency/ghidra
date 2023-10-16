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

import java.util.Map;

import javax.swing.LookAndFeel;
import javax.swing.UIDefaults;
import javax.swing.plaf.nimbus.NimbusLookAndFeel;

import generic.theme.ApplicationThemeManager;
import generic.theme.GThemeValueMap;
import generic.theme.laf.nimbus.SelectedTreePainter;

/**
 * Extends the {@link NimbusLookAndFeel} (Nimbus) to intercept {@link #getDefaults()}. Nimbus 
 * does not honor changes to the UIDefaults after it is installed as the active
 * {@link LookAndFeel}, so we have to make the changes at the time the UIDefaults are installed. 
 * <P>
 * To get around this issue, we extend Nimbus so that we can install our GColors and
 * overridden properties as Nimbus is being installed, specifically during the call to the 
 * getDefaults() method. For all other Look And Feels, the GColors and overridden properties are 
 * changed in the UIDefaults after the Look And Feel is installed, so they don't need to extend the
 * Look and Feel class.
 * <P>
 * Also, unlike other LaFs, Nimbus needs to be reinstalled every time we need to make a change to 
 * any of the UIDefaults values, since it does not respond to changes other than when first 
 * installed.
 */
public class CustomNimbusLookAndFeel extends NimbusLookAndFeel {
	private ApplicationThemeManager themeManager;
	private Map<String, String> normalizedIdToLafIdMap;

	CustomNimbusLookAndFeel(ApplicationThemeManager themeManager) {
		this.themeManager = themeManager;
	}

	@Override
	public UIDefaults getDefaults() {
		UIDefaults defaults = super.getDefaults();

		installCustomPainters(defaults);

		// normally all of this wiring is handled by the LookAndFeelManager (see above)
		UiDefaultsMapper uiDefaultsMapper = new NimbusUiDefaultsMapper(defaults);
		installJavaDefaultsIntoThemeManager(uiDefaultsMapper);
		uiDefaultsMapper.installValuesIntoUIDefaults(themeManager.getCurrentValues());

		normalizedIdToLafIdMap = uiDefaultsMapper.getNormalizedIdToLafIdMap();
		return defaults;
	}

	protected void installJavaDefaultsIntoThemeManager(UiDefaultsMapper uiDefaultsMapper) {
		GThemeValueMap javaDefaults = uiDefaultsMapper.getNormalizedJavaDefaults();
		themeManager.setJavaDefaults(javaDefaults);
	}

	private void installCustomPainters(UIDefaults defaults) {
		defaults.put("Tree:TreeCell[Enabled+Selected].backgroundPainter",
			new SelectedTreePainter());
		defaults.put("Tree:TreeCell[Focused+Selected].backgroundPainter",
			new SelectedTreePainter());
	}

	public Map<String, String> getNormalizedIdToLafIdMap() {
		return normalizedIdToLafIdMap;
	}
}
