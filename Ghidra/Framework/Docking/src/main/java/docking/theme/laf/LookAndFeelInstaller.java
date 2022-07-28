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
package docking.theme.laf;

import java.awt.Color;
import java.util.List;

import javax.swing.UIDefaults;
import javax.swing.UIManager;
import javax.swing.plaf.UIResource;

import docking.theme.*;
import ghidra.docking.util.LookAndFeelUtils;

public abstract class LookAndFeelInstaller {

	public void install() throws Exception {
		cleanUiDefaults();
		installLookAndFeel();
		installJavaDefaults();
		fixupLookAndFeelIssues();
	}

	protected abstract void installLookAndFeel() throws Exception;

	protected void fixupLookAndFeelIssues() {
		// no generic fix-ups at this time.
	}

	protected void installJavaDefaults() {
		GThemeValueMap javaDefaults = extractJavaDefaults();
		Gui.setJavaDefaults(javaDefaults);
		installIndirectValues(javaDefaults);
	}

	private void installIndirectValues(GThemeValueMap javaDefaults) {
		UIDefaults defaults = UIManager.getDefaults();
		for (ColorValue colorValue : javaDefaults.getColors()) {
			String id = colorValue.getId();
			GColorUIResource gColor = Gui.getGColorUiResource(id);
			defaults.put(id, gColor);
		}
		for (FontValue fontValue : javaDefaults.getFonts()) {
			String id = fontValue.getId();
			GFont gFont = new GFont(id);
			if (!gFont.equals(fontValue.getRawValue())) {
				// only update if we have changed the default java color
				defaults.put(id, gFont);
			}
		}
	}

	protected GThemeValueMap extractJavaDefaults() {
		GThemeValueMap values = new GThemeValueMap();
		// for now, just doing color properties.
		List<String> ids =
			LookAndFeelUtils.getLookAndFeelIdsForType(UIManager.getDefaults(), Color.class);
		for (String id : ids) {
			values.addColor(new ColorValue(id, getNonUiColor(id)));
		}
		return values;
	}

	private static Color getNonUiColor(String id) {
		// Not sure, but for now, make sure colors are not UIResource
		Color color = UIManager.getColor(id);
		if (color instanceof UIResource) {
			return new Color(color.getRGB(), true);
		}
		return color;
	}

	private void cleanUiDefaults() {
		GThemeValueMap javaDefaults = Gui.getJavaDefaults();
		if (javaDefaults == null) {
			return;
		}
		UIDefaults defaults = UIManager.getDefaults();
		for (ColorValue colorValue : javaDefaults.getColors()) {
			String id = colorValue.getId();
			defaults.put(id, null);
		}
//		for (FontValue fontValue : javaDefaults.getFonts()) {
//			String id = fontValue.getId();
//			defaults.put(id, null);
//		}
	}

}
