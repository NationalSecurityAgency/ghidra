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

import java.awt.Font;
import java.awt.Window;
import java.util.List;
import java.util.Set;

import javax.swing.*;

import generic.theme.*;

/**
 * Manages installing and updating a {@link LookAndFeel}
 */
public abstract class LookAndFeelManager {

	private LafType laf;

	protected LookAndFeelManager(LafType laf) {
		this.laf = laf;
	}

	protected abstract LookAndFeelInstaller getLookAndFeelInstaller();

	public LafType getLookAndFeelType() {
		return laf;
	}

	public void installLookAndFeel() throws ClassNotFoundException, InstantiationException,
			IllegalAccessException, UnsupportedLookAndFeelException {

		LookAndFeelInstaller installer = getLookAndFeelInstaller();
		installer.install();
		updateComponentUis();
	}

	public void resetAll(GThemeValueMap javaDefaults) {
		GColor.refreshAll();
		GIcon.refreshAll();
		resetIcons(javaDefaults);
		resetFonts(javaDefaults);
		updateComponentUis();
	}

	private void resetFonts(GThemeValueMap javaDefaults) {
		List<FontValue> fonts = javaDefaults.getFonts();
		UIDefaults defaults = UIManager.getDefaults();
		for (FontValue fontValue : fonts) {
			String id = fontValue.getId();
			Font correctFont = Gui.getFont(id);
			Font storedFont = defaults.getFont(id);
			if (correctFont != null && !correctFont.equals(storedFont)) {
				defaults.put(id, correctFont);
			}
		}
	}

	private void resetIcons(GThemeValueMap javaDefaults) {
		List<IconValue> icons = javaDefaults.getIcons();
		UIDefaults defaults = UIManager.getDefaults();
		for (IconValue iconValue : icons) {
			String id = iconValue.getId();
			Icon correctIcon = Gui.getRawIcon(id, false);
			Icon storedIcon = defaults.getIcon(id);
			if (correctIcon != null && !correctIcon.equals(storedIcon)) {
				defaults.put(id, correctIcon);
			}
		}
	}

	public void updateColors() {
		GColor.refreshAll();
		repaintAll();
	}

	public void updateIcons(String id, Set<String> affectedJavaIds, Icon newIcon) {
		if (!affectedJavaIds.isEmpty()) {
			UIDefaults defaults = UIManager.getDefaults();
			for (String javaIconId : affectedJavaIds) {
				defaults.put(javaIconId, newIcon);
			}
			updateComponentUis();
		}
		GIcon.refreshAll();
		repaintAll();
	}

	public void updateFonts(String id, Set<String> affectedJavaIds, Font newFont) {
		if (!affectedJavaIds.isEmpty()) {
			UIDefaults defaults = UIManager.getDefaults();
			for (String javaFontId : affectedJavaIds) {
				defaults.put(javaFontId, newFont);
			}
			updateComponentUis();
		}
		repaintAll();
	}

	protected void updateComponentUis() {
		for (Window window : Window.getWindows()) {
			SwingUtilities.updateComponentTreeUI(window);
		}
	}

	protected void repaintAll() {
		for (Window window : Window.getWindows()) {
			window.repaint();
		}
	}

}
