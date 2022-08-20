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
import java.util.*;
import java.util.List;

import javax.swing.*;
import javax.swing.plaf.FontUIResource;

import generic.theme.*;

/**
 * Manages installing and updating a {@link LookAndFeel}
 */
public abstract class LookAndFeelManager {

	private LafType laf;
	private Map<String, ComponentFontRegistry> fontRegistryMap = new HashMap<>();

	protected LookAndFeelManager(LafType laf) {
		this.laf = laf;
	}

	protected abstract LookAndFeelInstaller getLookAndFeelInstaller();

	/**
	 * Returns the {@link LafType} managed by this manager.
	 * @return the {@link LafType}
	 */
	public LafType getLookAndFeelType() {
		return laf;
	}

	/**
	 * Installs the {@link LookAndFeel}
	 * @throws ClassNotFoundException if the <code>LookAndFeel</code>
	 *           class could not be found
	 * @throws InstantiationException if a new instance of the class
	 *          couldn't be created
	 * @throws IllegalAccessException if the class or initializer isn't accessible
	 * @throws UnsupportedLookAndFeelException if
	 *          <code>lnf.isSupportedLookAndFeel()</code> is false
	 */
	public void installLookAndFeel() throws ClassNotFoundException, InstantiationException,
			IllegalAccessException, UnsupportedLookAndFeelException {

		LookAndFeelInstaller installer = getLookAndFeelInstaller();
		installer.install();
		updateComponentUis();
	}

	/**
	 * Called when all colors, fonts, and icons may have changed
	 * @param javaDefaults the current set of java defaults so that those ids can be updated
	 * special as needed by the current {@link LookAndFeel}
	 */
	public void resetAll(GThemeValueMap javaDefaults) {
		GColor.refreshAll();
		GIcon.refreshAll();
		resetIcons(javaDefaults);
		resetFonts(javaDefaults);
		updateAllRegisteredComponentFonts();
		updateComponentUis();
	}

	private void updateAllRegisteredComponentFonts() {
		for (ComponentFontRegistry register : fontRegistryMap.values()) {
			register.updateComponentFonts();
		}
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

	/**
	 * Called when one or more colors have changed.
	 */
	public void colorsChanged() {
		GColor.refreshAll();
		repaintAll();
	}

	/**
	 * Called when one or more icons have changed.
	 * @param id the id of primary icon that changed
	 * @param changedIconIds 
	 * @param newIcon 
	 */
	public void iconsChanged(Set<String> changedIconIds, Icon newIcon) {
		if (!changedIconIds.isEmpty()) {
			UIDefaults defaults = UIManager.getDefaults();
			for (String javaIconId : changedIconIds) {
				defaults.put(javaIconId, newIcon);
			}
			updateComponentUis();
		}
		GIcon.refreshAll();
		repaintAll();
	}

	/**
	 * Called when one or more fonts have changed.
	 * @param changedJavaFontIds the set of Java Font ids that are affected by this change
	 * @param newFont the new font for the given ids
	 */
	public void fontsChanged(Set<String> changedJavaFontIds, Font newFont) {
		if (!changedJavaFontIds.isEmpty()) {
			UIDefaults defaults = UIManager.getDefaults();
			newFont = new FontUIResource(newFont);
			for (String javaFontId : changedJavaFontIds) {
				defaults.put(javaFontId, newFont);
			}
			updateComponentFonts(changedJavaFontIds);
			updateComponentUis();
		}
		repaintAll();
	}

	protected void updateComponentFonts(Set<String> changedFontIds) {
		for (String javaFontId : changedFontIds) {
			ComponentFontRegistry register = fontRegistryMap.get(javaFontId);
			if (register != null) {
				register.updateComponentFonts();
			}
		}
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

	public void registerFont(Component c, String fontId) {
		ComponentFontRegistry register =
			fontRegistryMap.computeIfAbsent(fontId, id -> new ComponentFontRegistry(id));

		register.addComponent(c);
	}

}
