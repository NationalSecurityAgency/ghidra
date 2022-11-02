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
package ghidra.docking.util;

import java.awt.Font;
import java.awt.Taskbar;
import java.util.Iterator;
import java.util.Map.Entry;
import java.util.Set;

import javax.swing.UIDefaults;
import javax.swing.UIManager;

import docking.framework.ApplicationInformationDisplayFactory;
import ghidra.framework.preferences.Preferences;
import ghidra.util.SystemUtilities;

/**
 * A utility class to manage LookAndFeel (LaF) settings.
 */
public class LookAndFeelUtils {

	private LookAndFeelUtils() {
		// utils class, cannot create
	}

	/**
	 * Loads settings from {@link Preferences}.
	 */
	public static void installGlobalOverrides() {

		//
		// Users can change this via the SystemUtilities.FONT_SIZE_OVERRIDE_PROPERTY_NAME
		// system property.
		//
		Integer fontOverride = SystemUtilities.getFontSizeOverrideValue();
		if (fontOverride != null) {
			setGlobalFontSizeOverride(fontOverride);
		}
	}

	/** Allows you to globally set the font size (don't use this method!) */
	private static void setGlobalFontSizeOverride(int fontSize) {
		UIDefaults defaults = UIManager.getDefaults();

		Set<Entry<Object, Object>> set = defaults.entrySet();
		Iterator<Entry<Object, Object>> iterator = set.iterator();
		while (iterator.hasNext()) {
			Entry<Object, Object> entry = iterator.next();
			Object key = entry.getKey();

			if (key.toString().toLowerCase().indexOf("font") != -1) {
				Font currentFont = defaults.getFont(key);
				if (currentFont != null) {
					Font newFont = currentFont.deriveFont((float) fontSize);
					UIManager.put(key, newFont);
				}
			}
		}
	}

	public static void performPlatformSpecificFixups() {
		// Set the dock icon for macOS
		if (Taskbar.isTaskbarSupported()) {
			Taskbar taskbar = Taskbar.getTaskbar();
			if (taskbar.isSupported(Taskbar.Feature.ICON_IMAGE)) {
				taskbar.setIconImage(ApplicationInformationDisplayFactory.getLargestWindowIcon());
			}
		}
	}
}
