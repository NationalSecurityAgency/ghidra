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

import java.util.ArrayList;
import java.util.List;

import javax.swing.*;
import javax.swing.plaf.ComponentUI;

import org.apache.commons.collections4.IteratorUtils;

import docking.theme.LafType;

/**
 * A utility class to manage LookAndFeel (LaF) settings.
 */
public class LookAndFeelUtils {

	private LookAndFeelUtils() {
		// utils class, cannot create
	}

//	/**
//	 * Loads settings from {@link Preferences}.
//	 */
//	public static void installGlobalOverrides() {
//
//		//
//		// Users can change this via the SystemUtilities.FONT_SIZE_OVERRIDE_PROPERTY_NAME
//		// system property.
//		//
//		Integer fontOverride = SystemUtilities.getFontSizeOverrideValue();
//		if (fontOverride != null) {
//			setGlobalFontSizeOverride(fontOverride);
//		}
//	}

	public static List<String> getLookAndFeelIdsForType(UIDefaults defaults, Class<?> clazz) {
		List<String> colorKeys = new ArrayList<>();
		List<Object> keyList = IteratorUtils.toList(defaults.keys().asIterator());
		for (Object key : keyList) {
			if (key instanceof String) {
				Object value = defaults.get(key);
				if (clazz.isInstance(value)) {
					colorKeys.add((String) key);
				}
			}
		}
		return colorKeys;
	}

	/**
	 * Returns true if the given UI object is using the Aqua Look and Feel.
	 * @param UI the UI to examine.
	 * @return true if the UI is using Aqua
	 */
	public static boolean isUsingAquaUI(ComponentUI UI) {
		Class<? extends ComponentUI> clazz = UI.getClass();
		String name = clazz.getSimpleName();
		return name.startsWith("Aqua");
	}

	/**
	 * Returns true if 'Nimbus' is the current Look and Feel
	 * @return true if 'Nimbus' is the current Look and Feel
	 */
	public static boolean isUsingNimbusUI() {
		LookAndFeel lookAndFeel = UIManager.getLookAndFeel();
		return LafType.NIMBUS.equals(lookAndFeel.getName());
	}

}
