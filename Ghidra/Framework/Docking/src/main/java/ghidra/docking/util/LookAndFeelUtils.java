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

import java.awt.Taskbar;

import javax.swing.LookAndFeel;
import javax.swing.plaf.ComponentUI;

import docking.framework.ApplicationInformationDisplayFactory;
import generic.theme.LafType;
import generic.theme.ThemeManager;

/**
 * A utility class to manage LookAndFeel (LaF) settings.
 */
public class LookAndFeelUtils {

	private LookAndFeelUtils() {
		// utils class, cannot create
	}

	/**
	 * This method does nothing.  This is not handled by the theming system in the look and feel
	 * manager.
	 */
	@Deprecated(since = "11.1", forRemoval = true)
	public static void installGlobalOverrides() {
		//
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

	/**
	 * Returns the {@link LafType} for the currently active {@link LookAndFeel}
	 * @return the {@link LafType} for the currently active {@link LookAndFeel}
	 */
	public static LafType getLookAndFeelType() {
		return ThemeManager.getInstance().getLookAndFeelType();
	}

	/**
	 * Returns true if the given UI object is using the Aqua Look and Feel.
	 * @param UI the UI to examine.
	 * @return true if the UI is using Aqua
	 */
	public static boolean isUsingAquaUI(ComponentUI UI) {
		return ThemeManager.getInstance().isUsingAquaUI();
	}

	/**
	 * Returns true if 'Nimbus' is the current Look and Feel
	 * @return true if 'Nimbus' is the current Look and Feel
	 */
	public static boolean isUsingNimbusUI() {
		return ThemeManager.getInstance().isUsingNimbusUI();
	}

	/**
	 * Returns true if the current UI is the FlatLaf Dark or FlatLaf Light Look and Feel.
	 * @return true if the current UI is the FlatLaf Dark or FlatLaf Light Look and Feel 
	 */
	public static boolean isUsingFlatUI() {
		return ThemeManager.getInstance().isUsingFlatUI();
	}
}
