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
package generic.theme;

import java.io.File;
import java.io.IOException;

import ghidra.framework.preferences.Preferences;
import ghidra.util.Msg;

/**
 * Reads and writes current theme info to preferences
 */
public class ThemePreferences {
	private static final String THEME_PREFFERENCE_KEY = "Theme";

	/**
	 * Returns the theme that was stored in preferences or the default theme if none stored.
	 * @return the last theme used (stored in preferences) or the default theme if not stored
	 * in preferences
	 */
	public GTheme load() {
		String themeId = Preferences.getProperty(THEME_PREFFERENCE_KEY, "Default", true);
		if (themeId.startsWith(GTheme.FILE_PREFIX)) {
			String filename = themeId.substring(GTheme.FILE_PREFIX.length());
			try {
				return new ThemeReader(new File(filename)).readTheme();
			}
			catch (IOException e) {
				Msg.showError(GTheme.class, null, "Can't Load Previous Theme",
					"Error loading theme file: " + filename, e);
			}
		}
		else if (themeId.startsWith(DiscoverableGTheme.CLASS_PREFIX)) {
			String className = themeId.substring(DiscoverableGTheme.CLASS_PREFIX.length());
			try {
				Class<?> forName = Class.forName(className);
				return (GTheme) forName.getDeclaredConstructor().newInstance();
			}
			catch (Exception e) {
				Msg.showError(GTheme.class, null, "Can't Load Previous Theme",
					"Can't find or instantiate class: " + className, e);
			}
		}
		return ThemeManager.getDefaultTheme();
	}

	/**
	 * Saves the current theme choice to {@link Preferences}.
	 * @param theme the theme to remember in {@link Preferences}
	 */
	public void save(GTheme theme) {
		Preferences.setProperty(THEME_PREFFERENCE_KEY, theme.getThemeLocater());
		Preferences.store();
	}
}
