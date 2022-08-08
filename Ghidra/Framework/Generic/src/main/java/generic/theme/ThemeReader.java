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

public class ThemeReader extends ThemePropertyFileReader {

	private Section themeSection;
	private String themeName;
	private LafType lookAndFeel;
	private boolean useDarkDefaults;

	public ThemeReader(File file) throws IOException {
		super(file);
	}

	@Override
	protected void processNoSection(Section section) throws IOException {
		themeSection = section;
		themeName = section.getValue(GTheme.THEME_NAME_KEY);
		if (themeName == null) {
			throw new IOException("Missing theme name!");
		}
		String lookAndFeelName = section.getValue(GTheme.THEME_LOOK_AND_FEEL_KEY);
		lookAndFeel = LafType.fromName(lookAndFeelName);
		if (lookAndFeel == null) {
			throw new IOException(
				"Invalid or missing lookAndFeel name: \"" + lookAndFeelName + "\"");
		}
		useDarkDefaults = Boolean.valueOf(section.getValue(GTheme.THEME_USE_DARK_DEFAULTS));
	}

	void loadValues(GTheme theme) {

		// processValues expects only colors, fonts, and icons
		themeSection.remove(GTheme.THEME_NAME_KEY);
		themeSection.remove(GTheme.THEME_LOOK_AND_FEEL_KEY);
		themeSection.remove(GTheme.THEME_USE_DARK_DEFAULTS);

		processValues(theme, themeSection);
	}

	public String getThemeName() {
		return themeName;
	}

	public LafType getLookAndFeelType() {
		return lookAndFeel;
	}

}
