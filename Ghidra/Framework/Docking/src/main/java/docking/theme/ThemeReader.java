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
package docking.theme;

import java.io.File;
import java.io.IOException;

public class ThemeReader extends ThemePropertyFileReader {

	private Section themeSection;
	private String themeName;
	private String lookAndFeelName;
	private boolean isDark;

	public ThemeReader(File file) throws IOException {
		super(file);
	}

	@Override
	protected void processNoSection(Section section) throws IOException {
		themeSection = section;
		themeName = section.getValue(GTheme.THEME_NAME_KEY);
		lookAndFeelName = section.getValue(GTheme.THEME_LOOK_AND_FEEL_KEY);
		if (themeName == null) {
			throw new IOException("Missing theme name and/or lookAndFeel name!");
		}
		if (lookAndFeelName == null) {
			error(section.getLineNumber(), "Invalid theme - missing theme name!");
			return;
		}
		isDark = Boolean.parseBoolean(section.getValue(GTheme.THEME_IS_DARK_KEY));
	}

	void loadValues(GTheme theme) {

		// processValues expects only colors, fonts, and icons
		themeSection.remove(GTheme.THEME_NAME_KEY);
		themeSection.remove(GTheme.THEME_LOOK_AND_FEEL_KEY);
		themeSection.remove(GTheme.THEME_IS_DARK_KEY);

		processValues(theme, themeSection);
	}

	public String getThemeName() {
		return themeName;
	}

	public String getLookAndFeelName() {
		return lookAndFeelName;
	}

	public boolean isDark() {
		return isDark;
	}

}
