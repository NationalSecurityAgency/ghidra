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

import static ghidra.util.WebColors.*;

import java.awt.Color;
import java.awt.Component;
import java.util.Set;

import javax.swing.plaf.ComponentUI;

/**
 * Version of ThemeManager that is used before an application or test installs a full
 * ApplicationThemeManager. Provides enough basic functionality used by the Gui class to
 * allow simple unit tests to run.
 */
public class StubThemeManager extends ThemeManager {

	public StubThemeManager() {
		installPaletteColors();
	}

	// palette colors are used statically throughout the application, so having them have values
	// in the stub will allow unit tests to run without initializing theming
	protected void installPaletteColors() {
		addPalette("nocolor", BLACK);
		addPalette("black", BLACK);
		addPalette("blue", BLUE);
		addPalette("cyan", CYAN);
		addPalette("darkgray", DARK_GRAY);
		addPalette("gold", GOLD);
		addPalette("gray", GRAY);
		addPalette("green", GREEN);
		addPalette("lavender", LAVENDER);
		addPalette("lightgray", LIGHT_GRAY);
		addPalette("lime", LIME);
		addPalette("magenta", MAGENTA);
		addPalette("maroon", MAROON);
		addPalette("orange", ORANGE);
		addPalette("pink", PINK);
		addPalette("purple", PURPLE);
		addPalette("red", RED);
		addPalette("silver", SILVER);
		addPalette("white", WHITE);
		addPalette("yellow", YELLOW);

	}

	@Override
	public void reloadApplicationDefaults() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void restoreThemeValues() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void restoreColor(String id) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void restoreFont(String id) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void restoreIcon(String id) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isChangedColor(String id) {
		return false;
	}

	@Override
	public boolean isChangedFont(String id) {
		return false;
	}

	@Override
	public boolean isChangedIcon(String id) {
		return false;
	}

	@Override
	public void setTheme(GTheme theme) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void addTheme(GTheme newTheme) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void deleteTheme(GTheme theme) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Set<GTheme> getAllThemes() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Set<GTheme> getSupportedThemes() {
		throw new UnsupportedOperationException();
	}

	@Override
	public GTheme getActiveTheme() {
		throw new UnsupportedOperationException();
	}

	@Override
	public LafType getLookAndFeelType() {
		throw new UnsupportedOperationException();
	}

	@Override
	public GTheme getTheme(String themeName) {
		throw new UnsupportedOperationException();
	}

	@Override
	public GThemeValueMap getThemeValues() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setFont(FontValue newValue) {
		currentValues.addFont(newValue);
	}

	@Override
	public void setColor(ColorValue newValue) {
		currentValues.addColor(newValue);
	}

	@Override
	public void setIcon(IconValue newValue) {
		currentValues.addIcon(newValue);
	}

	@Override
	public GThemeValueMap getJavaDefaults() {
		throw new UnsupportedOperationException();
	}

	@Override
	public GThemeValueMap getApplicationDarkDefaults() {
		throw new UnsupportedOperationException();
	}

	@Override
	public GThemeValueMap getApplicationLightDefaults() {
		throw new UnsupportedOperationException();
	}

	@Override
	public GThemeValueMap getDefaults() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isUsingAquaUI(ComponentUI UI) {
		return false;
	}

	@Override
	public boolean isUsingNimbusUI() {
		return false;
	}

	@Override
	public boolean hasThemeChanges() {
		return false;
	}

	@Override
	public void registerFont(Component component, String fontId) {
		// do nothing
	}

	@Override
	public boolean isDarkTheme() {
		return false;
	}

	@Override
	protected void error(String message) {
		// don't report errors in stub for test purposes
	}

	private void addPalette(String paletteId, Color color) {
		setColor(new ColorValue("color.palette." + paletteId, color));
	}

	@Override
	protected ThemeDefaultsProvider getThemeDefaultsProvider() {
		return new ThemeDefaultsProvider() {

			@Override
			public GThemeValueMap getDefaults() {
				return null;
			}

			@Override
			public GThemeValueMap getDarkDefaults() {
				return null;
			}

			@Override
			public GThemeValueMap getLookAndFeelDefaults(LafType lafType) {
				return null;
			}

		};
	}

}
