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
package help.screenshot;

import java.awt.Font;

import org.junit.Test;

import docking.theme.gui.*;
import generic.theme.*;
import generic.theme.GThemeDefaults.Colors.Palette;
import resources.ResourceManager;

public class ThemingScreenShots extends GhidraScreenShotGenerator {

	private ThemeManager themeManager;

	public ThemingScreenShots() {
		super();
		themeManager = ThemeManager.getInstance();
	}

	@Test
	public void testThemeDialog() {
		showDialogWithoutBlocking(tool, new ThemeDialog(themeManager));
		captureDialog(1000, 500);
	}

	@Test
	public void testColorEditor() {
		ColorValueEditor editor = new ColorValueEditor(e -> {
			/**/});
		ColorValue value = new ColorValue("color.bg.test", Palette.BLUE);
		themeManager.setColor(value);
		editor.editValue(value);
		captureDialog();
	}

	@Test
	public void testFontEditor() {
		FontValueEditor editor = new FontValueEditor(e -> {
			/**/});
		FontValue value = new FontValue("font.xyz", new Font("Monospaced", Font.BOLD, 14));
		themeManager.setFont(value);
		editor.editValue(value);
		captureDialog();
	}

	@Test
	public void testIconEditor() {
		IconValueEditor editor = new IconValueEditor(e -> {
			/**/});
		IconValue value = new IconValue("icon.bomb", ResourceManager.getDefaultIcon());
		themeManager.setIcon(value);
		editor.editValue(value);
		captureDialog();
	}
}
