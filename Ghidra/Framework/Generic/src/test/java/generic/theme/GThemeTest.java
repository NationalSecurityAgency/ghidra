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

import static org.junit.Assert.*;

import java.awt.Color;
import java.awt.Font;
import java.io.File;
import java.io.IOException;

import javax.swing.Icon;

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import resources.ResourceManager;

public class GThemeTest extends AbstractGenericTest {

	private static final Font COURIER = new Font("Courier", Font.BOLD, 14);
	private static final Font DIALOG = new Font("Dialog", Font.PLAIN, 16);
	private static final Color COLOR_WITH_ALPHA = new Color(10, 20, 30, 40);
	private static final String ICON_PATH_1 = "images/error.png";
	private static final String ICON_PATH_2 = "images/exec.png";
	private static final Icon ICON1 = ResourceManager.loadImage(ICON_PATH_1);
	private static final Icon ICON2 = ResourceManager.loadImage(ICON_PATH_2);

	private GTheme theme;

	@Before
	public void setUp() {
		theme = new GTheme("TestTheme");
		new Font("Courier", Font.BOLD, 12);
	}

	@Test
	public void testGetName() {
		assertEquals("TestTheme", theme.getName());
	}

	@Test
	public void testSetColor() {
		theme.setColor("color.a.1", Color.BLUE);
		assertEquals(Color.BLUE, theme.getColor("color.a.1").get(null));
		theme.setColor("color.a.1", Color.RED);
		assertEquals(Color.RED, theme.getColor("color.a.1").get(null));
	}

	@Test
	public void testSetFont() {
		theme.setFont("font.a.1", DIALOG);
		assertEquals(DIALOG, theme.getFont("font.a.1").get(null));
	}

	@Test
	public void testSetIconPath() {
		theme.setIcon("icon.a.1", ICON1);
		assertEquals(ICON1, theme.getIcon("icon.a.1").get(null));
	}

	@Test
	public void testSavingLoadingTheme() throws IOException {
		theme = new GTheme("abc");
		theme.setColor("color.a.1", Color.RED);
		theme.setColor("color.a.2", Color.BLUE);
		theme.setColor("color.a.3", COLOR_WITH_ALPHA);
		theme.setColorRef("color.a.4", "color.a.1");
		theme.setColor("foo.bar", Color.GREEN);
		theme.setColorRef("foo.bar.xyz", "foo.bar");

		theme.setFont("font.a.1", COURIER);
		theme.setFont("font.a.2", DIALOG);
		theme.setFontRef("font.a.3", "font.a.1");
		theme.setFont("x.y.z", COURIER);
		theme.setFontRef("x.y.z.1", "x.y.z");

		theme.setIcon("icon.a.1", ICON1);
		theme.setIcon("icon.a.2", ICON2);
		theme.setIconRef("icon.a.3", "icon.a.1");
		theme.setIcon("t.u.v", ICON1);
		theme.setIconRef("t.u.v.1", "t.u.v");

		File file = createTempFile("themeTest", ".theme");

		new ThemeWriter(theme).writeThemeToFile(file);
		theme = new ThemeReader(file).readTheme();

		assertEquals("abc", theme.getName());
		assertEquals(LafType.getDefaultLookAndFeel(), theme.getLookAndFeelType());

		assertEquals(Color.RED, theme.getColor("color.a.1").get(theme));
		assertEquals(Color.BLUE, theme.getColor("color.a.2").get(theme));
		assertEquals(COLOR_WITH_ALPHA, theme.getColor("color.a.3").get(theme));
		assertEquals("color.a.1", theme.getColor("color.a.4").getReferenceId());
		assertEquals(Color.RED, theme.getColor("color.a.4").get(theme));
		assertEquals(Color.GREEN, theme.getColor("foo.bar").get(theme));
		assertEquals(Color.GREEN, theme.getColor("foo.bar.xyz").get(theme));

		assertEquals(COURIER, theme.getFont("font.a.1").get(theme));
		assertEquals(DIALOG, theme.getFont("font.a.2").get(theme));
		assertEquals(COURIER, theme.getFont("x.y.z").get(theme));
		assertEquals(COURIER, theme.getFont("x.y.z.1").get(theme));

		assertEquals(ICON1, theme.getIcon("icon.a.1").get(theme));
		assertEquals(ICON2, theme.getIcon("icon.a.2").get(theme));
		assertEquals(ICON1, theme.getIcon("t.u.v").get(theme));
		assertEquals(ICON1, theme.getIcon("t.u.v.1").get(theme));
	}

}
