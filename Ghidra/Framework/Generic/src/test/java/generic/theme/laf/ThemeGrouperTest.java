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

import static ghidra.util.WebColors.*;
import static org.junit.Assert.*;

import java.awt.Color;
import java.awt.Font;

import org.junit.Before;
import org.junit.Test;

import generic.theme.*;

public class ThemeGrouperTest {
	private static Font FONT1 = new Font("Dialog", Font.PLAIN, 12);
	private static Font FONT2 = new Font("Dialog", Font.BOLD, 16);

	private ThemeGrouper grouper;
	private GThemeValueMap values;

	@Before
	public void setUp() {
		grouper = new ThemeGrouper();
		values = new GThemeValueMap();
	}

	@Test
	public void testGroupColorUsingPreferredSources() {
		initColor("control", RED);
		initColor("menu", RED);
		initColor("Menu.background", RED);
		grouper.group(values);

		ColorValue colorValue = values.getColor("Menu.background");
		assertEquals("menu", colorValue.getReferenceId());
	}

	@Test
	public void testGroupColorUsingNonPreferredSourceWhenPreferredDoesntMatch() {
		initColor("control", RED);
		initColor("menu", BLUE);
		initColor("Menu.background", RED);
		grouper.group(values);

		ColorValue colorValue = values.getColor("Menu.background");
		assertEquals("control", colorValue.getReferenceId());
	}

	@Test
	public void testGroupFontUsingPreferredSources() {
		initFont("Button.font", FONT1);
		initFont("RadioButton.font", FONT1);
		initFont("Menu.font", FONT1);
		initFont("MenuItem.font", FONT1);
		grouper.group(values);

		assertEquals(FONT1, values.getFont("font.button").getRawValue());
		assertEquals(FONT1, values.getFont("font.menu").getRawValue());
		assertEquals("font.button", values.getFont("Button.font").getReferenceId());
		assertEquals("font.button", values.getFont("RadioButton.font").getReferenceId());
		assertEquals("font.menu", values.getFont("Menu.font").getReferenceId());
		assertEquals("font.menu", values.getFont("MenuItem.font").getReferenceId());
	}

	@Test
	public void testGroupFontUsingNonPreferredSourceWhenPreferredDoesntMatch() {
		initFont("Button.font", FONT1);
		initFont("RadioButton.font", FONT1);
		initFont("Menu.font", FONT2);
		initFont("MenuItem.font", FONT1);
		grouper.group(values);

		assertEquals(FONT1, values.getFont("font.button").getRawValue());
		assertEquals(FONT2, values.getFont("font.menu").getRawValue());
		assertEquals("font.button", values.getFont("Button.font").getReferenceId());
		assertEquals("font.button", values.getFont("RadioButton.font").getReferenceId());
		assertEquals("font.menu", values.getFont("Menu.font").getReferenceId());
		assertEquals("font.button", values.getFont("MenuItem.font").getReferenceId());
	}

	private void initColor(String id, Color color) {
		values.addColor(new ColorValue(id, color));
	}

	private void initFont(String id, Font font) {
		values.addFont(new FontValue(id, font));
	}

}
