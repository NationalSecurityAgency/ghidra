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

import javax.swing.Icon;

import org.junit.Before;
import org.junit.Test;

import resources.ResourceManager;

public class ThemeEventTest {
	private static Font FONT1 = new Font("Dialog", 12, Font.PLAIN);
	private static Font FONT2 = new Font("Dialog", 14, Font.PLAIN);
	private static Icon ICON1 = ResourceManager.loadImage("images/flag.png");
	private static Icon ICON2 = ResourceManager.loadImage("images/exec.png");

	private GThemeValueMap values;

	@Before
	public void setup() {
		values = new GThemeValueMap();
	}

	@Test
	public void testIsColorChangedDirect() {
		ColorValue value = new ColorValue("color.value", Color.RED);
		values.addColor(value);
		ColorValue newValue = new ColorValue("color.value", Color.BLUE);
		values.addColor(value);

		ColorChangedThemeEvent event = new ColorChangedThemeEvent(values, newValue);
		assertTrue(event.isColorChanged("color.value"));
		assertFalse(event.isColorChanged("color.othervalue"));
	}

	@Test
	public void testIsColorChangedIndirect() {
		ColorValue parent = new ColorValue("color.parent", Color.RED);
		values.addColor(parent);
		ColorValue value = new ColorValue("color.value", "color.parent");
		values.addColor(value);

		ColorValue newValue = new ColorValue("color.parent", Color.BLUE);
		values.addColor(value);

		ColorChangedThemeEvent event = new ColorChangedThemeEvent(values, newValue);
		assertTrue(event.isColorChanged("color.parent"));
		assertTrue(event.isColorChanged("color.value"));
		assertFalse(event.isColorChanged("color.othervalue"));
	}

	@Test
	public void testIsFontChangedDirect() {
		FontValue value = new FontValue("font.value", FONT1);
		values.addFont(value);
		FontValue newValue = new FontValue("font.value", FONT2);
		values.addFont(value);

		FontChangedThemeEvent event = new FontChangedThemeEvent(values, newValue);
		assertTrue(event.isFontChanged("font.value"));
		assertFalse(event.isFontChanged("font.othervalue"));
	}

	@Test
	public void testIsFontChangedIndirect() {
		FontValue parent = new FontValue("font.parent", FONT1);
		values.addFont(parent);
		FontValue value = new FontValue("font.value", "font.parent");
		values.addFont(value);

		FontValue newValue = new FontValue("font.parent", FONT2);
		values.addFont(value);

		FontChangedThemeEvent event = new FontChangedThemeEvent(values, newValue);
		assertTrue(event.isFontChanged("font.parent"));
		assertTrue(event.isFontChanged("font.value"));
		assertFalse(event.isFontChanged("font.othervalue"));
	}

	@Test
	public void testIsIconChangedDirect() {
		IconValue value = new IconValue("ICON.value", ICON1);
		values.addIcon(value);
		IconValue newValue = new IconValue("icon.value", ICON2);
		values.addIcon(value);

		IconChangedThemeEvent event = new IconChangedThemeEvent(values, newValue);
		assertTrue(event.isIconChanged("icon.value"));
		assertFalse(event.isIconChanged("icon.othervalue"));
	}

	@Test
	public void testIsIconChangedIndirect() {
		IconValue parent = new IconValue("icon.parent", ICON1);
		values.addIcon(parent);
		IconValue value = new IconValue("icon.value", "icon.parent");
		values.addIcon(value);

		IconValue newValue = new IconValue("icon.parent", ICON2);
		values.addIcon(value);

		IconChangedThemeEvent event = new IconChangedThemeEvent(values, newValue);
		assertTrue(event.isIconChanged("icon.parent"));
		assertTrue(event.isIconChanged("icon.value"));
		assertFalse(event.isIconChanged("icon.othervalue"));
	}

}
