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

import static ghidra.util.WebColors.*;
import static org.junit.Assert.*;

import java.awt.Color;
import java.awt.Font;
import java.io.IOException;
import java.io.StringReader;
import java.util.List;

import org.junit.Before;
import org.junit.Test;

public class ThemePropertyFileReaderTest {

	@Before
	public void setUp() {
	}

	@Test
	public void testDefaults() throws IOException {
		//@formatter:off
		ThemePropertyFileReader reader = new ThemePropertyFileReader("test", new StringReader(String.join("\n", 
			"[Defaults]", 
			"  color.b.1    = white",					// WHITE
			"  color.b.2    = #ff0000",					// RED
			"  color.b.3    = 0x008000",				// GREEN
			"  color.b.4    = 0xff000080",				// half alpha red
			"  color.b.5 	= rgb(0,0,255)",			// BLUE
			"  color.b.6 	= rgba(255,0,0,0.5)",		// half alpha red
			"  color.b.7    = color.b.1",				// ref
			"  font.a.8     = dialog-PLAIN-14",
			"  font.a.9     = font.a.8",
			"  icon.a.10     = foo.png",
			"  icon.a.11     = icon.a.10",
			"")));
		//@formatter:on

		Color halfAlphaRed = new Color(0x80ff0000, true);
		GThemeValueMap values = reader.getDefaultValues();
		assertEquals(11, values.size());

		assertEquals(WHITE, getColorOrRef(values, "color.b.1"));
		assertEquals(RED, getColorOrRef(values, "color.b.2"));
		assertEquals(GREEN, getColorOrRef(values, "color.b.3"));
		assertEquals(halfAlphaRed, getColorOrRef(values, "color.b.4"));
		assertEquals(BLUE, getColorOrRef(values, "color.b.5"));
		assertEquals(halfAlphaRed, getColorOrRef(values, "color.b.6"));
		assertEquals("color.b.1", getColorOrRef(values, "color.b.7"));

		assertEquals(new Font("dialog", Font.PLAIN, 14), getFontOrRef(values, "font.a.8"));
		assertEquals("font.a.8", getFontOrRef(values, "font.a.9"));

		assertEquals("foo.png", getIconOrRef(values, "icon.a.10"));
		assertEquals("icon.a.10", getIconOrRef(values, "icon.a.11"));

	}

	@Test
	public void testDarkDefaults() throws IOException {
		//@formatter:off
		ThemePropertyFileReader reader = new ThemePropertyFileReader("test", new StringReader(String.join("\n", 
			"[Dark Defaults]", 
			"  color.b.1    = white",					// WHITE
			"  color.b.2    = #ff0000",					// RED
			"  color.b.3    = 0x008000",				// GREEN
			"  color.b.4    = 0xff000080",				// half alpha red
			"  color.b.5 	= rgb(0,0,255)",			// BLUE
			"  color.b.6 	= rgba(255,0,0,0.5)",		// half alpha red
			"  color.b.7    = color.b.1",				// ref
			"")));
		//@formatter:on

		Color halfAlphaRed = new Color(0x80ff0000, true);
		GThemeValueMap values = reader.getDarkDefaultValues();
		assertEquals(7, values.size());

		assertEquals(WHITE, getColorOrRef(values, "color.b.1"));
		assertEquals(RED, getColorOrRef(values, "color.b.2"));
		assertEquals(GREEN, getColorOrRef(values, "color.b.3"));
		assertEquals(halfAlphaRed, getColorOrRef(values, "color.b.4"));
		assertEquals(BLUE, getColorOrRef(values, "color.b.5"));
		assertEquals(halfAlphaRed, getColorOrRef(values, "color.b.6"));
		assertEquals("color.b.1", getColorOrRef(values, "color.b.7"));
	}

	@Test
	public void testBothDefaultsAndDarkDefaultsInSameFile() throws IOException {
		//@formatter:off
		ThemePropertyFileReader reader = new ThemePropertyFileReader("test", new StringReader(String.join("\n", 
			"[Defaults]", 
			"  color.b.1    = white",					// WHITE
			"  color.b.2    = #ff0000",					// RED
			"[Dark Defaults]", 
			"  color.b.1    = black",					// BLACK
			"  color.b.2    = #0000ff",					// BLUE
			"")));
		//@formatter:on

		GThemeValueMap values = reader.getDefaultValues();
		assertEquals(2, values.size());

		GThemeValueMap darkValues = reader.getDarkDefaultValues();
		assertEquals(2, values.size());

		assertEquals(WHITE, getColorOrRef(values, "color.b.1"));
		assertEquals(RED, getColorOrRef(values, "color.b.2"));
		assertEquals(BLACK, getColorOrRef(darkValues, "color.b.1"));
		assertEquals(BLUE, getColorOrRef(darkValues, "color.b.2"));
	}

	@Test
	public void testParseColorError() throws IOException {
		//@formatter:off
		ThemePropertyFileReader reader = new ThemePropertyFileReader("test", new StringReader(String.join("\n", 
			"[Defaults]", 
			"  color.b.1    = white",					// WHITE
			"  color.b.2    = sdfsdf",					// RED
			"")));
		//@formatter:on
		List<String> errors = reader.getErrors();
		assertEquals(1, errors.size());
		assertEquals("Error parsing file \"test\" at line: 3, Could not parse Color: sdfsdf",
			errors.get(0));

	}

	private Object getColorOrRef(GThemeValueMap values, String id) {
		ColorValue color = values.getColor(id);
		if (color.getReferenceId() != null) {
			return color.getReferenceId();
		}
		return color.getRawValue();
	}

	private Object getFontOrRef(GThemeValueMap values, String id) {
		FontValue font = values.getFont(id);
		if (font.getReferenceId() != null) {
			return font.getReferenceId();
		}
		return font.getRawValue();
	}

	private Object getIconOrRef(GThemeValueMap values, String id) {
		IconValue icon = values.getIcon(id);
		if (icon.getReferenceId() != null) {
			return icon.getReferenceId();
		}
		return icon.getRawValue();
	}
}
