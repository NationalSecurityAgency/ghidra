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

import java.awt.Font;
import java.text.ParseException;

import org.junit.Before;
import org.junit.Test;

public class FontValueTest {
	private static Font FONT = new Font("Dialog", Font.PLAIN, 12);
	private GThemeValueMap values;

	@Before
	public void setup() {
		values = new GThemeValueMap();
	}

	@Test
	public void testDirectValue() {
		FontValue value = new FontValue("font.test", FONT);
		values.addFont(value);

		assertEquals("font.test", value.getId());
		assertEquals(FONT, value.getRawValue());
		assertNull(value.getReferenceId());
		assertEquals(FONT, value.get(values));
	}

	@Test
	public void testIndirectValue() {
		values.addFont(new FontValue("font.parent", FONT));
		FontValue value = new FontValue("font.test", "font.parent");
		values.addFont(value);

		assertEquals("font.test", value.getId());
		assertNull(value.getRawValue());
		assertEquals("font.parent", value.getReferenceId());
		assertEquals(FONT, value.get(values));
	}

	@Test
	public void TestIndirectMultiHopValue() {
		values.addFont(new FontValue("font.grandparent", FONT));
		values.addFont(new FontValue("font.parent", "font.grandparent"));
		FontValue value = new FontValue("font.test", "font.parent");
		values.addFont(value);

		assertNull(value.getRawValue());
		assertEquals("font.parent", value.getReferenceId());
		assertEquals(FONT, value.get(values));
	}

	@Test
	public void TestUnresolvedIndirectValue() {
		FontValue value = new FontValue("font.test", "font.parent");
		values.addFont(value);

		assertNull(value.getRawValue());
		assertEquals("font.parent", value.getReferenceId());
		assertEquals(FontValue.LAST_RESORT_DEFAULT, value.get(values));
	}

	@Test
	public void testReferenceLoop() {
		values.addFont(new FontValue("font.grandparent", "font.test"));
		values.addFont(new FontValue("font.parent", "font.grandparent"));
		FontValue value = new FontValue("font.test", "font.parent");
		assertEquals(FontValue.LAST_RESORT_DEFAULT, value.get(values));
	}

	@Test
	public void testGetSerializationString() {
		FontValue value = new FontValue("font.test", FONT);
		assertEquals("font.test = Dialog-PLAIN-12", value.getSerializationString());

		value = new FontValue("foo.bar", FONT);
		assertEquals("[font]foo.bar = Dialog-PLAIN-12", value.getSerializationString());

		value = new FontValue("font.test", "xyz.abc");
		assertEquals("font.test = [font]xyz.abc", value.getSerializationString());
	}

	@Test
	public void testParse() throws ParseException {
		FontValue value = FontValue.parse("font.test", "Dialog-PLAIN-12");
		assertEquals("font.test", value.getId());
		assertEquals(FONT, value.getRawValue());
		assertEquals(null, value.getReferenceId());

		value = FontValue.parse("[font]foo.bar", "Dialog-PLAIN-12");
		assertEquals("foo.bar", value.getId());
		assertEquals(FONT, value.getRawValue());
		assertEquals(null, value.getReferenceId());

		value = FontValue.parse("font.test", "[font]xyz.abc");
		assertEquals("font.test", value.getId());
		assertEquals(null, value.getRawValue());
		assertEquals("xyz.abc", value.getReferenceId());
	}

	@Test
	public void testIsFontKey() {
		assertTrue(FontValue.isFontKey("font.a.b.c"));
		assertTrue(FontValue.isFontKey("[font]a.b.c"));
		assertFalse(FontValue.isFontKey("a.b.c"));
	}

	@Test
	public void testInheritsFrom() {
		FontValue grandParent = new FontValue("font.grandparent", FONT);
		values.addFont(grandParent);
		FontValue parent = new FontValue("font.parent", "font.grandparent");
		values.addFont(parent);
		FontValue value = new FontValue("font.test", "font.parent");
		values.addFont(value);

		assertTrue(value.inheritsFrom("font.parent", values));
		assertTrue(value.inheritsFrom("font.grandparent", values));
		assertTrue(parent.inheritsFrom("font.grandparent", values));

		assertFalse(value.inheritsFrom("font.test", values));
		assertFalse(parent.inheritsFrom("font.test", values));
		assertFalse(grandParent.inheritsFrom("font.test", values));
	}

}
