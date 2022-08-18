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

import org.junit.Before;
import org.junit.Test;

public class ColorValueTest {

	private GThemeValueMap values;

	@Before
	public void setup() {
		values = new GThemeValueMap();
	}

	@Test
	public void testDirectValue() {
		ColorValue value = new ColorValue("color.test", Color.RED);
		values.addColor(value);

		assertEquals("color.test", value.getId());
		assertEquals(Color.RED, value.getRawValue());
		assertNull(value.getReferenceId());
		assertEquals(Color.RED, value.get(values));
	}

	@Test
	public void testIndirectValue() {
		values.addColor(new ColorValue("color.parent", Color.RED));
		ColorValue value = new ColorValue("color.test", "color.parent");
		values.addColor(value);

		assertEquals("color.test", value.getId());
		assertNull(value.getRawValue());
		assertEquals("color.parent", value.getReferenceId());
		assertEquals(Color.RED, value.get(values));
	}

	@Test
	public void TestIndirectMultiHopValue() {
		values.addColor(new ColorValue("color.grandparent", Color.RED));
		values.addColor(new ColorValue("color.parent", "color.grandparent"));
		ColorValue value = new ColorValue("color.test", "color.parent");
		values.addColor(value);

		assertNull(value.getRawValue());
		assertEquals("color.parent", value.getReferenceId());
		assertEquals(Color.RED, value.get(values));
	}

	@Test
	public void TestUnresolvedIndirectValue() {
		ColorValue value = new ColorValue("color.test", "color.parent");
		values.addColor(value);

		assertNull(value.getRawValue());
		assertEquals("color.parent", value.getReferenceId());
		assertEquals(ColorValue.LAST_RESORT_DEFAULT, value.get(values));
	}

	@Test
	public void testReferenceLoop() {
		values.addColor(new ColorValue("color.grandparent", "color.test"));
		values.addColor(new ColorValue("color.parent", "color.grandparent"));
		ColorValue value = new ColorValue("color.test", "color.parent");
		assertEquals(ColorValue.LAST_RESORT_DEFAULT, value.get(values));
	}

	@Test
	public void testToExernalId() {
		ColorValue value = new ColorValue("color.test", Color.BLUE);
		assertEquals("color.test", value.toExternalId("color.test"));
		assertEquals("[color]foo.bar", value.toExternalId("foo.bar"));
	}

	@Test
	public void testFromExternalId() {
		ColorValue value = new ColorValue("color.test", Color.BLUE);
		assertEquals("color.test", value.fromExternalId("color.test"));
		assertEquals("foo.bar", value.fromExternalId("[color]foo.bar"));
	}

	@Test
	public void testIsColorKey() {
		assertTrue(ColorValue.isColorKey("color.a.b.c"));
		assertTrue(ColorValue.isColorKey("[color]a.b.c"));
		assertFalse(ColorValue.isColorKey("a.b.c"));
	}

	@Test
	public void testInheritsFrom() {
		ColorValue grandParent = new ColorValue("color.grandparent", Color.RED);
		values.addColor(grandParent);
		ColorValue parent = new ColorValue("color.parent", "color.grandparent");
		values.addColor(parent);
		ColorValue value = new ColorValue("color.test", "color.parent");
		values.addColor(value);

		assertTrue(value.inheritsFrom("color.parent", values));
		assertTrue(value.inheritsFrom("color.grandparent", values));
		assertTrue(parent.inheritsFrom("color.grandparent", values));

		assertFalse(value.inheritsFrom("color.test", values));
		assertFalse(parent.inheritsFrom("color.test", values));
		assertFalse(grandParent.inheritsFrom("color.test", values));
	}

	@Test
	public void testCreatingValueFromGColor() {
		ColorValue parent = new ColorValue("color.parent", Color.RED);
		values.addColor(parent);
		Color gColor = new GColor("color.parent");
		ColorValue value = new ColorValue("color.value", gColor);
		assertEquals("color.parent", value.getReferenceId());
		assertNull(value.getRawValue());
	}
}
