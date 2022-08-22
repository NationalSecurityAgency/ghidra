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

import javax.swing.Icon;

import org.junit.Before;
import org.junit.Test;

import resources.ResourceManager;

public class IconValueTest {
	private static Icon ICON1 = ResourceManager.getDefaultIcon();
	private GThemeValueMap values;

	@Before
	public void setup() {
		values = new GThemeValueMap();
	}

	@Test
	public void testDirectValue() {
		IconValue value = new IconValue("icon.test", ICON1);
		values.addIcon(value);

		assertEquals("icon.test", value.getId());
		assertEquals(ICON1, value.getRawValue());
		assertNull(value.getReferenceId());
		assertEquals(ICON1, value.get(values));
	}

	@Test
	public void testIndirectValue() {
		values.addIcon(new IconValue("icon.parent", ICON1));
		IconValue value = new IconValue("icon.test", "icon.parent");
		values.addIcon(value);

		assertEquals("icon.test", value.getId());
		assertNull(value.getRawValue());
		assertEquals("icon.parent", value.getReferenceId());
		assertEquals(ICON1, value.get(values));
	}

	@Test
	public void TestIndirectMultiHopValue() {
		values.addIcon(new IconValue("icon.grandparent", ICON1));
		values.addIcon(new IconValue("icon.parent", "icon.grandparent"));
		IconValue value = new IconValue("icon.test", "icon.parent");
		values.addIcon(value);

		assertNull(value.getRawValue());
		assertEquals("icon.parent", value.getReferenceId());
		assertEquals(ICON1, value.get(values));
	}

	@Test
	public void TestUnresolvedIndirectValue() {
		IconValue value = new IconValue("icon.test", "icon.parent");
		values.addIcon(value);

		assertNull(value.getRawValue());
		assertEquals("icon.parent", value.getReferenceId());
		assertEquals(IconValue.LAST_RESORT_DEFAULT, value.get(values));
	}

	@Test
	public void testReferenceLoop() {
		values.addIcon(new IconValue("icon.grandparent", "icon.test"));
		values.addIcon(new IconValue("icon.parent", "icon.grandparent"));
		IconValue value = new IconValue("icon.test", "icon.parent");
		assertEquals(IconValue.LAST_RESORT_DEFAULT, value.get(values));
	}

	@Test
	public void testGetSerializationString() {
		IconValue value = new IconValue("icon.test", ICON1);
		assertEquals("icon.test = images/core.png", value.getSerializationString());

		value = new IconValue("foo.bar", ICON1);
		assertEquals("[icon]foo.bar = images/core.png", value.getSerializationString());

		value = new IconValue("icon.test", "xyz.abc");
		assertEquals("icon.test = [icon]xyz.abc", value.getSerializationString());
	}

	@Test
	public void testParse() {
		IconValue value = IconValue.parse("icon.test", "images/core.png");
		assertEquals("icon.test", value.getId());
		assertEquals(ICON1, value.getRawValue());
		assertEquals(null, value.getReferenceId());

		value = IconValue.parse("[icon]foo.bar", "images/core.png");
		assertEquals("foo.bar", value.getId());
		assertEquals(ICON1, value.getRawValue());
		assertEquals(null, value.getReferenceId());

		value = IconValue.parse("icon.test", "[icon]xyz.abc");
		assertEquals("icon.test", value.getId());
		assertEquals(null, value.getRawValue());
		assertEquals("xyz.abc", value.getReferenceId());
	}

	@Test
	public void testIsIconKey() {
		assertTrue(IconValue.isIconKey("icon.a.b.c"));
		assertTrue(IconValue.isIconKey("[icon]a.b.c"));
		assertFalse(IconValue.isIconKey("a.b.c"));
	}

	@Test
	public void testInheritsFrom() {
		IconValue grandParent = new IconValue("icon.grandparent", ICON1);
		values.addIcon(grandParent);
		IconValue parent = new IconValue("icon.parent", "icon.grandparent");
		values.addIcon(parent);
		IconValue value = new IconValue("icon.test", "icon.parent");
		values.addIcon(value);

		assertTrue(value.inheritsFrom("icon.parent", values));
		assertTrue(value.inheritsFrom("icon.grandparent", values));
		assertTrue(parent.inheritsFrom("icon.grandparent", values));

		assertFalse(value.inheritsFrom("icon.test", values));
		assertFalse(parent.inheritsFrom("icon.test", values));
		assertFalse(grandParent.inheritsFrom("icon.test", values));
	}

	@Test
	public void testCreatingValueFromGIcon() {
		IconValue parent = new IconValue("icon.parent", ICON1);
		values.addIcon(parent);
		Icon gIcon = new GIcon("icon.parent");
		IconValue value = new IconValue("icon.value", gIcon);
		assertEquals("icon.parent", value.getReferenceId());
		assertNull(value.getRawValue());
	}
}
