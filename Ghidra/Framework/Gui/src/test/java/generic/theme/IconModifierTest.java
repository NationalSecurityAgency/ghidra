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

import java.awt.Dimension;
import java.awt.Point;
import java.text.ParseException;

import javax.swing.Icon;

import org.junit.Test;

import resources.MultiIcon;
import resources.ResourceManager;
import resources.icons.RotateIcon;
import resources.icons.TranslateIcon;

public class IconModifierTest {
	private Icon baseIcon = ResourceManager.getDefaultIcon();
	private GThemeValueMap values = new GThemeValueMap();

	@Test
	public void testNoModifiers() throws Exception {
		assertNull(IconModifier.parse(""));
	}

	@Test
	public void testSizeModifier() throws Exception {
		IconModifier modifier = IconModifier.parse("[size(7,13)]");
		Icon modifiedIcon = modifier.modify(baseIcon, values);
		assertEquals(7, modifiedIcon.getIconWidth());
		assertEquals(13, modifiedIcon.getIconHeight());
	}

	@Test
	public void testSizeModifier2() throws Exception {
		IconModifier modifier = IconModifier.parse("[SIZE(7,13)]");
		Icon modifiedIcon = modifier.modify(baseIcon, values);
		assertEquals(7, modifiedIcon.getIconWidth());
		assertEquals(13, modifiedIcon.getIconHeight());
	}

	@Test
	public void testMoveModifier() throws Exception {
		IconModifier modifier = IconModifier.parse("[move(4, 3)]");
		Icon modifiedIcon = modifier.modify(baseIcon, values);
		assertTrue(modifiedIcon instanceof TranslateIcon);
		TranslateIcon translateIcon = (TranslateIcon) modifiedIcon;

		assertEquals(4, translateIcon.getX());
		assertEquals(3, translateIcon.getY());
	}

	@Test
	public void testRotateModifier() throws Exception {
		IconModifier modifier = IconModifier.parse("[rotate(90)]");
		Icon modifiedIcon = modifier.modify(baseIcon, values);
		assertTrue(modifiedIcon instanceof RotateIcon);
		RotateIcon rotateIcon = (RotateIcon) modifiedIcon;

		assertEquals(90, rotateIcon.getRotation());
	}

	@Test
	public void testDisabledModifier() throws Exception {
		IconModifier modifier = IconModifier.parse("[disabled]");
		Icon modifiedIcon = modifier.modify(baseIcon, values);
		assertNotEquals(baseIcon, modifiedIcon);
	}

	@Test
	public void testMirrorModifier() throws Exception {
		IconModifier modifier = IconModifier.parse("[mirror]");
		Icon modifiedIcon = modifier.modify(baseIcon, values);
		assertNotEquals(baseIcon, modifiedIcon);
	}

	@Test
	public void testFlipModifier() throws Exception {
		IconModifier modifier = IconModifier.parse("[flip]");
		Icon modifiedIcon = modifier.modify(baseIcon, values);
		assertNotEquals(baseIcon, modifiedIcon);
	}

	@Test
	public void testOverlayIcon() throws Exception {
		IconModifier modifier = IconModifier.parse("{images/flag.png}");
		Icon modifiedIcon = modifier.modify(baseIcon, values);
		assertTrue(modifiedIcon instanceof MultiIcon);
		MultiIcon multiIcon = (MultiIcon) modifiedIcon;
		Icon[] icons = multiIcon.getIcons();
		assertEquals(2, icons.length);
		assertEquals(baseIcon, icons[0]);
		assertEquals(ResourceManager.loadImage("images/flag.png"), icons[1]);
	}

	@Test
	public void testOverlayIcon2() throws Exception {
		IconModifier modifier =
			IconModifier.parse("[size(20,25)]{images/flag.png[size(8,9)][move(4,4)]}");
		Icon modifiedIcon = modifier.modify(baseIcon, values);
		assertTrue(modifiedIcon instanceof MultiIcon);
		MultiIcon multiIcon = (MultiIcon) modifiedIcon;
		Icon[] icons = multiIcon.getIcons();
		assertEquals(2, icons.length);
		assertEquals(20, icons[0].getIconWidth());
		assertEquals(25, icons[0].getIconHeight());
		assertEquals(8, icons[1].getIconWidth());
		assertEquals(9, icons[1].getIconHeight());
	}

	@Test
	public void testInvalidModifierString() {
		try {
			IconModifier.parse("dasdf");
			fail("Expected IllegalArgumentExcption");
		}
		catch (ParseException e) {
			// expected
		}
	}

	@Test
	public void testInvalidModifierString2() {
		try {
			IconModifier.parse("disabledx");
			fail("Expected IllegalArgumentExcption");
		}
		catch (ParseException e) {
			// expected
		}
	}

	@Test
	public void testInvalidModifierString3() {
		try {
			IconModifier.parse("[size(13,14,13)]");
			fail("Expected IllegalArgumentExcption");
		}
		catch (ParseException e) {
			// expected
		}
	}

	@Test
	public void testInvalidModifierString4() {
		try {
			IconModifier.parse("[size(14,12]");
			fail("Expected IllegalArgumentExcption");
		}
		catch (ParseException e) {
			// expected
		}
	}

	@Test
	public void testInvalidModifierString5() {
		try {
			IconModifier.parse("[size(14)]");
			fail("Expected IllegalArgumentExcption");
		}
		catch (ParseException e) {
			// expected
		}
	}

	@Test
	public void testInvalidModifierString6() {
		try {
			IconModifier.parse("[size(10,10)]move(3,4)]");
			fail("Expected IllegalArgumentExcption");
		}
		catch (ParseException e) {
			// expected
		}
	}

	@Test
	public void testGetSerializationString() {
		//@formatter:off
		assertEquals("[size(5,9)]", new IconModifier(new Dimension(5,9), null, null, false, false, false).getSerializationString());
		assertEquals("[move(8,7)]", new IconModifier(null, new Point(8,7), null,false, false, false).getSerializationString());
		assertEquals("[disabled]", new IconModifier(null, null, null, true, false, false).getSerializationString());
		assertEquals("[size(5,0)][move(8,7)][disabled]", new IconModifier(new Dimension(5,0), new Point(8,7), null, true, false, false).getSerializationString());
		assertEquals("[rotate(90)]", new IconModifier(null, null, 90, false, false, false).getSerializationString());
		assertEquals("[mirror]", new IconModifier(null, null, null, false, true, false).getSerializationString());
		assertEquals("[flip]", new IconModifier(null, null, null, false, false, true).getSerializationString());
		//@formatter:on
	}
}
