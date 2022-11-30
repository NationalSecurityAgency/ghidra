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

import org.junit.Test;

public class FontModifierTest {
	private Font baseFont = new Font("Dialog", Font.PLAIN, 12);

	@Test
	public void testNoModifiers() throws ParseException {
		assertNull(FontModifier.parse(""));
	}

	@Test
	public void testSizeModifier() throws ParseException {
		FontModifier modifier = FontModifier.parse("[6]");
		assertNotNull(modifier);
		Font newFont = modifier.modify(baseFont);
		assertEquals(6, newFont.getSize());
		assertEquals(baseFont.getName(), newFont.getName());
		assertEquals(baseFont.getStyle(), newFont.getStyle());
	}

	@Test
	public void testStyleModifierPlain() throws ParseException {
		FontModifier modifier = FontModifier.parse("[plain]");
		assertNotNull(modifier);
		Font newFont = modifier.modify(baseFont);
		assertEquals(Font.PLAIN, newFont.getStyle());
		assertEquals(baseFont.getName(), newFont.getName());
		assertEquals(baseFont.getSize(), newFont.getSize());
	}

	@Test
	public void testStyleModifierBold() throws ParseException {
		FontModifier modifier = FontModifier.parse("[bold]");
		assertNotNull(modifier);
		Font newFont = modifier.modify(baseFont);
		assertEquals(Font.BOLD, newFont.getStyle());
		assertEquals(baseFont.getName(), newFont.getName());
		assertEquals(baseFont.getSize(), newFont.getSize());
	}

	@Test
	public void testStyleModifierItalic() throws ParseException {
		FontModifier modifier = FontModifier.parse("[ITALIC]");
		assertNotNull(modifier);
		Font newFont = modifier.modify(baseFont);
		assertEquals(Font.ITALIC, newFont.getStyle());
		assertEquals(baseFont.getName(), newFont.getName());
		assertEquals(baseFont.getSize(), newFont.getSize());
	}

	@Test
	public void testStyleModifierBoldItalic() throws ParseException {
		FontModifier modifier = FontModifier.parse("[BOLDitalic]");
		assertNotNull(modifier);
		Font newFont = modifier.modify(baseFont);
		assertEquals(Font.ITALIC | Font.BOLD, newFont.getStyle());
		assertEquals(baseFont.getName(), newFont.getName());
		assertEquals(baseFont.getSize(), newFont.getSize());
	}

	@Test
	public void testStyleModifierBoldItalic2() throws ParseException {
		FontModifier modifier = FontModifier.parse("[BOLD][italic]");
		assertNotNull(modifier);
		Font newFont = modifier.modify(baseFont);
		assertEquals(Font.ITALIC | Font.BOLD, newFont.getStyle());
		assertEquals(baseFont.getName(), newFont.getName());
		assertEquals(baseFont.getSize(), newFont.getSize());
	}

	@Test
	public void testFamilyModification() throws ParseException {
		FontModifier modifier = FontModifier.parse("[monospaced]");
		assertNotNull(modifier);
		Font newFont = modifier.modify(baseFont);
		assertEquals("Monospaced", newFont.getFamily());
		assertEquals(baseFont.getStyle(), newFont.getStyle());
		assertEquals(baseFont.getSize(), newFont.getSize());
	}

	@Test
	public void testSizeAndStyleModification() throws ParseException {
		FontModifier modifier = FontModifier.parse("[16][bold]");
		assertNotNull(modifier);
		Font newFont = modifier.modify(baseFont);
		assertEquals(baseFont.getName(), newFont.getFamily());
		assertEquals(Font.BOLD, newFont.getStyle());
		assertEquals(16, newFont.getSize());

	}

	@Test
	public void testFamilyModificationMultiple() {
		try {
			FontModifier.parse("[monospaced][courier]");
			fail("Expecected Exception");
		}
		catch (ParseException e) {
			// expected
		}
	}

	@Test
	public void testStyleModifierIncompatableStyles() {
		try {
			FontModifier.parse("[plain][italic]");
			fail("Expected IllegalStateException");
		}
		catch (ParseException e) {
			// expected
		}
	}

	@Test
	public void testInvalidModifierString() {
		try {
			FontModifier.parse("asdfasf");
			fail("Expected IllegalArgumentExcption");
		}
		catch (ParseException e) {
			// expected
		}
	}

	@Test
	public void testInvalidModifierString2() {
		try {
			FontModifier.parse("[12]aa[13]");
			fail("Expected IllegalArgumentExcption");
		}
		catch (ParseException e) {
			// expected
		}
	}

	@Test
	public void testInvalidModifierString3() {
		try {
			FontModifier.parse("[12]aa13]");
			fail("Expected IllegalArgumentExcption");
		}
		catch (ParseException e) {
			// expected
		}
	}

	@Test
	public void testInvalidModifierString4() {
		try {
			FontModifier.parse("[12][plain]sz");
			fail("Expected IllegalArgumentExcption");
		}
		catch (ParseException e) {
			// expected
		}
	}

	@Test
	public void testGetSerializationString() {
		//@formatter:off
		assertEquals("[12]", new FontModifier(null, null, 12).getSerializationString());
		assertEquals("[plain]", new FontModifier(null, Font.PLAIN, null).getSerializationString());
		assertEquals("[bold]", new FontModifier(null, Font.BOLD, null).getSerializationString());
		assertEquals("[italic]", new FontModifier(null, Font.ITALIC, null).getSerializationString());
		assertEquals("[bold][italic]", new FontModifier(null, Font.BOLD | Font.ITALIC, null).getSerializationString());
		assertEquals("[Monospaced]",new FontModifier("Monospaced", null, null).getSerializationString());
		assertEquals("[Monospaced][12][plain]",new FontModifier("Monospaced", Font.PLAIN, 12).getSerializationString());
		//@formatter:on
	}
}
