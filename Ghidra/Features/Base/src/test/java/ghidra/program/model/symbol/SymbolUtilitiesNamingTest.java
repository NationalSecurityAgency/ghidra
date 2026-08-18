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
package ghidra.program.model.symbol;

import static ghidra.program.model.symbol.SymbolUtilities.*;
import static org.junit.Assert.*;

import org.junit.Test;

import ghidra.util.StringUtilities;

public class SymbolUtilitiesNamingTest {

	@Test
	public void testGoodStringObjectPassthru() {
		String s = "testsym";
		assertSame(s, replaceInvalidChars(s, OMIT_BAD_CHARS));

		s = "test sym";
		assertNotSame(s, replaceInvalidChars(s, OMIT_BAD_CHARS));
	}

	@Test
	public void testNullString() {
		assertNull(replaceInvalidChars(null, OMIT_BAD_CHARS));
		assertNull(SymbolUtilities.replaceInvalidChars(null, true));
	}

	@Test
	public void testNullChar() {
		assertEquals("testsym", replaceInvalidChars("test\0sym", OMIT_BAD_CHARS));
		assertTrue(SymbolUtilities.isInvalidCodePoint(0));
	}

	@Test
	public void testBOMChar() {
		assertEquals("testsym",
			replaceInvalidChars(
				"test" + Character.toString(StringUtilities.UNICODE_BE_BYTE_ORDER_MARK) + "sym",
				OMIT_BAD_CHARS));
	}

	@Test
	public void testRTLOChar() {
		assertEquals("testsym", replaceInvalidChars("test\u202esym", OMIT_BAD_CHARS));
	}

	@Test
	public void testBadCharRemoval() {
		assertEquals("testsym", replaceInvalidChars("test sym", OMIT_BAD_CHARS));
		assertEquals("testsym", replaceInvalidChars("test\u007fsym", OMIT_BAD_CHARS));
		assertEquals("testsym", replaceInvalidChars("test\tsym", OMIT_BAD_CHARS));

		assertEquals("test\uaabbsym", replaceInvalidChars("test\uaabbsym", OMIT_BAD_CHARS));
	}

	@Test
	public void testBadCharReplaceWithUnderscores() {
		assertEquals("test_sym", replaceInvalidChars("test sym", USE_UNDERSCORES));
		assertEquals("test_sym", replaceInvalidChars("test\u007fsym", USE_UNDERSCORES));
		assertEquals("test_sym", replaceInvalidChars("test\tsym", USE_UNDERSCORES));
	}

	@Test
	public void testBadCharReplaceWithCustom() {
		assertEquals("test_4_sym",
			replaceInvalidChars("test sym", (index, cp) -> "_" + index + "_"));
	}

	@Test
	public void testAsciiRange() {
		assertEquals(
			"!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~",
			replaceInvalidChars(
				"!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~",
				OMIT_BAD_CHARS));
	}

}
