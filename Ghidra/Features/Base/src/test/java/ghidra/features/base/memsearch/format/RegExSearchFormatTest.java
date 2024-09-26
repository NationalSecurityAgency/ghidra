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
package ghidra.features.base.memsearch.format;

import static org.junit.Assert.*;

import org.junit.Test;

import ghidra.features.base.memsearch.matcher.ByteMatcher;

public class RegExSearchFormatTest extends AbstractSearchFormatTest {
	private ByteMatcher byteMatcher;

	public RegExSearchFormatTest() {
		super(SearchFormat.REG_EX);
	}

	@Test
	public void testSimpleCase() {
		byteMatcher = format.parse("a|b", settings);

		assertTrue(byteMatcher.isValidInput());
		assertTrue(byteMatcher.isValidSearch());
		assertEquals("Reg Ex", byteMatcher.getDescription());
	}

	@Test
	public void testIncompleteCase() {
		byteMatcher = format.parse("a(", settings);
		assertTrue(byteMatcher.isValidInput());
		assertFalse(byteMatcher.isValidSearch());
		assertEquals("RegEx Pattern Error: Unclosed group", byteMatcher.getDescription());
	}

	@Test
	public void testConvertTextFromBinary() {
		assertEquals("10001000 11111111", convertText(binarySettings, "10001000 11111111"));
		assertEquals("1 0", convertText(binarySettings, "1 0"));
	}

	@Test
	public void testConvertTextFromHex() {
		assertEquals("56 12", convertText(hexSettings, "56 12"));
		assertEquals("1 0", convertText(hexSettings, "1 0"));
	}

	@Test
	public void testConvertTextFromInts() {
		assertEquals("0 22 -1 -14", convertText(int1Settings, "0 22 -1 -14"));
		assertEquals("0 22 -1 -14", convertText(int2Settings, "0 22 -1 -14"));
		assertEquals("0 22 -1 -14", convertText(int8Settings, "0 22 -1 -14"));

		assertEquals("20000000", convertText(int4Settings, "20000000"));
		assertEquals("2000000000000", convertText(int8Settings, "2000000000000"));

	}

	@Test
	public void testConvertTextFromUnsignedInts() {
		assertEquals("0 22 255", convertText(uint1Settings, "0 22 255"));
		assertEquals("0 22 65535", convertText(uint2Settings, "0 22 65535"));
		assertEquals("22 4294967295", convertText(uint4Settings, "22 4294967295"));
		assertEquals("22", convertText(uint8Settings, "22"));
		assertEquals("18446744073709551615",
			convertText(uint8Settings, "18446744073709551615"));
	}

	@Test
	public void testConvertTextFromDoubles() {
		assertEquals("1.234", convertText(doubleSettings, "1.234"));
	}

}
