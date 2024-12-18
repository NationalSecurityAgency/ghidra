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

public class BinarySearchFormatTest extends AbstractSearchFormatTest {
	public BinarySearchFormatTest() {
		super(SearchFormat.BINARY);
	}

	@Test
	public void testSimpleCase() {
		matcher = parse("0 1 10001000 11111111");

		assertBytes(0, 1, 0x88, 0xff);
		assertMask(0xff, 0xff, 0xff, 0xff);
	}

	@Test
	public void testWildCards() {
		matcher = parse("111.111?");
		assertBytes(0xee);
		assertMask(0xee);

		matcher = parse("....0001");
		assertBytes(0x01);
		assertMask(0x0f);
	}

	@Test
	public void testGroupTooBig() {
		ByteMatcher bad = format.parse("111111111", settings);
		assertFalse(bad.isValidInput());
		assertEquals("Max group size exceeded. Enter <space> to add more.", bad.getDescription());
	}

	@Test
	public void testInvalidChars() {
		ByteMatcher bad = format.parse("012", settings);
		assertFalse(bad.isValidInput());
		assertEquals("Invalid character", bad.getDescription());
	}

	@Test
	public void testConvertTextFromHex() {
		assertEquals("10001000 11111111", convertText(hexSettings, "88 ff"));
		assertEquals("00000001 00000000", convertText(hexSettings, "1 0"));
	}

	@Test
	public void testConvertTextFromSignedInts() {

		assertEquals("00010110 11111111 00000000", convertText(int1Settings, "22 -1 0"));
		assertEquals("00000000 00000001", convertText(int2Settings, "1"));
		assertEquals("11111111 11111111", convertText(int2Settings, "-1"));
		assertEquals("00000000 00000000 00000000 00000001", convertText(int4Settings, "1"));
		assertEquals("11111111 11111111 11111111 11111111", convertText(int4Settings, "-1"));
		assertEquals("00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000001",
			convertText(int8Settings, "1"));
		assertEquals("11111111 11111111 11111111 11111111 11111111 11111111 11111111 11111111",
			convertText(int8Settings, "-1"));
	}

	@Test
	public void testConvertTextFromUnsignedInts() {

		assertEquals("00010110 11111111 00000000", convertText(uint1Settings, "22 255 0"));
		assertEquals("00000000 00000001", convertText(uint2Settings, "1"));
		assertEquals("11111111 11111111", convertText(uint2Settings, "65535"));
		assertEquals("00000000 00000000 00000000 00000001", convertText(uint4Settings, "1"));
		assertEquals("11111111 11111111 11111111 11111111",
			convertText(uint4Settings, "4294967295"));
		assertEquals("00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000001",
			convertText(uint8Settings, "1"));
		assertEquals("11111111 11111111 11111111 11111111 11111111 11111111 11111111 11111111",
			convertText(uint8Settings, "18446744073709551615"));
	}

	@Test
	public void testConvertTextFromFloats() {
		assertEquals("00111111 10011101 11110011 10110110",
			convertText(floatSettings, "1.234"));
		assertEquals("00111111 11110011 10111110 01110110 11001000 10110100 00111001 01011000",
			convertText(doubleSettings, "1.234"));
	}

	@Test
	public void testConvertTextFromString() {
		assertEquals("", convertText(stringSettings, "Hey"));
		assertEquals("", convertText(stringSettings, "56 ab"));
		assertEquals("0001", convertText(stringSettings, "0001"));
		assertEquals("", convertText(regExSettings, "B*B"));
		assertEquals("", convertText(regExSettings, "56 ab"));
		assertEquals("0001", convertText(regExSettings, "0001"));
	}

}
