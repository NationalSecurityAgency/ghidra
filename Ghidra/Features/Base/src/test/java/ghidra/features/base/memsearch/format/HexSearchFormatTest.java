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

public class HexSearchFormatTest extends AbstractSearchFormatTest {

	public HexSearchFormatTest() {
		super(SearchFormat.HEX);
	}

	@Test
	public void testSimpleLowerCase() {
		matcher = parse("1 02 3 aa");

		assertBytes(1, 2, 3, 0xaa);
		assertMask(0xff, 0xff, 0xff, 0xff);
	}

	@Test
	public void testSimpleUpperCase() {
		matcher = parse("1 02 3 AA");

		assertBytes(1, 2, 3, 0xaa);
		assertMask(0xff, 0xff, 0xff, 0xff);
	}

	@Test
	public void testSimpleWildCardOneDigit() {
		matcher = parse("1 . 3");
		assertBytes(1, 0, 3);
		assertMask(0xff, 0, 0xff);

		matcher = parse("1 ? 3");
		assertBytes(1, 0, 3);
		assertMask(0xff, 0, 0xff);
	}

	@Test
	public void testSimpleWildCardTwoDigit() {
		matcher = parse("1 .. 3");
		assertBytes(1, 0, 3);
		assertMask(0xff, 0, 0xff);

		matcher = parse("1 ?? 3");
		assertBytes(1, 0, 3);
		assertMask(0xff, 0, 0xff);

		matcher = parse("1 ?. 3");
		assertBytes(1, 0, 3);
		assertMask(0xff, 0, 0xff);
	}

	@Test
	public void testGroupBigEndian() {
		settings = settings.withBigEndian(true);

		matcher = parse("1234");
		assertBytes(0x12, 0x34);
		assertMask(0xff, 0xff);

		matcher = parse("12345678");
		assertBytes(0x12, 0x34, 0x56, 0x78);
		assertMask(0xff, 0xff, 0xff, 0xff);

		matcher = parse("123456789abcdef0");
		assertBytes(0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0);
		assertMask(0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
	}

	@Test
	public void testOddGroupSizeBigEndian() {
		settings = settings.withBigEndian(true);

		matcher = parse("123456");
		assertBytes(0x12, 0x34, 0x56);
		assertMask(0xff, 0xff, 0xff);

		matcher = parse("123456789abcde");
		assertBytes(0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde);
		assertMask(0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
	}

	@Test
	public void testGroupLittleEndian() {
		settings = settings.withBigEndian(false);

		matcher = parse("1234");
		assertBytes(0x34, 0x12);
		assertMask(0xff, 0xff);

		matcher = parse("12345678");
		assertBytes(0x78, 0x56, 0x34, 0x12);
		assertMask(0xff, 0xff, 0xff, 0xff);

		matcher = parse("123456789abcdef0");
		assertBytes(0xf0, 0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12);
		assertMask(0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
	}

	@Test
	public void testOddGroupSizeLittleEndian() {
		settings = settings.withBigEndian(false);

		matcher = parse("123456");
		assertBytes(0x56, 0x34, 0x12);
		assertMask(0xff, 0xff, 0xff);

		matcher = parse("123456789abcde");
		assertBytes(0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12);
		assertMask(0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
	}

	@Test
	public void testGroupsWithWildsBigEndian() {
		settings = settings.withBigEndian(true);
		matcher = parse("12.45.");
		assertBytes(0x12, 0x04, 0x50);
		assertMask(0xff, 0x0f, 0xf0);
	}

	@Test
	public void testGroupsWithWildsLittleEndian() {
		settings = settings.withBigEndian(false);
		matcher = parse("12.45.");
		assertBytes(0x50, 0x04, 0x12);
		assertMask(0xf0, 0x0f, 0xff);
	}

	@Test
	public void testGroupTooBig() {
		ByteMatcher bad = format.parse("0123456789abcdef0", settings);
		assertFalse(bad.isValidInput());
		assertEquals("Max group size exceeded. Enter <space> to add more.", bad.getDescription());
	}

	@Test
	public void testInvalidChars() {
		ByteMatcher bad = format.parse("01z3", settings);
		assertFalse(bad.isValidInput());
		assertEquals("Invalid character", bad.getDescription());
	}

	@Test
	public void testConvertTextFromBinary() {
		assertEquals("88 ff", convertText(binarySettings, "10001000 11111111"));
		assertEquals("01 00", convertText(binarySettings, "1 0"));
	}

	@Test
	public void testConvertTextFromSignedInts() {

		assertEquals("00 16 ff f2", convertText(int1Settings, "0 22 -1 -14"));
		assertEquals("00 00 00 16 ff ff ff f2", convertText(int2Settings, "0 22 -1 -14"));
		assertEquals("00 00 00 16 ff ff ff f2", convertText(int4Settings, "22 -14"));
		assertEquals("00 00 00 00 00 00 00 16", convertText(int8Settings, "22"));
		assertEquals("ff ff ff ff ff ff ff f2", convertText(int8Settings, "-14"));
	}

	@Test
	public void testConvertTextFromUnsignedInts() {
		assertEquals("00 16 ff", convertText(uint1Settings, "0 22 255"));
		assertEquals("00 00 00 16 ff ff", convertText(uint2Settings, "0 22 65535"));
		assertEquals("00 00 00 16 ff ff ff ff", convertText(uint4Settings, "22 4294967295"));
		assertEquals("00 00 00 00 00 00 00 16", convertText(uint8Settings, "22"));
		assertEquals("ff ff ff ff ff ff ff ff", convertText(uint8Settings, "18446744073709551615"));
	}

	@Test
	public void testConvertTextFromFloats() {
		assertEquals("3f 9d f3 b6", convertText(floatSettings, "1.234"));
		assertEquals("3f f3 be 76 c8 b4 39 58", convertText(doubleSettings, "1.234"));
	}

	@Test
	public void testConvertTextFromString() {
		assertEquals("", convertText(stringSettings, "Hey"));
		assertEquals("56 ab", convertText(stringSettings, "56 ab"));
		assertEquals("", convertText(regExSettings, "B*B"));
		assertEquals("56 ab", convertText(regExSettings, "56 ab"));
	}
}
