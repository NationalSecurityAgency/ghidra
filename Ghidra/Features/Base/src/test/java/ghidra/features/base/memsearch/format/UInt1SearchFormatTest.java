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

public class UInt1SearchFormatTest extends AbstractSearchFormatTest {
	public UInt1SearchFormatTest() {
		super(SearchFormat.DECIMAL);
		settings = settings.withDecimalByteSize(1);
		settings = settings.withDecimalUnsigned(true);
	}

	@Test
	public void testSimpleCaseBigEndian() {
		matcher = parse("1 2 3");
		assertBytes(1, 2, 3);
		assertMask(0xff, 0xff, 0xff);
	}

	@Test
	public void testSimpleCaseLittleEndian() {
		settings = settings.withBigEndian(false);
		matcher = parse("1 2 3");
		assertBytes(1, 2, 3);
		assertMask(0xff, 0xff, 0xff);
	}

	@Test
	public void testMinimum() {
		matcher = parse("0");
		assertBytes(0);

		ByteMatcher byteMatcher = format.parse("-1", settings);
		assertFalse(byteMatcher.isValidInput());
		assertEquals("Number must be in the range [0, 255]",
			byteMatcher.getDescription());
	}

	@Test
	public void testMaximum() {
		long value = 0xffL;
		matcher = parse(Long.toString(value));
		assertBytes(0xff);

		value += 1;
		ByteMatcher byteMatcher = format.parse(Long.toString(value), settings);
		assertFalse(byteMatcher.isValidInput());
		assertEquals("Number must be in the range [0, 255]",
			byteMatcher.getDescription());
	}

	@Test
	public void testNegativeSignOnly() {
		ByteMatcher byteMatcher = format.parse("-", settings);
		assertFalse(byteMatcher.isValidInput());
		assertFalse(byteMatcher.isValidSearch());
		assertEquals("Negative numbers not allowed for unsigned values",
			byteMatcher.getDescription());
	}

	@Test
	public void testBadChars() {
		ByteMatcher byteMatcher = format.parse("12z", settings);
		assertFalse(byteMatcher.isValidInput());
		assertFalse(byteMatcher.isValidSearch());
		assertEquals("Number parse error: For input string: \"12z\"", byteMatcher.getDescription());
	}

	@Test
	public void testGetValueBigEndian() {
		settings = settings.withBigEndian(true);
		assertRoundTrip(1, "1");
		assertRoundTrip(0, "0");
		assertRoundTrip(0xffL, Long.toString(0xffL));
	}

	@Test
	public void testGetValueLittleEndian() {
		settings = settings.withBigEndian(false);
		assertRoundTrip(1, "1");
		assertRoundTrip(0, "0");
		assertRoundTrip(0xffL, Long.toString(0xffL));
	}

	@Test
	public void testCompareValuesBigEndian() {
		settings = settings.withBigEndian(true);
		assertEquals(0, compareBytes("10", "10"));
		assertEquals(-1, compareBytes("9", "10"));
		assertEquals(1, compareBytes("11", "10"));

		assertEquals(0, compareBytes(str(0xffl), str(0xffL)));
		assertEquals(1, compareBytes(str(0xffl), str(0xfeL)));
		assertEquals(-1, compareBytes(str(0xfeL), str(0xffL)));

	}

	@Test
	public void testCompareValuesLittleEndian() {
		settings = settings.withBigEndian(false);
		assertEquals(0, compareBytes("10", "10"));
		assertEquals(-1, compareBytes("9", "10"));
		assertEquals(1, compareBytes("11", "10"));

		assertEquals(0, compareBytes(str(0xffL), str(0xffL)));
		assertEquals(1, compareBytes(str(0xffL), str(0xfeL)));
		assertEquals(-1, compareBytes(str(0xfeL), str(0xffL)));

	}

	@Test
	public void testConvertTextFromBinary() {
		assertEquals("136 255", convertText(binarySettings, "10001000 11111111"));
		assertEquals("1 0", convertText(binarySettings, "1 0"));
	}

	@Test
	public void testConvertTextFromHex() {
		assertEquals("86 18", convertText(hexSettings, "56 12"));
		assertEquals("1 0", convertText(hexSettings, "1 0"));
	}

	@Test
	public void testConvertTextFromOtherSizedInts() {
		assertEquals("0 0 0 22 255 255 255 242", convertText(int2Settings, "0 22 -1 -14"));
		assertEquals("0 0 0 0 0 0 0 22 255 255 255 255",
			convertText(int4Settings, "0 22 -1"));
		assertEquals("0", convertText(int8Settings, "0"));
		assertEquals("255 255 255 255 255 255 255 255", convertText(int8Settings, "-1"));

		assertEquals("78 32", convertText(int2Settings, "20000"));
		assertEquals("1 49 45 0", convertText(int4Settings, "20000000"));
		assertEquals("0 0 1 209 169 74 32 0", convertText(int8Settings, "2000000000000"));

	}

	@Test
	public void testConvertTextFromUnsignedInts() {
		assertEquals("0 22 255", convertText(uint1Settings, "0 22 255"));
		assertEquals("0 0 0 22 255 255", convertText(uint2Settings, "0 22 65535"));
		assertEquals("0 0 0 22 255 255 255 255", convertText(uint4Settings, "22 4294967295"));
		assertEquals("22", convertText(uint8Settings, "22"));
		assertEquals("255 255 255 255 255 255 255 255",
			convertText(uint8Settings, "18446744073709551615"));
	}

	@Test
	public void testConvertTextFromDoubles() {
		assertEquals("", convertText(doubleSettings, "1.234"));
	}

	@Test
	public void testConvertTextFromString() {
		assertEquals("", convertText(stringSettings, "Hey"));
		assertEquals("123", convertText(stringSettings, "123"));
		assertEquals("", convertText(regExSettings, "B*B"));
		assertEquals("123", convertText(regExSettings, "123"));
	}

	private void assertRoundTrip(long expected, String input) {
		matcher = parse(input);
		byte[] bytes = matcher.getBytes();
		long value = getNumberFormat().getValue(bytes, 0, settings);
		assertEquals(expected, value);
	}

	private DecimalSearchFormat getNumberFormat() {
		return (DecimalSearchFormat) format;
	}

}
