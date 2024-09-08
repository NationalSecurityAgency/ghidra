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

public class Int1SearchFormatTest extends AbstractSearchFormatTest {
	public Int1SearchFormatTest() {
		super(SearchFormat.DECIMAL);
		settings = settings.withDecimalByteSize(1);
	}

	@Test
	public void testSimpleCaseBigEndian() {
		matcher = parse("1 2 -1");
		assertBytes(1, 2, -1);
		assertMask(0xff, 0xff, 0xff);
	}

	@Test
	public void testSimpleCaseLittleEndian() {
		settings = settings.withBigEndian(false);
		matcher = parse("1 2 -1");
		assertBytes(1, 2, -1);
		assertMask(0xff, 0xff, 0xff);
	}

	@Test
	public void testMinimum() {
		long value = Byte.MIN_VALUE;
		matcher = parse(Long.toString(value));
		assertBytes(0x80);

		value -= 1;
		ByteMatcher byteMatcher = format.parse(Long.toString(value), settings);
		assertFalse(byteMatcher.isValidInput());
		assertEquals("Number must be in the range [-128, 127]",
			byteMatcher.getDescription());
	}

	@Test
	public void testMaximum() {
		long value = Byte.MAX_VALUE;
		matcher = parse(Long.toString(value));
		assertBytes(0x7f);

		value += 1;
		ByteMatcher byteMatcher = format.parse(Long.toString(value), settings);
		assertFalse(byteMatcher.isValidInput());
		assertEquals("Number must be in the range [-128, 127]",
			byteMatcher.getDescription());
	}

	@Test
	public void testNegativeSignOnly() {
		ByteMatcher byteMatcher = format.parse("-", settings);
		assertTrue(byteMatcher.isValidInput());
		assertFalse(byteMatcher.isValidSearch());
		assertEquals("Incomplete negative number", byteMatcher.getDescription());
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
		assertRoundTrip(-1, "-1");
		assertRoundTrip(1, "1");
		assertRoundTrip(0, "0");
		assertRoundTrip(Byte.MAX_VALUE, Integer.toString(Byte.MAX_VALUE));
		assertRoundTrip(Byte.MIN_VALUE, Integer.toString(Byte.MIN_VALUE));
	}

	@Test
	public void testGetValueLittleEndian() {
		settings = settings.withBigEndian(false);
		assertRoundTrip(-1, "-1");
		assertRoundTrip(1, "1");
		assertRoundTrip(0, "0");
		assertRoundTrip(Byte.MAX_VALUE, Integer.toString(Byte.MAX_VALUE));
		assertRoundTrip(Byte.MIN_VALUE, Integer.toString(Byte.MIN_VALUE));
	}

	@Test
	public void testCompareValuesBigEndian() {
		settings = settings.withBigEndian(true);
		assertEquals(0, compareBytes("10", "10"));
		assertEquals(-1, compareBytes("9", "10"));
		assertEquals(1, compareBytes("11", "10"));

		assertEquals(0, compareBytes("-10", "-10"));
		assertEquals(1, compareBytes("-9", "-10"));
		assertEquals(-1, compareBytes("-11", "-10"));

	}

	@Test
	public void testCompareValuesLittleEndian() {
		settings = settings.withBigEndian(false);
		assertEquals(0, compareBytes("10", "10"));
		assertEquals(-1, compareBytes("9", "10"));
		assertEquals(1, compareBytes("11", "10"));

		assertEquals(0, compareBytes("-10", "-10"));
		assertEquals(1, compareBytes("-9", "-10"));
		assertEquals(-1, compareBytes("-11", "-10"));

	}

	@Test
	public void testConvertTextFromBinary() {
		assertEquals("-120 -1", convertText(binarySettings, "10001000 11111111"));
		assertEquals("1 0", convertText(binarySettings, "1 0"));
	}

	@Test
	public void testConvertTextFromhexSettings() {
		assertEquals("86 18", convertText(hexSettings, "56 12"));
		assertEquals("1 0", convertText(hexSettings, "1 0"));
	}

	@Test
	public void testConvertTextFromOtherSizedInts() {
		assertEquals("0 22 -1 -14", convertText(int2Settings, "0 22 -1 -14"));
		assertEquals("0 22 -1 -14", convertText(int4Settings, "0 22 -1 -14"));
		assertEquals("0 22 -1 -14", convertText(int8Settings, "0 22 -1 -14"));

		assertEquals("78 32", convertText(int2Settings, "20000"));
		assertEquals("1 49 45 0", convertText(int4Settings, "20000000"));
		assertEquals("0 0 1 -47 -87 74 32 0", convertText(int8Settings, "2000000000000"));

	}

	@Test
	public void testConvertTextFromUnsignedInts() {
		assertEquals("0 22 -1", convertText(uint1Settings, "0 22 255"));
		assertEquals("0 0 0 22 -1 -1", convertText(uint2Settings, "0 22 65535"));
		assertEquals("0 0 0 22 -1 -1 -1 -1", convertText(uint4Settings, "22 4294967295"));
		assertEquals("22", convertText(uint8Settings, "22"));
		assertEquals("-1 -1 -1 -1 -1 -1 -1 -1",
			convertText(uint8Settings, "18446744073709551615"));
	}

	@Test
	public void testConvertTextFromdoubleSettingss() {
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
		long value = getDecimalFormat().getValue(bytes, 0, settings);
		assertEquals(expected, value);
	}

	private DecimalSearchFormat getDecimalFormat() {
		return (DecimalSearchFormat) format;
	}

}
