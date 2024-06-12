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

public class Int4SearchFormatTest extends AbstractSearchFormatTest {
	public Int4SearchFormatTest() {
		super(SearchFormat.DECIMAL);
		settings = settings.withDecimalByteSize(4);
	}

	@Test
	public void testSimpleCaseBigEndian() {
		matcher = parse("1 2 -1");
		assertBytes(0, 0, 0, 1, 0, 0, 0, 2, -1, -1, -1, -1);
		assertMask(0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
	}

	@Test
	public void testSimpleCaseLittleEndian() {
		settings = settings.withBigEndian(false);
		matcher = parse("1 2 -1");
		assertBytes(1, 0, 0, 0, 2, 0, 0, 0, -1, -1, -1, -1);
		assertMask(0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
	}

	@Test
	public void testMinimum() {
		long value = Integer.MIN_VALUE;
		matcher = parse(Long.toString(value));
		assertBytes(0x80, 0, 0, 0);

		value -= 1;
		ByteMatcher byteMatcher = format.parse(Long.toString(value), settings);
		assertFalse(byteMatcher.isValidInput());
		assertEquals("Number must be in the range [-2147483648, 2147483647]",
			byteMatcher.getDescription());
	}

	@Test
	public void testMaximum() {
		long value = Integer.MAX_VALUE;
		matcher = parse(Long.toString(value));
		assertBytes(0x7f, 0xff, 0xff, 0xff);

		value += 1;
		ByteMatcher byteMatcher = format.parse(Long.toString(value), settings);
		assertFalse(byteMatcher.isValidInput());
		assertEquals("Number must be in the range [-2147483648, 2147483647]",
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
		assertRoundTrip(Integer.MAX_VALUE, Integer.toString(Integer.MAX_VALUE));
		assertRoundTrip(Integer.MIN_VALUE, Integer.toString(Integer.MIN_VALUE));
	}

	@Test
	public void testGetValueLittleEndian() {
		settings = settings.withBigEndian(false);
		assertRoundTrip(-1, "-1");
		assertRoundTrip(1, "1");
		assertRoundTrip(0, "0");
		assertRoundTrip(Integer.MAX_VALUE, Integer.toString(Integer.MAX_VALUE));
		assertRoundTrip(Integer.MIN_VALUE, Integer.toString(Integer.MIN_VALUE));
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
		assertEquals("35071", convertText(binarySettings, "10001000 11111111"));
		assertEquals("256", convertText(binarySettings, "1 0"));
	}

	@Test
	public void testConvertTextFromHex() {
		assertEquals("22034", convertText(hexSettings, "56 12"));
		assertEquals("256", convertText(hexSettings, "1 0"));
	}

	@Test
	public void testConvertTextFromOtherSizedInts() {
		assertEquals("1507314", convertText(int1Settings, "0 22 -1 -14"));
		assertEquals("22 -14", convertText(int2Settings, "0 22 -1 -14"));
		assertEquals("0 22 -1 -14", convertText(int8Settings, "0 22 -1 -14"));

		assertEquals("20000000", convertText(int4Settings, "20000000"));
		assertEquals("465 -1454759936", convertText(int8Settings, "2000000000000"));

	}

	@Test
	public void testConvertTextFromUnsignedInts() {
		assertEquals("5887", convertText(uint1Settings, "0 22 255"));
		assertEquals("22 65535", convertText(uint2Settings, "0 22 65535"));
		assertEquals("22 -1", convertText(uint4Settings, "22 4294967295"));
		assertEquals("22", convertText(uint8Settings, "22"));
		assertEquals("-1 -1",
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
		long value = getDecimalFormat().getValue(bytes, 0, settings);
		assertEquals(expected, value);
	}

	private DecimalSearchFormat getDecimalFormat() {
		return (DecimalSearchFormat) format;
	}
}
