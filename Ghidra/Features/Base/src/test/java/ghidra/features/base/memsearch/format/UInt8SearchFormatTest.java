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

import java.math.BigInteger;

import org.junit.Test;

import ghidra.features.base.memsearch.matcher.ByteMatcher;

public class UInt8SearchFormatTest extends AbstractSearchFormatTest {
	public UInt8SearchFormatTest() {
		super(SearchFormat.DECIMAL);
		settings = settings.withDecimalByteSize(8);
		settings = settings.withDecimalUnsigned(true);
	}

	@Test
	public void testSimpleCaseBigEndian() {
		matcher = parse("1 2 3");
		assertBytes(0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 3);
		assertMask(0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
	}

	@Test
	public void testSimpleCaseLittleEndian() {
		settings = settings.withBigEndian(false);
		matcher = parse("1 2 3");
		assertBytes(1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0);
		assertMask(0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
	}

	@Test
	public void testMinimum() {
		matcher = parse("0");
		assertBytes(0, 0, 0, 0, 0, 0, 0, 0);

		ByteMatcher byteMatcher = format.parse("-1", settings);
		assertFalse(byteMatcher.isValidInput());
		assertEquals("Number must be in the range [0, 18446744073709551615]",
			byteMatcher.getDescription());
	}

	@Test
	public void testMaximum() {
		BigInteger value = new BigInteger("ffffffffffffffff", 16);
		matcher = parse(value.toString());
		assertBytes(0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff);

		BigInteger bigValue = value.add(BigInteger.ONE);
		ByteMatcher byteMatcher = format.parse(bigValue.toString(), settings);
		assertFalse(byteMatcher.isValidInput());
		assertEquals("Number must be in the range [0, 18446744073709551615]",
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
		assertRoundTrip(-1, new BigInteger("ffffffffffffffff", 16).toString());
	}

	@Test
	public void testGetValueLittleEndian() {
		settings = settings.withBigEndian(false);
		assertRoundTrip(1, "1");
		assertRoundTrip(0, "0");
		assertRoundTrip(-1, new BigInteger("ffffffffffffffff", 16).toString());
	}

	@Test
	public void testCompareValuesBigEndian() {
		settings = settings.withBigEndian(true);
		assertEquals(0, compareBytes("10", "10"));
		assertEquals(-1, compareBytes("9", "10"));
		assertEquals(1, compareBytes("11", "10"));

		BigInteger maxValue = new BigInteger("ffffffffffffffff", 16);
		BigInteger maxValueMinus1 = maxValue.subtract(BigInteger.valueOf(1));
		assertEquals(0, compareBytes(maxValue.toString(), maxValue.toString()));
		assertEquals(1, compareBytes(maxValue.toString(), maxValueMinus1.toString()));
		assertEquals(-1, compareBytes(maxValueMinus1.toString(), maxValue.toString()));

	}

	@Test
	public void testCompareValuesLittleEndian() {
		settings = settings.withBigEndian(false);
		assertEquals(0, compareBytes("10", "10"));
		assertEquals(-1, compareBytes("9", "10"));
		assertEquals(1, compareBytes("11", "10"));

		BigInteger maxValue = new BigInteger("ffffffffffffffff", 16);
		BigInteger maxValueMinus1 = maxValue.subtract(BigInteger.valueOf(1));
		assertEquals(0, compareBytes(maxValue.toString(), maxValue.toString()));
		assertEquals(1, compareBytes(maxValue.toString(), maxValueMinus1.toString()));
		assertEquals(-1, compareBytes(maxValueMinus1.toString(), maxValue.toString()));

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
		assertEquals("98784247794", convertText(int2Settings, "0 22 -1 -14"));
		assertEquals("22 18446744073709551615", convertText(int4Settings, "0 22 -1 -1"));
		assertEquals("0 22 18446744073709551615", convertText(int8Settings, "0 22 -1"));

		assertEquals("20000000", convertText(int4Settings, "20000000"));
	}

	@Test
	public void testConvertTextFromUnsignedInts() {
		assertEquals("5887", convertText(uint1Settings, "0 22 255"));
		assertEquals("1507327", convertText(uint2Settings, "0 22 65535"));
		assertEquals("98784247807", convertText(uint4Settings, "22 4294967295"));
		assertEquals("22", convertText(uint8Settings, "22"));
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
