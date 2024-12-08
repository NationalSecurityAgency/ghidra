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

public class FloatSearchFormatTest extends AbstractSearchFormatTest {
	public FloatSearchFormatTest() {
		super(SearchFormat.FLOAT);
		settings = settings.withBigEndian(true);
	}

	@Test
	public void testSimpleCaseBigEndian() {
		matcher = parse("1.2 1.2");
		assertBytes(63, -103, -103, -102, 63, -103, -103, -102);
		assertMask(0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
	}

	@Test
	public void testSimpleCaseLittleEndian() {
		settings = settings.withBigEndian(false);
		matcher = parse("1.2 1.2");
		assertBytes(-102, -103, -103, 63, -102, -103, -103, 63);
		assertMask(0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
	}

	@Test
	public void testECase() {
		matcher = parse("1.2e10");
		assertBytes(80, 50, -48, 94);
	}

	@Test
	public void testNegativeECase() {
		matcher = parse("1.2e-10");
		assertBytes(47, 3, -16, -1);
	}

	@Test
	public void testDotOnly() {
		ByteMatcher byteMatcher = format.parse(".", settings);
		assertTrue(byteMatcher.isValidInput());
		assertFalse(byteMatcher.isValidSearch());
		assertEquals("Incomplete floating point number", byteMatcher.getDescription());
	}

	@Test
	public void testEndE() {
		ByteMatcher byteMatcher = format.parse("2.1e", settings);
		assertTrue(byteMatcher.isValidInput());
		assertFalse(byteMatcher.isValidSearch());
		assertEquals("Incomplete floating point number", byteMatcher.getDescription());
	}

	@Test
	public void testEndNegativeE() {
		ByteMatcher byteMatcher = format.parse("2.1-e", settings);
		assertTrue(byteMatcher.isValidInput());
		assertFalse(byteMatcher.isValidSearch());
		assertEquals("Incomplete floating point number", byteMatcher.getDescription());
	}

	@Test
	public void testNegativeSignOnly() {
		ByteMatcher byteMatcher = format.parse("-", settings);
		assertTrue(byteMatcher.isValidInput());
		assertFalse(byteMatcher.isValidSearch());
		assertEquals("Incomplete negative floating point number", byteMatcher.getDescription());
	}

	@Test
	public void testNegativeDotSignOnly() {
		ByteMatcher byteMatcher = format.parse("-.", settings);
		assertTrue(byteMatcher.isValidInput());
		assertFalse(byteMatcher.isValidSearch());
		assertEquals("Incomplete negative floating point number", byteMatcher.getDescription());
	}

	@Test
	public void testBadChars() {
		ByteMatcher byteMatcher = format.parse("12.z", settings);
		assertFalse(byteMatcher.isValidInput());
		assertFalse(byteMatcher.isValidSearch());
		assertEquals("Floating point parse error: For input string: \"12.z\"",
			byteMatcher.getDescription());
	}

	@Test
	public void testGetValueBigEndian() {
		settings = settings.withBigEndian(true);
		assertRoundTrip(-1.1234, "-1.1234");
		assertRoundTrip(1.1234, "1.1234");
		assertRoundTrip(0.0, "0.0");
	}

	@Test
	public void testGetValueLittleEndian() {
		settings = settings.withBigEndian(false);
		assertRoundTrip(-1.1234, "-1.1234");
		assertRoundTrip(1.1234, "1.1234");
		assertRoundTrip(0.0, "0.0");
	}

	@Test
	public void testCompareValuesBigEndian() {
		settings = settings.withBigEndian(true);
		assertEquals(0, compareBytes("10.0", "10.0"));
		assertEquals(-1, compareBytes("9.0", "10.0"));
		assertEquals(1, compareBytes("11.0", "10.0"));

		assertEquals(0, compareBytes("-10.1", "-10.1"));
		assertEquals(1, compareBytes("-9.1", "-10.1"));
		assertEquals(-1, compareBytes("-11.1", "-10.1"));

	}

	@Test
	public void testCompareValuesLittleEndian() {
		settings = settings.withBigEndian(false);

		assertEquals(0, compareBytes("10.0", "10.0"));
		assertEquals(-1, compareBytes("9.0", "10.0"));
		assertEquals(1, compareBytes("11.0", "10.0"));

		assertEquals(0, compareBytes("-10.1", "-10.1"));
		assertEquals(1, compareBytes("-9.1", "-10.1"));
		assertEquals(-1, compareBytes("-11.1", "-10.1"));
	}

	@Test
	public void testConvertTextFromBinary() {
		assertEquals("10001000 11111111", convertText(binarySettings, "10001000 11111111"));
		assertEquals("1 0", convertText(binarySettings, "1 0"));
	}

	@Test
	public void testConvertTextFromHex() {
		assertEquals("56 12", convertText(hexSettings, "56 12"));
		assertEquals("1 0", convertText(binarySettings, "1 0"));
	}

	@Test
	public void testConvertTextFromSignedInts() {
		assertEquals("0 22 -1 -14", convertText(int1Settings, "0 22 -1 -14"));
		assertEquals("0 22 -1 -14", convertText(int2Settings, "0 22 -1 -14"));
		assertEquals("0 22 -1 -14", convertText(int4Settings, "0 22 -1 -14"));
		assertEquals("0 22 -1 -14", convertText(int8Settings, "0 22 -1 -14"));
	}

	@Test
	public void testConvertTextFromUnsignedInts() {
		assertEquals("0 22 255", convertText(uint1Settings, "0 22 255"));
		assertEquals("0 22 65535", convertText(uint2Settings, "0 22 65535"));
		assertEquals("22 4294967295", convertText(uint4Settings, "22 4294967295"));
		assertEquals("22", convertText(uint8Settings, "22"));
		assertEquals("18446744073709551615", convertText(uint8Settings, "18446744073709551615"));
	}

	@Test
	public void testConvertTextFromDoubles() {
		assertEquals("1.234", convertText(doubleSettings, "1.234"));
	}

	@Test
	public void testConvertTextFromString() {
		assertEquals("", convertText(stringSettings, "Hey"));
		assertEquals("1.23", convertText(stringSettings, "1.23"));
		assertEquals("", convertText(regExSettings, "B*B"));
		assertEquals("1.23", convertText(regExSettings, "1.23"));
	}

	private void assertRoundTrip(double expected, String input) {
		matcher = parse(input);
		byte[] bytes = matcher.getBytes();
		double value = getFloatFormat().getValue(bytes, 0, settings.isBigEndian());
		assertEquals(expected, value, 0.0000001);
	}

	private FloatSearchFormat getFloatFormat() {
		return (FloatSearchFormat) format;
	}

}
