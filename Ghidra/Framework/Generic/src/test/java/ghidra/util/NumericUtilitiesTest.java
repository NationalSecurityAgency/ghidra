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
package ghidra.util;

import static org.junit.Assert.*;

import java.util.*;
import java.util.stream.Collectors;

import org.junit.Test;

public class NumericUtilitiesTest {

	private static final byte[] BYTES_012380ff00 =
		new byte[] { (byte) 0x1, (byte) 0x23, (byte) 0x80, (byte) 0xff, (byte) 0 };

	@Test
	public void testConvertStringToBytes() {
		String string = "012380ff00";
		byte[] expected = BYTES_012380ff00;
		byte[] actual = NumericUtilities.convertStringToBytes(string);

		assertEquals(expected.length, actual.length);
		for (int i = 0; i < expected.length; i++) {
			assertEquals(expected[i], actual[i]);
		}
	}

	@Test
	public void testConvertStringToBytes_OddLength() {
		String string = "012380ff00f";

		try {
			NumericUtilities.convertStringToBytes(string);
			fail("Expected an exception when passing an odd number of characters");
		}
		catch (IllegalArgumentException e) {
			// good
		}
	}

	@Test
	public void testConvertStringToBytes_SpaceDelimited() {
		String string = "01 23 80 ff 00";
		byte[] expected = BYTES_012380ff00;
		byte[] actual = NumericUtilities.convertStringToBytes(string);

		assertEquals(expected.length, actual.length);
		for (int i = 0; i < expected.length; i++) {
			assertEquals(expected[i], actual[i]);
		}
	}

	@Test
	public void testConvertStringToBytes_CommaDelimited() {
		String string = "01,23,80,ff,00";
		byte[] expected = BYTES_012380ff00;
		byte[] actual = NumericUtilities.convertStringToBytes(string);

		assertEquals(expected.length, actual.length);
		for (int i = 0; i < expected.length; i++) {
			assertEquals(expected[i], actual[i]);
		}
	}

	@Test
	public void testConvertStringToBytes_CommaAndSpaceDelimited() {
		String string = "01, 23, 80, ff, 00";
		byte[] expected = BYTES_012380ff00;
		byte[] actual = NumericUtilities.convertStringToBytes(string);

		assertEquals(expected.length, actual.length);
		for (int i = 0; i < expected.length; i++) {
			assertEquals(expected[i], actual[i]);
		}
	}

	@Test
	public void testConvertBytesToString() {
		byte[] bytes = new byte[] { (byte) 0x1, (byte) 0x23, (byte) 0x80, (byte) 0xff, (byte) 0 };
		String str = NumericUtilities.convertBytesToString(bytes);
		assertEquals("012380ff00", str);
	}

	@Test
	public void testConvertBytesToStringWithOffsetAndLength() {
		byte[] bytes = new byte[] { (byte) 0x1, (byte) 0x23, (byte) 0x80, (byte) 0xff, (byte) 0 };
		String str = NumericUtilities.convertBytesToString(bytes, 2, 2, " ");
		assertEquals("80 ff", str);
	}

	@Test
	public void testConvertBytesToStringWithDelimiter() {
		byte[] bytes = new byte[] { (byte) 0x1, (byte) 0x23, (byte) 0x80, (byte) 0xff, (byte) 0 };
		String str = NumericUtilities.convertBytesToString(bytes, " ");
		assertEquals("01 23 80 ff 00", str);
	}

	@Test
	public void testFormatNumber() {

		long number = 100;

		assertEquals("\"\\x00\\x00\\x00\\x00\\x00\\x00\\x00d\"",
			NumericUtilities.formatNumber(number, 0));
		assertEquals("1100100b", NumericUtilities.formatNumber(number, 2));
		assertEquals("144o", NumericUtilities.formatNumber(number, 8));
		assertEquals("100", NumericUtilities.formatNumber(number, 10));
		assertEquals("64h", NumericUtilities.formatNumber(number, 16));
	}

	private static class FormatNumberResult {
		final long number;
		final int radix;
		final SignednessFormatMode mode;
		final String result;

		public FormatNumberResult(long num, int rad, SignednessFormatMode mode, String result) {
			this.number = num;
			this.radix = rad;
			this.mode = mode;
			this.result = result;
		}

		@Override
		public String toString() {
			return String.format("%6d %2d (%s) :: %s", number, radix, mode.name(), result);
		}

	}

	/*
	 * HELPER ROUTINE:
	 * Get the result object of formatting a given number in a given radix as either 
	 * signed or unsigned
	 */
	private static FormatNumberResult formatNumber(long number, int radix,
			SignednessFormatMode mode) {
		String formattedNumber = NumericUtilities.formatNumber(number, radix, mode);
		return new FormatNumberResult(number, radix, mode, formattedNumber);
	}

	/*
	 * HELPER ROUTINE:
	 * Render the number value in the given radix in both Signed and Unsigned modes.
	 */
	private static List<FormatNumberResult> formatNumberSignedAndUnsigned(long number, int radix) {
		List<FormatNumberResult> results = new ArrayList<>();
		results.add(formatNumber(number, radix, SignednessFormatMode.SIGNED));
		results.add(formatNumber(number, radix, SignednessFormatMode.UNSIGNED));
		return results;
	}

	/*
	 * HELPER ROUTINE:
	 * Compute the renderings of number in the supported radixes
	 */
	private static List<FormatNumberResult> formatNumberAsSignedAndUnsignedInRadixes(long number) {
		List<FormatNumberResult> results = new ArrayList<>();
		int[] radixes = new int[] { 2, 8, 10, 16 };
		for (int radix : radixes) {
			results.addAll(formatNumberSignedAndUnsigned(number, radix));
		}
		return results;
	}

	/*
	 * HELPER ROUTINE:
	 * For the given number value, compute the signed and unsigned renderings in the supported 
	 * integer bases, and compare against the supplied values. 
	 */
	private void computeAndCheckNumberRenderings(long number, String[] expectedSignedResults,
			String[] expectedUnsignedResults) {
		assertEquals(expectedSignedResults.length, expectedUnsignedResults.length);

		/* 
		 * 1) Get the renderings of the number (signed and unsigned, in various radixes) as a list
		 * 2) Group the results by Signed/Unsigned into a map of mode::result-list
		 * 3) Sort the result-list of each group by the rendered radix 
		 */
		Map<SignednessFormatMode, List<FormatNumberResult>> results =
			formatNumberAsSignedAndUnsignedInRadixes(number).stream().collect(
				Collectors.groupingBy(r -> r.mode,
					Collectors.collectingAndThen(Collectors.toCollection(ArrayList::new), l -> {
						l.sort((r1, r2) -> r1.radix - r2.radix);
						return l;
					})));

		List<FormatNumberResult> signedResults = results.get(SignednessFormatMode.SIGNED);
		// Iterate the radix-sorted result list of signed renderings, comparing against the
		// expected results
		for (int i = 0; i < signedResults.size(); i++) {
			FormatNumberResult signedResult = signedResults.get(i);
			String result = signedResult.result;
			String expected = expectedSignedResults[i];
			assertEquals("SIGNED(" + signedResult.number + " Radix " + signedResult.radix + ") ",
				expected, result);
		}

		List<FormatNumberResult> unsignedResults = results.get(SignednessFormatMode.UNSIGNED);
		// Iterate the radix-sorted result list of unsigned renderings, comparing against the
		// expected results
		for (int i = 0; i < unsignedResults.size(); i++) {
			FormatNumberResult unsignedResult = unsignedResults.get(i);
			String result = unsignedResult.result;
			String expected = expectedUnsignedResults[i];
			assertEquals(
				"UNSIGNED(" + unsignedResult.number + " Radix " + unsignedResult.radix + ") ",
				expected, result);
		}
	}

	@Test
	public void testFormatNumber_100() {
		String[] expectedSignedResults = new String[] { "1100100b", "144o", "100", "64h" };
		String[] expectedUnsignedResults = new String[] { "1100100b", "144o", "100", "64h" };

		long number = 100;

		computeAndCheckNumberRenderings(number, expectedSignedResults, expectedUnsignedResults);
	}

	@Test
	public void testFormatNumber_neg100() {
		String[] expectedSignedResults = new String[] { "-1100100b", "-144o", "-100", "-64h" };
		String[] expectedUnsignedResults =
			new String[] { "1111111111111111111111111111111111111111111111111111111110011100b",
				"1777777777777777777634o", "18446744073709551516", "ffffffffffffff9ch" };

		long number = -100;

		computeAndCheckNumberRenderings(number, expectedSignedResults, expectedUnsignedResults);
	}

	@Test
	public void testFormatNumber_MinLong() {
		String[] expectedSignedResults =
			new String[] { "-1000000000000000000000000000000000000000000000000000000000000000b",
				"-1000000000000000000000o", "-9223372036854775808", "-8000000000000000h" };
		String[] expectedUnsignedResults =
			new String[] { "1000000000000000000000000000000000000000000000000000000000000000b",
				"1000000000000000000000o", "9223372036854775808", "8000000000000000h" };

		long number = Long.MIN_VALUE;

		computeAndCheckNumberRenderings(number, expectedSignedResults, expectedUnsignedResults);
	}

	@Test
	public void testFormatNumber_MaxLong() {
		String[] expectedSignedResults =
			new String[] { "111111111111111111111111111111111111111111111111111111111111111b",
				"777777777777777777777o", "9223372036854775807", "7fffffffffffffffh" };
		String[] expectedUnsignedResults =
			new String[] { "111111111111111111111111111111111111111111111111111111111111111b",
				"777777777777777777777o", "9223372036854775807", "7fffffffffffffffh" };

		long number = Long.MAX_VALUE;

		computeAndCheckNumberRenderings(number, expectedSignedResults, expectedUnsignedResults);
	}

	@Test
	public void testConvertStringToBytes_WithSpaces_WithSingleByteChars() {

		String string = "01 1 ff f";
		byte[] expected = new byte[] { (byte) 0x1, (byte) 0x1, (byte) 0xff, (byte) 0x0f };
		byte[] actual = NumericUtilities.convertStringToBytes(string);
		asssertBytesEquals(expected, actual);
	}

	@Test
	public void testGetUnsignedAlignedValue() {

		assertEquals(0, NumericUtilities.getUnsignedAlignedValue(0xffffffffffffffffL, 8));
		assertEquals(0xfffffffffffffff8L,
			NumericUtilities.getUnsignedAlignedValue(0xfffffffffffffff8L, 8));
		assertEquals(0xfffffffffffffff8L,
			NumericUtilities.getUnsignedAlignedValue(0xfffffffffffffff3L, 8));
		assertEquals(0xfffffffffffffff0L,
			NumericUtilities.getUnsignedAlignedValue(0xffffffffffffffecL, 8));
		assertEquals(0xffffffffffffffe8L,
			NumericUtilities.getUnsignedAlignedValue(0xffffffffffffffe8L, 8));
		assertEquals(0, NumericUtilities.getUnsignedAlignedValue(0, 8));
		assertEquals(8, NumericUtilities.getUnsignedAlignedValue(3, 8));
		assertEquals(8, NumericUtilities.getUnsignedAlignedValue(8, 8));

		assertEquals(0, NumericUtilities.getUnsignedAlignedValue(0xffffffffffffffffL, 5));
		assertEquals(0xfffffffffffffffbL,
			NumericUtilities.getUnsignedAlignedValue(0xfffffffffffffff8L, 5));
		assertEquals(0xfffffffffffffff6L,
			NumericUtilities.getUnsignedAlignedValue(0xfffffffffffffff3L, 5));
		assertEquals(0xffffffffffffffecL,
			NumericUtilities.getUnsignedAlignedValue(0xffffffffffffffecL, 5));
		assertEquals(0xffffffffffffffecL,
			NumericUtilities.getUnsignedAlignedValue(0xffffffffffffffe8L, 5));
		assertEquals(0, NumericUtilities.getUnsignedAlignedValue(0, 5));
		assertEquals(5, NumericUtilities.getUnsignedAlignedValue(3, 5));
		assertEquals(0xa, NumericUtilities.getUnsignedAlignedValue(8, 5));
		assertEquals(0xa, NumericUtilities.getUnsignedAlignedValue(0xa, 0));

	}

	private void asssertBytesEquals(byte[] expected, byte[] actual) {

		String errorMessage = "Byte arrays not equal - exptected: " + Arrays.toString(expected) +
			"; actual: " + Arrays.toString(actual);

		assertEquals(errorMessage, expected.length, actual.length);
		for (int i = 0; i < expected.length; i++) {
			assertEquals(errorMessage, expected[i], actual[i]);
		}
	}
}
