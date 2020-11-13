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

import java.math.BigInteger;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apache.commons.collections4.IteratorUtils;
import org.apache.commons.lang3.StringUtils;

import util.CollectionUtils;

public final class NumericUtilities {
	public static final BigInteger MAX_UNSIGNED_LONG = new BigInteger("ffffffffffffffff", 16);
	public static final BigInteger MAX_SIGNED_LONG = new BigInteger("7fffffffffffffff", 16);
	public static final long MAX_UNSIGNED_INT32_AS_LONG = 0xffffffffL;

	private final static String HEX_PREFIX_X = "0X";
	private final static String HEX_PREFIX_x = "0x";

	private final static Set<Class<? extends Number>> INTEGER_TYPES = new HashSet<>();
	static {
		INTEGER_TYPES.add(Byte.class);
		INTEGER_TYPES.add(Short.class);
		INTEGER_TYPES.add(Integer.class);
		INTEGER_TYPES.add(Long.class);
	}
	private static final Set<Class<? extends Number>> FLOATINGPOINT_TYPES = new HashSet<>();
	static {
		FLOATINGPOINT_TYPES.add(Float.class);
		FLOATINGPOINT_TYPES.add(Double.class);
	}

	// @formatter:off
	private static IntegerRadixRenderer SIGNED_INTEGER_RENDERER = new SignedIntegerRadixRenderer();
	private static IntegerRadixRenderer UNSIGNED_INTEGER_RENDERER = new UnsignedIntegerRadixRenderer();
	private static IntegerRadixRenderer DEFAULT_INTEGER_RENDERER = new DefaultIntegerRadixRenderer();
	// @formatter:on

	private NumericUtilities() {
	}

	/**
	 * parses the given string as a numeric value, detecting whether or not it begins with a Hex
	 * prefix, and if not, parses as a long int value.
	 */
	public static long parseNumber(String numStr) {
		long value = 0;

		numStr = (numStr == null ? "" : numStr.trim());
		if (numStr.length() == 0) {
			return value;
		}

		try {
			if (numStr.startsWith(HEX_PREFIX_x) || numStr.startsWith(HEX_PREFIX_X)) {
				value = Integer.parseInt(numStr.substring(2), 16);
			}
			else {
				value = Integer.parseInt(numStr);
			}
		}
		catch (NumberFormatException exc) {
			// do nothing special; use default value
		}

		return value;
	}

	/**
	 * parses the given string as a numeric value, detecting whether or not it begins with a Hex
	 * prefix, and if not, parses as a long int value.
	 */
	public static long parseLong(String numStr) {
		String origStr = numStr;
		long value = 0;
		long sign = 1;

		numStr = (numStr == null ? "" : numStr.trim());
		if (numStr.length() == 0) {
			return value;
		}
		if (numStr.startsWith("-")) {
			sign = -1;
			numStr = numStr.substring(1);
		}
		int radix = 10;

		if (numStr.startsWith(HEX_PREFIX_x) || numStr.startsWith(HEX_PREFIX_X)) {
			if (numStr.length() > 18) {
				throw new NumberFormatException(numStr + " has too many digits.");
			}
			numStr = numStr.substring(2);
			radix = 16;
		}
		if (numStr.length() == 0) {
			return 0;
		}
		try {
			BigInteger bi = new BigInteger(numStr, radix);
			return bi.longValue() * sign;
		}
		catch (NumberFormatException e) {
			// This is a little hacky, but the message should be complete and report about the
			// original string
			NumberFormatException e2 =
				new NumberFormatException("Cannot parse long from " + origStr);
			e2.setStackTrace(e.getStackTrace());
			throw e2;
		}
		catch (ArithmeticException e) {
			throw new NumberFormatException(origStr + " is too big.");
		}
	}

	/**
	 * parses the given string as a numeric value, detecting whether or not it begins with a Hex
	 * prefix, and if not, parses as a long int value.
	 */
	public static long parseOctLong(String numStr) {

		long value = 0;
		long sign = 1;

		numStr = (numStr == null ? "" : numStr.trim());
		if (numStr.length() == 0) {
			return value;
		}

		if (numStr.startsWith("-")) {
			sign = -1;
			numStr = numStr.substring(1);
		}

		int radix = 8;
		if (numStr.startsWith("0")) {
			if (numStr.length() > 18) {
				throw new NumberFormatException(numStr + " has too many digits.");
			}
			numStr = numStr.substring(1);
		}
		BigInteger bi = new BigInteger(numStr, radix);

		return bi.longValue() * sign;

	}

	public static long parseHexLong(String numStr) {

		return parseHexBigInteger(numStr).longValue();
	}

	public static BigInteger parseHexBigInteger(String numStr) {

		numStr = (numStr == null ? "" : numStr.trim());
		if (numStr.length() == 0) {
			throw new NumberFormatException(numStr + " no digits.");
		}

		boolean negative = false;
		if (numStr.startsWith("-")) {
			negative = true;
			numStr = numStr.substring(1);
		}

		if (numStr.startsWith(HEX_PREFIX_x) || numStr.startsWith(HEX_PREFIX_X)) {
			numStr = numStr.substring(2);
		}

		if (negative) {
			numStr = "-" + numStr;
		}
		return new BigInteger(numStr, 16);
	}

	/**
	 * returns the value of the specified long as hexadecimal, prefixing with the HEX_PREFIX_x
	 * string.
	 * 
	 * @param value the long value to convert
	 */
	public final static String toHexString(long value) {
		return HEX_PREFIX_x + Long.toHexString(value);
	}

	/**
	 * returns the value of the specified long as hexadecimal, prefixing with the HEX_PREFIX_x
	 * string.
	 * 
	 * @param value the long value to convert
	 * @param size number of bytes to be represented
	 */
	public final static String toHexString(long value, int size) {
		if (size > 0 && size < 8) {
			value &= -1L >> (8 * (8 - size));
		}
		return HEX_PREFIX_x + Long.toHexString(value);
	}

	/**
	 * returns the value of the specified long as signed hexadecimal, prefixing with the
	 * HEX_PREFIX_x string.
	 * 
	 * @param value the long value to convert
	 */
	public final static String toSignedHexString(long value) {
		StringBuffer buf = new StringBuffer();
		if (value < 0) {
			buf.append("-");
		}
		buf.append(HEX_PREFIX_x);
		buf.append(Long.toHexString(Math.abs(value)));
		return buf.toString();
	}

	/**
	 * Converts a <strong>unsigned</strong> long value, which is currently stored in a 
	 * java <strong>signed</strong> long, into a {@link BigInteger}.
	 * <p>
	 * In other words, the full 64 bits of the primitive java <strong>signed</strong> 
	 * long is being used to store an <strong>unsigned</strong> value.  This 
	 * method converts this into a positive BigInteger value.
	 *  
	 * @param value java <strong>unsigned</strong> long value stuffed into a 
	 * java <strong>signed</strong> long
	 * @return new {@link BigInteger} with the positive value of the unsigned long value
	 */
	public static BigInteger unsignedLongToBigInteger(long value) {
		if (value >= 0) {
			return BigInteger.valueOf(value);
		}
		return MAX_UNSIGNED_LONG.add(BigInteger.valueOf(value + 1));
	}

	public static long bigIntegerToUnsignedLong(BigInteger value) {
		if (value.compareTo(MAX_SIGNED_LONG) <= 0) {
			return value.longValue();
		}
		return value.subtract(MAX_UNSIGNED_LONG).longValue() - 1;
	}

	/**
	 * Get an unsigned aligned value corresponding to the specified unsigned value which will be
	 * greater than or equal the specified value.
	 * 
	 * @param unsignedValue value to be aligned
	 * @param alignment alignment
	 * @return aligned value
	 */
	public static long getUnsignedAlignedValue(long unsignedValue, long alignment) {
		if (alignment == 0 || unsignedValue % alignment == 0) {
			return unsignedValue;
		}
		boolean negative = unsignedValue < 0;
		if (negative) {
			unsignedValue = -(unsignedValue + alignment);
		}
		long alignedValue = ((unsignedValue + alignment - 1) / alignment) * alignment;
		if (negative) {
			alignedValue = -alignedValue;
		}
		return alignedValue;
	}

	/**
	 * Convert a masked value into a hexadecimal-ish string.
	 *
	 * Converts the data to hexadecimal, placing an X where a nibble is unknown. Where a nibble is
	 * partially defined, it is displayed as four bits in brackets []. Bits are displayed as x, or
	 * the defined value.
	 *
	 * For example, consider the mask 00001111:01011100, and the value 00001001:00011000. This will
	 * display as {@code X8:[x0x1][10xx]}. To see the correlation, consider the table:
	 * <table>
	 * <caption></caption>
	 * <tr>
	 * <th>Display</th>
	 * <th>{@code X}</th>
	 * <th>{@code 8}</th>
	 * <th>{@code :}</th>
	 * <th>{@code [x0x1]}</th>
	 * <th>{@code [10xx]}</th>
	 * </tr>
	 * <tr>
	 * <th>Mask</th>
	 * <td>{@code 0000}</td>
	 * <td>{@code 1111}</td>
	 * <td>{@code :}</td>
	 * <td>{@code 0101}</td>
	 * <td>{@code 1100}</td>
	 * </tr>
	 * <tr>
	 * <th>Value</th>
	 * <td>{@code 0000}</td>
	 * <td>{@code 1000}</td>
	 * <td>{@code :}</td>
	 * <td>{@code 0001}</td>
	 * <td>{@code 1000}</td>
	 * </tr>
	 * </table>
	 *
	 * @param msk the mask
	 * @param val the value
	 * @param n the number of nibbles, starting at the right. The example uses 4.
	 * @param truncate true if leading Xs may be truncated. The example uses {@code false}.
	 * @param spaceevery how many nibbles in spaced groups, 0 for no spaces. The example uses 2.
	 * @param spacer the group separator, if applicable. The example uses {@code ':'}.
	 * @return the string representation
	 *
	 * @see #convertMaskToHexString(long, int, boolean, int, String)
	 * @see #convertHexStringToMaskedValue(AtomicLong, AtomicLong, String, int, int, String)
	 */
	public static String convertMaskedValueToHexString(long msk, long val, int n, boolean truncate,
			int spaceevery, String spacer) {
		StringBuilder sb = new StringBuilder(n * 4);
		int shamt = (n * 4 - 4);
		final long LEFT_NIBBLE = 0x0fL << shamt;
		final long LEFT_BIT = 0x08L << shamt;

		for (int i = 0; i < n; i++) {
			if (!truncate && spaceevery != 0 && i != 0 && i % spaceevery == 0) {
				sb.append(spacer);
			}
			long m = msk & LEFT_NIBBLE;
			if (m == 0L) { // fully-undefined nibble: either truncate or append X
				msk <<= 4;
				val <<= 4;
				if (truncate) {
					continue;
				}
				sb.append('X');
			}
			else if (m == LEFT_NIBBLE) { // fully-defined nibble: append hex digit
				sb.append(String.format("%1X", (val & LEFT_NIBBLE) >>> shamt));
				msk <<= 4;
				val <<= 4;
			}
			else { // partially-defined nibble: append bracketed bits
				sb.append('[');
				for (int j = 0; j < 4; j++) {
					if ((msk & LEFT_BIT) == 0) {
						sb.append('x');
					}
					else if ((val & LEFT_BIT) == 0) {
						sb.append('0');
					}
					else {
						sb.append('1');
					}
					msk <<= 1;
					val <<= 1;
				}
				sb.append(']');
			}
			truncate = false;
		}
		if (sb.length() == 0 && n != 0) {
			return "X";
		}
		return sb.toString();
	}

	/**
	 * Convert a mask to a hexadecimal-ish string.
	 *
	 * Converts the mask in a similar way to
	 * {@link #convertMaskedValueToHexString(long, long, int, boolean, int, String)}.
	 * Philosophically, it is hexadecimal, but the only valid digits are 0 and F. Any
	 * partially-included nibble will be broken down into bracketed bits. Displaying masks in this
	 * way is convenient when shown proximal to related masked values.
	 * 
	 * @param msk the mask
	 * @param n the number of nibbles, starting at the right
	 * @param truncate true if leading Xs may be truncated
	 * @param spaceevery how many nibbles in spaced groups, 0 for no spaces
	 * @param spacer the group separator, if applicable
	 * @return the string representation
	 *
	 * @see #convertMaskedValueToHexString(long, long, int, boolean, int, String)
	 * @see #convertHexStringToMaskedValue(AtomicLong, AtomicLong, String, int, int, String)
	 */
	public static String convertMaskToHexString(long msk, int n, boolean truncate, int spaceevery,
			String spacer) {
		StringBuilder sb = new StringBuilder(n * 4);
		int shamt = (n * 4 - 4);
		final long LEFT_NIBBLE = 0x0fL << shamt;
		final long LEFT_BIT = 0x08L << shamt;

		for (int i = 0; i < n; i++) {
			if (!truncate && spaceevery != 0 && i != 0 && i % spaceevery == 0) {
				sb.append(spacer);
			}
			long m = msk & LEFT_NIBBLE;
			if (m == 0L) { // fully-excluded nibble: either truncate or append 0
				if (truncate) {
					continue;
				}
				sb.append('0');
				msk <<= 4;
			}
			else if (m == LEFT_NIBBLE) { // fully-included nibble: append F
				sb.append('F');
				msk <<= 4;
			}
			else { // partially-defined nibble: append bracketed bits
				sb.append('[');
				for (int j = 0; j < 4; j++) {
					if ((msk & LEFT_BIT) == 0) {
						sb.append('0');
					}
					else {
						sb.append('1');
					}
					msk <<= 1;
				}
				sb.append(']');
			}
			truncate = false;
		}
		if (sb.length() == 0 && n != 0) {
			return "X";
		}
		return sb.toString();
	}

	/**
	 * The reverse of {@link #convertMaskedValueToHexString(long, long, int, boolean, int, String)}
	 * 
	 * @param msk an object to receive the resulting mask
	 * @param val an object to receive the resulting value
	 * @param hex the input string to parse
	 * @param n the number of nibbles to parse (they are stored right aligned in the result)
	 * @param spaceevery how many nibbles are expected between spacers
	 * @param spacer the spacer
	 *
	 * @see #convertMaskedValueToHexString(long, long, int, boolean, int, String)
	 * @see #convertMaskToHexString(long, int, boolean, int, String)
	 */
	public static void convertHexStringToMaskedValue(AtomicLong msk, AtomicLong val, String hex,
			int n, int spaceevery, String spacer) {
		long lmsk = 0;
		long lval = 0;
		int pos = 0;
		int i = 0;
		while (pos < hex.length() && i < n) {
			lmsk <<= 4;
			lval <<= 4;
			if (i != 0 && spaceevery != 0 && i % spaceevery == 0) {
				boolean matchspacer = hex.regionMatches(pos, spacer, 0, spacer.length());
				if (!matchspacer) {
					throw new NumberFormatException("Missing spacer at " + pos);
				}
				pos += spacer.length();
				continue;
			}
			char c = hex.charAt(pos);
			if (Character.isLetterOrDigit(c)) { // a hex digit, defined or not
				if (c == 'X') { // undefined
					// Write to neither. Just shift.
					i++;
					pos++;
					continue;
				}
				// Try defined
				long nibble = Long.parseLong(hex.substring(pos, pos + 1), 16);
				lmsk |= 0x0fL;
				lval |= nibble;
				i++;
				pos++;
				continue;
			}
			if (c == '[') { // A partially-defined nibble. Parse bits
				lmsk >>= 4; // EW
				lval >>= 4; // EW
				for (int j = 0; j < 4; j++) {
					pos++;
					lmsk <<= 1;
					lval <<= 1;
					if (pos > hex.length()) {
						throw new NumberFormatException("Missing one or more bits at " + pos);
					}
					c = hex.charAt(pos);
					if (c == 'x') { // undefined. Just let it shift.
						continue;
					}
					lmsk |= 1; // defined, so write the mask
					if (c == '0') {
						continue; // Mask already written
					}
					if (c == '1') {
						lval |= 1;
						continue;
					}
					throw new NumberFormatException("Illegal character '" + c + "' at " + pos);
				}
				pos++;
				if (pos > hex.length() || hex.charAt(pos) != ']') {
					throw new NumberFormatException("Missing closing bracket after bits at " + pos);
				}
				pos++;
				i++;
				continue;
			}
			throw new NumberFormatException("Illegal character '" + c + "' at " + pos);
		}
		if (pos < hex.length()) {
			throw new NumberFormatException("Gratuitous characters starting at " + pos);
		}
		if (i < n) {
			throw new NumberFormatException("Too few characters for " + n + " nibbles. Got " + i);
		}
		msk.set(lmsk);
		val.set(lval);
	}

	/**
	 * Render <code>number</code> in different bases using the default signedness mode.
	 * <p>
	 * This invokes {@linkplain #formatNumber(long, int, SignednessFormatMode)} with a
	 * <code>mode</code> parameter of <code>{@linkplain SignednessFormatMode#DEFAULT}</code>.
	 *
	 * @param number The number to represent
	 * @param radix the base in which <code>number</code> is represented
	 * @return formatted string of the number parameter in provided radix base
	 * @see #formatNumber(long, int, SignednessFormatMode)
	 */
	public static String formatNumber(long number, int radix) {
		return formatNumber(number, radix, SignednessFormatMode.DEFAULT);
	}

	/**
	 * Provide renderings of <code>number</code> in different bases:
	 * <ul>
	 * <li><code>0</code> - renders <code>number</code> as an escaped character sequence</li>
	 * <li><code>2</code> - renders <code>number</code> as a <code>base-2</code> integer</li>
	 * <li><code>8</code> - renders <code>number</code> as a <code>base-8</code> integer</li>
	 * <li><code>10</code> - renders <code>number</code> as a <code>base-10</code> integer</li>
	 * <li><code>16</code> (default) - renders <code>number</code> as a <code>base-16</code>
	 * integer</li>
	 * </ul>
	 * <table>
	 * <caption></caption>
	 * <tr>
	 * <th>Number</th>
	 * <th>Radix</th>
	 * <th>DEFAULT Mode Alias</th>
	 * <th style="text-align:center"><i>UNSIGNED</i> Mode Value</th>
	 * <th><i>SIGNED</i> Mode Value</th>
	 * </tr>
	 * <tr>
	 * <td>&nbsp;</td>
	 * <td></td>
	 * <td><i></i></td>
	 * <td></td>
	 * <td></td>
	 * </tr>
	 * <tr style="text-align:right;font-family: monospace">
	 * <td>100</td>
	 * <td>2</td>
	 * <td><i>UNSIGNED</i></td>
	 * <td>1100100b</td>
	 * <td>1100100b</td>
	 * </tr>
	 * <tr style="text-align:right;font-family: monospace">
	 * <td>100</td>
	 * <td>8</td>
	 * <td><i>UNSIGNED</i></td>
	 * <td>144o</td>
	 * <td>144o</td>
	 * </tr>
	 * <tr style="text-align:right;font-family: monospace">
	 * <td>100</td>
	 * <td>10</td>
	 * <td><i>SIGNED</i></td>
	 * <td>100</td>
	 * <td>100</td>
	 * </tr>
	 * <tr style="text-align:right;font-family: monospace">
	 * <td>100</td>
	 * <td>16</td>
	 * <td><i>UNSIGNED</i></td>
	 * <td>64h</td>
	 * <td>64h</td>
	 * </tr>
	 * <tr>
	 * <td>&nbsp;</td>
	 * <td></td>
	 * <td><i></i></td>
	 * <td></td>
	 * <td></td>
	 * </tr>
	 * <tr style="text-align:right;font-family: monospace">
	 * <td>-1</td>
	 * <td>2</td>
	 * <td><i>UNSIGNED</i></td>
	 * <td>1111111111111111111111111111111111111111111111111111111111111111b</td>
	 * <td>-1b</td>
	 * </tr>
	 * <tr style="text-align:right;font-family: monospace">
	 * <td>-1</td>
	 * <td>8</td>
	 * <td><i>UNSIGNED</i></td>
	 * <td>1777777777777777777777o</td>
	 * <td>-1o</td>
	 * </tr>
	 * <tr style="text-align:right;font-family: monospace">
	 * <td>-1</td>
	 * <td>10</td>
	 * <td><i>SIGNED</i></td>
	 * <td>18446744073709551615</td>
	 * <td>-1</td>
	 * </tr>
	 * <tr style="text-align:right;font-family: monospace">
	 * <td>-1</td>
	 * <td>16</td>
	 * <td><i>UNSIGNED</i></td>
	 * <td>ffffffffffffffffh</td>
	 * <td>-1h</td>
	 * </tr>
	 * <tr>
	 * <td>&nbsp;</td>
	 * <td></td>
	 * <td><i></i></td>
	 * <td></td>
	 * <td></td>
	 * </tr>
	 * <tr style="text-align:right;font-family: monospace">
	 * <td>-100</td>
	 * <td>2</td>
	 * <td><i>UNSIGNED</i></td>
	 * <td>1111111111111111111111111111111111111111111111111111111110011100b</td>
	 * <td>-1100100b</td>
	 * </tr>
	 * <tr style="text-align:right;font-family: monospace">
	 * <td>-100</td>
	 * <td>8</td>
	 * <td><i>UNSIGNED</i></td>
	 * <td>1777777777777777777634o</td>
	 * <td>-144o</td>
	 * </tr>
	 * <tr style="text-align:right;font-family: monospace">
	 * <td>-100</td>
	 * <td>10</td>
	 * <td><i>SIGNED</i></td>
	 * <td>18446744073709551516</td>
	 * <td>-100</td>
	 * </tr>
	 * <tr style="text-align:right;font-family: monospace">
	 * <td>-100</td>
	 * <td>16</td>
	 * <td><i>UNSIGNED</i></td>
	 * <td>ffffffffffffff9ch</td>
	 * <td>-64h</td>
	 * </tr>
	 * </table>
	 * 
	 * @param number The number to represent
	 * @param radix The base in which <code>number</code> is represented
	 * @param mode Specifies how the number is formatted with respect to its signed-ness
	 * @return number string in the given base
	 */
	public static String formatNumber(long number, int radix, SignednessFormatMode mode) {
		if (radix == 0) {
			byte[] bytes = new byte[8];
			bytes[0] = (byte) (number >> 56);
			bytes[1] = (byte) (number >> 48);
			bytes[2] = (byte) (number >> 40);
			bytes[3] = (byte) (number >> 32);
			bytes[4] = (byte) (number >> 24);
			bytes[5] = (byte) (number >> 16);
			bytes[6] = (byte) (number >> 8);
			bytes[7] = (byte) (number >> 0);
			return StringUtilities.toQuotedString(bytes);
		}

		IntegerRadixRenderer renderer = null;
		switch (mode) {
			case SIGNED:
				renderer = SIGNED_INTEGER_RENDERER;
				break;
			case UNSIGNED:
				renderer = UNSIGNED_INTEGER_RENDERER;
				break;
			case DEFAULT:
				renderer = DEFAULT_INTEGER_RENDERER;
				break;
		}
		return renderer.toString(number, radix);

	}

	/**
	 * Parse hexadecimal digits into a byte array.
	 *
	 * @param hexString hexadecimal digits
	 * @return numeric value as a byte array, or null if string contains invalid hex characters.
	 */
	public static byte[] convertStringToBytes(String hexString) {

		CharSequence characters = condenseByteString(hexString);
		return convertCharSequenceToBytes(characters);
	}

	private static CharSequence condenseByteString(String hexString) {

		if (!StringUtils.containsAny(hexString, ' ', ',')) {
			return hexString;
		}

		String[] parts = hexString.split("[ ,]");
		StringBuilder buffy = new StringBuilder();
		for (String s : parts) {
			if (s.length() == 1) {
				s = "0" + s;
			}
			buffy.append(s);
		}

		return buffy;
	}

	private static byte[] convertCharSequenceToBytes(CharSequence characters) {

		// assumption: no separators

		if (characters.length() % 2 == 1) {
			throw new IllegalArgumentException("Hex string must be an even number of characters");
		}

		try {
			byte[] bytes = new byte[characters.length() / 2];
			for (int i = 0; i < characters.length(); i += 2) {
				CharSequence bs = characters.subSequence(i, i + 2);
				bytes[i / 2] = (byte) Integer.parseInt(bs.toString(), 16);
			}
			return bytes;
		}
		catch (Exception e) {
			// tried, but failed
		}

		return null;
	}

	/**
	 * Convert the given byte into a two character String, padding with a leading 0 if needed.
	 *
	 * @param b the byte
	 * @return the byte string
	 */
	public static String toString(byte b) {
		String bs = Integer.toHexString(b & 0xff);
		if (bs.length() == 1) {
			return "0" + bs;
		}
		return bs;
	}

	/**
	 * Convert a byte array into a hexadecimal string.
	 *
	 * @param bytes byte array
	 * @return hex string representation
	 */
	public static String convertBytesToString(byte[] bytes) {
		return convertBytesToString(bytes, null);
	}

	/**
	 * Convert a byte array into a hexadecimal string.
	 *
	 * @param bytes byte array
	 * @param delimeter the text between byte strings
	 * @return hex string representation
	 */
	public static String convertBytesToString(byte[] bytes, String delimeter) {
		if (bytes == null) {
			return null;
		}
		return convertBytesToString(bytes, 0, bytes.length, delimeter);
	}

	/**
	 * Convert a byte array into a hexadecimal string.
	 *
	 * @param bytes byte array
	 * @param start start index
	 * @param len number of bytes to convert
	 * @param delimeter the text between byte strings
	 * @return hex string representation
	 */
	public static String convertBytesToString(byte[] bytes, int start, int len, String delimeter) {

		Iterator<Byte> iterator = IteratorUtils.arrayIterator(bytes, start, start + len);
		return convertBytesToString(iterator, delimeter);
	}

	/**
	 * Convert a bytes into a hexadecimal string.
	 *
	 * @param bytes an iterator of bytes
	 * @param delimiter the text between byte strings; null is allowed
	 * @return hex string representation
	 */
	public static String convertBytesToString(Iterator<Byte> bytes, String delimiter) {

		return convertBytesToString(() -> bytes, delimiter);
	}

	/**
	 * Convert a bytes into a hexadecimal string.
	 *
	 * @param bytes an iterable of bytes
	 * @param delimiter the text between byte strings; null is allowed
	 * @return hex string representation
	 */
	public static String convertBytesToString(Iterable<Byte> bytes, String delimiter) {
		return convertBytesToString(CollectionUtils.asStream(bytes), delimiter);
	}

	/**
	 * Convert a bytes into a hexadecimal string.
	 *
	 * @param bytes an stream of bytes
	 * @param delimiter the text between byte strings; null is allowed
	 * @return hex string representation
	 */
	public static String convertBytesToString(Stream<Byte> bytes, String delimiter) {

		delimiter = (delimiter == null) ? "" : delimiter;
		return bytes.map(NumericUtilities::toString).collect(Collectors.joining(delimiter));
	}

	/**
	 * Determine if the provided Number is an integer type -- Byte, Short, Integer, or Long.
	 * 
	 * @param number the object to check for for integer-type
	 * @return true if the provided number is an integer-type, false otherwise
	 */
	public static boolean isIntegerType(Number number) {
		Class<? extends Number> numClass = number.getClass();
		return isIntegerType(numClass);
	}

	/**
	 * Determine if the provided Number class is an integer type.
	 * 
	 * @param numClass Class of an object
	 * @return true if the class parameter is a integer type, false otherwise
	 */
	public static boolean isIntegerType(Class<?> numClass) {
		return INTEGER_TYPES.contains(numClass);
	}

	/**
	 * Determine if the provided Number is a floating-point type -- Float or Double.
	 * 
	 * @param number the object to check for for floating-point-type
	 * @return true if the provided number is a floating-point-type, false otherwise
	 */
	public static boolean isFloatingPointType(Number number) {
		Class<? extends Number> numClass = number.getClass();
		return isFloatingPointType(numClass);
	}

	/**
	 * Determine if the provided Number class is a floating-point type.
	 * 
	 * @param numClass Class of an object
	 * @return true if the class parameter is a floating-point type, false otherwise
	 */
	public static boolean isFloatingPointType(Class<?> numClass) {
		return FLOATINGPOINT_TYPES.contains(numClass);
	}

	/**
	 * Provides the protocol for rendering integer-type numbers in different signed-ness modes.
	 */
	private static interface IntegerRadixRenderer {
		/**
		 * Format the given number in the provided radix base.
		 * 
		 * @param number the number to render
		 * @param radix the base in which to render
		 * @return a string representing the provided number in the given base
		 */
		public String toString(long number, int radix);

	}

	/**
	 * Renders provided numbers as signed values
	 */
	private final static class SignedIntegerRadixRenderer implements IntegerRadixRenderer {
		/**
		 * {@inheritDoc}
		 * <p>
		 * All values are rendered in their <i>signed</i> form
		 **/
		@Override
		public String toString(long number, int radix) {
			switch (radix) {
				case 2:
					return Long.toString(number, radix) + "b";
				case 8:
					return Long.toString(number, radix) + "o";
				case 10:
					return Long.toString(number, radix);
				case 16:
					return Long.toString(number, radix) + "h";
			}
			throw new IllegalArgumentException("Unsupported radix");
		}
	}

	/**
	 * Renders provided numbers as unsigned values
	 */
	private final static class UnsignedIntegerRadixRenderer implements IntegerRadixRenderer {
		/**
		 * {@inheritDoc}
		 * <p>
		 * All values are rendered in their <i>unsigned</i> form
		 **/
		@Override
		public String toString(long number, int radix) {
			switch (radix) {
				case 2:
					return Long.toBinaryString(number) + "b";
				case 8:
					return Long.toOctalString(number) + "o";
				case 10:
					return Long.toUnsignedString(number);
				case 16:
					return Long.toHexString(number) + "h";
			}
			throw new IllegalArgumentException("Unsupported radix");
		}
	}

	/**
	 * Renders provided numbers in a more human-friendly manner
	 */
	private final static class DefaultIntegerRadixRenderer implements IntegerRadixRenderer {
		/**
		 * {@inheritDoc}
		 * <p>
		 * Values to be rendered in binary, octal, or hexadecimal bases are rendered as unsigned,
		 * numbers rendered in decimal are rendered as signed.
		 */
		@Override
		public String toString(long number, int radix) {
			switch (radix) {
				case 2:
					return new UnsignedIntegerRadixRenderer().toString(number, radix);
				case 8:
					return new UnsignedIntegerRadixRenderer().toString(number, radix);
				case 10:
					return new SignedIntegerRadixRenderer().toString(number, radix);
				case 16:
					return new UnsignedIntegerRadixRenderer().toString(number, radix);
			}
			throw new IllegalArgumentException("Unsupported radix");
		}
	}

}
