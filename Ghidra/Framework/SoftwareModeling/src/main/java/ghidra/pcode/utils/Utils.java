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
package ghidra.pcode.utils;

import java.math.BigInteger;

import ghidra.util.BigEndianDataConverter;
import ghidra.util.LittleEndianDataConverter;

public class Utils {

	public static final String endl = System.getProperty("line.separator");

	private static long[] uintbmasks = { 0, 0xff, 0xffff, 0xffffff, 0xffffffffL, 0xffffffffffL,
		0xffffffffffffL, 0xffffffffffffffL, 0xffffffffffffffffL };

	public static BigInteger convertToSignedValue(BigInteger val, int byteSize) {
		int signbit = (byteSize * 8) - 1;
		if (val.signum() < 0 || !val.testBit(signbit)) {
			return val; // positive value or already signed
		}
		return val.subtract(BigInteger.ONE.shiftLeft(signbit + 1));
	}

	public static BigInteger convertToUnsignedValue(BigInteger val, int byteSize) {
		if (val.signum() >= 0) {
			return val;
		}
		BigInteger mask = BigInteger.ONE.shiftLeft(byteSize * 8).subtract(BigInteger.ONE);
		return val.and(mask);
	}

	public static long calc_mask(int size) {
		return uintbmasks[(size < 8) ? size : 8];
	}

	public static BigInteger calc_bigmask(int size) {
		return BigInteger.ONE.shiftLeft(size * 8).subtract(BigInteger.ONE);
	}

	/**
	 * {@return true if signbit is set (negative)}
	 * 
	 * @param val the raw value as a long
	 * @param size the actual size (in bytes) of the value
	 */
	public static boolean signbit_negative(long val, int size) {
		long mask = 0x80;
		mask <<= 8 * (size - 1);
		return ((val & mask) != 0);
	}

	public static long uintb_negate(long in, int size) { // Invert bits
		return ((~in) & calc_mask(size));
	}

	public static long sign_extend(long in, int sizein, int sizeout) {
		int signbit;
		long mask;

		signbit = sizein * 8 - 1;
		in &= calc_mask(sizein);
		if (sizein >= sizeout) {
			return in;
		}
		if ((in >>> signbit) != 0) {
			mask = calc_mask(sizeout);
			long tmp = mask << signbit; // Split shift into two pieces
			tmp = (tmp << 1) & mask; // In case, everything is shifted out
			in |= tmp;
		}
		return in;
	}

	// this used to void and changed the parameter val - can't do it in java
	public static long zzz_sign_extend(long val, int bit) { // Sign extend -val- above -bit-
		long mask = 0;
		mask = (~mask) << bit;
		if (((val >>> bit) & 1) != 0) {
			val |= mask;
		}
		else {
			val &= (~mask);
		}
		return val;
	}

	// this used to void and changed the parameter val - can't do it in java
	public static long zzz_zero_extend(long val, int bit) { // Clear all bits in -val- above
															// -bit-
		long mask = 0;
		mask = (~mask) << bit;
		mask <<= 1;
		val &= (~mask);
		return val;
	}

	// this used to be void and changed the parameter val - can't do it in java
	/**
	 * Swap the least-significant bytes of the given value
	 * <p>
	 * The size must be less than 8, as that is the largest possible size of the given value. If
	 * size is larger than 8, there may be undefined behavior, e.g., bytes getting truncated.
	 * 
	 * @param val the value whose bytes to swap
	 * @param size the number of least-signifcant bytes to swap
	 * @return the value with the swapped bytes
	 */
	public static long byte_swap(long val, int size) { // Swap the least sig -size- bytes in val
		long res = 0;
		while (size > 0) {
			res <<= 8;
			res |= (val & 0xff);
			val >>>= 8;
			size -= 1;
		}
		return res;
	}

	long byte_swap(int val) { // Swap the bytes for the whole machine int
		long res = 0;
		for (int i = 0; i < 4; ++i) {
			res <<= 8;
			res |= (val & 0xff);
			val >>>= 8;
		}
		return res;
	}

	public static long bytesToLong(byte[] byteBuf, int size, boolean bigEndian) {
		long value = 0;
		for (int i = 0; i < size; i++) {
			value = value << 8 | (byteBuf[i] & 0xff);
		}
		if (!bigEndian) {
			value = byte_swap(value, size);
		}
		return value;
	}

	public static byte[] longToBytes(long val, int size, boolean bigEndian) {
		long value = val;
		byte[] bytes = new byte[size];
		for (int i = 0; i < size; i++) {
			int index = bigEndian ? size - i - 1 : i;
			bytes[index] = (byte) value;
			value = value >> 8;
		}
		return bytes;
	}

	public static BigInteger bytesToBigInteger(byte[] byteBuf, int size, boolean bigEndian,
			boolean signed) {
		if (bigEndian) {
			return BigEndianDataConverter.INSTANCE.getBigInteger(byteBuf, size, signed);
		}
		return LittleEndianDataConverter.INSTANCE.getBigInteger(byteBuf, size, signed);
	}

	public static byte[] bigIntegerToBytes(BigInteger val, int size, boolean bigEndian) {
		if (bigEndian) {
			return BigEndianDataConverter.INSTANCE.getBytes(val, size);
		}
		return LittleEndianDataConverter.INSTANCE.getBytes(val, size);
	}
}
