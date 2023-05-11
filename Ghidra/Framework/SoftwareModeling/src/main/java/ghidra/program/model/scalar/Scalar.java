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
package ghidra.program.model.scalar;

import java.math.BigInteger;

/**
 * The Scalar defines a immutable integer stored in an arbitrary number of bits (0..64), along
 * with a preferred signed-ness attribute.
 */
public class Scalar {
	private final long value;
	private final byte bitLength;
	private final byte unusedBits; // complement of bitLength
	private final boolean signed;

	/**
	 * Construct a new signed scalar object.
	 * 
	 * @param bitLength number of bits, valid values are 1..64, or 0 if value is also 0
	 * @param value value of the scalar, any bits that are set above bitLength will be ignored
	 */
	public Scalar(int bitLength, long value) {
		this(bitLength, value, true);
	}

	/**
	 * Construct a new scalar.
	 * 
	 * @param bitLength number of bits, valid values are 1..64, or 0 if value is also 0
	 * @param value value of the scalar, any bits that are set above bitLength will be ignored
	 * @param signed true for a signed value, false for an unsigned value.
	 */
	public Scalar(int bitLength, long value, boolean signed) {
		if (!(bitLength == 0 && value == 0) && (bitLength < 1 || bitLength > 64)) {
			throw new IllegalArgumentException("Bit length must be >= 1 and <= 64");
		}
		this.signed = signed;
		this.bitLength = (byte) bitLength;
		this.unusedBits = (byte)(64 /*sizeof(long)*8*/ - bitLength);
		this.value = (value << unusedBits) >>> unusedBits; // eliminate upper bits that are outside bitLength
	}

	/**
	 * Returns true if scalar was created as a signed value
	 * 
	 * @return boolean true if this scalar was created as a signed value, false if was created as
	 * unsigned
	 */
	public boolean isSigned() {
		return signed;
	}

	/**
	 * Get the value as a signed long, where the highest bit of the value, if set, will be 
	 * extended to fill the remaining bits of a java long.
	 * 
	 * @return signed value
	 */
	public long getSignedValue() {
		return (value << unusedBits) >> unusedBits; // if value has highbit set, sign extend it
	}

	/**
	 * Get the value as an unsigned long.
	 * 
	 * @return unsigned value
	 */
	public long getUnsignedValue() {
		return value;
	}

	/**
	 * Returns the value in its preferred signed-ness.  See {@link #getSignedValue()} and
	 * {@link #getUnsignedValue()}.
	 * 
	 * @return value, as either signed or unsigned, depending on how this instance was created
	 */
	public long getValue() {
		return signed ? getSignedValue() : value;
	}

	/**
	 * {@return the value, using the specified signedness.  Equivalent to calling getSignedValue()
	 * or getUnsignedValue()}
	 * 
	 * @param signednessOverride true for a signed value, false for an unsigned value
	 */
	public long getValue(boolean signednessOverride) {
		return signednessOverride ? getSignedValue() : value;
	}

	/**
	 * Returns the BigInteger representation of the value.
	 * 
	 * @return new BigInteger representation of the value
	 */
	public BigInteger getBigInteger() {
		int signum = (signed && testBit(bitLength - 1)) ? -1 : 1;

		// Get magnitude
		int numBytes = ((bitLength - 1) / 8) + 1;
		long tmpVal = getValue();
		if (signed && tmpVal < 0) {
			tmpVal = -tmpVal;
		}
		byte[] data = new byte[numBytes];
		for (int i = (numBytes - 1); i >= 0; --i) {
			data[i] = (byte) tmpVal;
			tmpVal >>= 8;
		}

		return new BigInteger(signum, data);
	}

	/**
	 * <p>Returns a byte array representing this Scalar.  The size of
	 * the byte array is the number of bytes required to hold the
	 * number of bits returned by <CODE>bitLength()</CODE>.</p>
	 *
	 * @return a big-endian byte array containing the bits in this Scalar.
	 */
	public byte[] byteArrayValue() {
		int numBytes = ((bitLength - 1) / 8) + 1;
		long tmpVal = getValue();
		byte[] data = new byte[numBytes];
		for (int i = numBytes - 1; i >= 0; i--) {
			data[i] = (byte) tmpVal;
			tmpVal >>= 8;
		}
		return data;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == null) {
			return false;
		}
		if (obj == this) {
			return true;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		Scalar other = (Scalar) obj;
		long v = getValue();
		if (v != other.getValue()) {
			return false;
		}
		if (v < 0) {
			if (bitLength == 64 || other.bitLength == 64) {
				// if both values are negative ensure that they have
				// the same signed-ness
				return signed == other.signed;
			}
		}
		return true;
	}

	@Override
	public int hashCode() {
		return Long.hashCode(value);
	}

	/**
	 * <p>The size of this Scalar in bits.  This is constant for a
	 * Scalar.  It is not dependent on the particular value of the scalar.
	 * For example, a 16-bit Scalar should always return 16 regardless of the
	 * actual value held.</p>
	 *
	 * @return the width of this Scalar.
	 */
	public int bitLength() {
		return bitLength;
	}

	/**
	 * <p>Returns true if and only if the designated bit is set to one.
	 * Computes ((this &amp; (1&lt;&lt;n)) != 0).  Bits are numbered
	 * 0..bitlength()-1 with 0 being the least significant bit.</p>
	 *
	 * @param n the bit to test.
	 * @return true if and only if the designated bit is set to one.
	 *
	 * @throws IndexOutOfBoundsException if n &gt;= bitLength().
	 */
	public boolean testBit(int n) {
		if (n < 0 || n > bitLength - 1) {
			throw new IllegalArgumentException();
		}
		return (value & (1L << n)) != 0;
	}

	/**
	 * <p>Get a String representing this Scalar using the
	 * format defined by radix.</p>
	 * @param radix an integer base to use in representing the number
	 *  (only 2, 8, 10, 16 are valid).  If 10 is specified, all
	 *  remaining parameters are ignored.
	 * @param zeroPadded a boolean which if true will have the
	 *  number left padded with 0 to the width necessary to hold
	 *  the maximum value.
	 * @param showSign if true the '-' sign will be prepended for negative values, else
	 * value will be treated as an unsigned value and output without a sign.
	 * @param pre a String to append after the sign (if signed) but before
	 *  the digits.
	 * @param post a String to append after the digits.
	 *
	 * @return a String representation of this scalar.
	 *
	 * @throws IllegalArgumentException If radix is not valid.
	 */
	public String toString(int radix, boolean zeroPadded, boolean showSign, String pre,
			String post) {
		if (!signed) {
			showSign = false;
		}

		long val;
		if (showSign) {
			val = getSignedValue();
			int shiftCnt = 64 - bitLength;
			val <<= shiftCnt;
			val >>= shiftCnt;
		}
		else {
			val = getUnsignedValue();
		}

		String b;
		StringBuffer buf = new StringBuffer(32);
		if (bitLength == 64 && !signed) {
			b = getBigInteger().toString(radix);
		}
		else if (radix == 10) {
			b = Long.toString(val);
		}
		else {
			if (showSign) {
				if (val < 0) {
					val = -val;
					buf.append('-');
				}
			}
			switch (radix) {
				case 2:
					b = Long.toBinaryString(val);
					break;
				case 8:
					b = Long.toOctalString(val);
					break;
				case 16:
					b = Long.toHexString(val);
					break;
				default:
					throw new IllegalArgumentException("Invalid radix");
			}
		}
		buf.append(pre);
		if (zeroPadded) {
			int numDigits = getDigits(radix);
			for (int i = 0; i < numDigits - b.length(); ++i) {
				buf.append("0");
			}
		}
		buf.append(b);
		buf.append(post);
		return new String(buf);
	}

	@Override
	public String toString() {
		return toString(16, false, true, "0x", "");
	}

	private int getDigits(int radix) {
		switch (radix) {
			case 2:
				return bitLength;
			case 8:
				return (bitLength - 1) / 3 + 1;
			case 16:
				return (bitLength - 1) / 4 + 1;
			default:
				return 0;
		}
	}
}
