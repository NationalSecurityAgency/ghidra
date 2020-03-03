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
 * <p>
 * The Scalar defines a immutable fixed bit signed integer.
 * Bit operations on a Scalar expect Scalar to act as a number in the
 * two's complement format. Scalar was designed to be used as an
 * offset (difference between two Addresses), an arithmetic operand,
 * and also potentially for simulating registers.
 * </p>
 *
 * <p>
 * If an operation varies depending on whether the Scalar is
 * treated as signed or unsigned, there are usally two version such as
 * multiply and unsignedMultiply.  Please note that this means that
 * the Comparable interface treats the number as signed.
 * </p>
 */
public class Scalar implements Comparable<Scalar> {
	private static final long[] BITMASKS = new long[65];

	static {
		// populate the BITMASKS for each possible bit length
		// up to 64
		long value = 1;
		for (int i = 1; i < 65; ++i) {
			BITMASKS[i] = value;
			value = (value << 1) + 1;
		}
	}

	private byte bitLength;
	private long value;
	private boolean signed;

	/**
	 * Constructor
	 * @param bitLength number of bits
	 * @param value value of the scalar
	 * @param signed true for a signed value, false for an unsigned value.
	 */
	public Scalar(int bitLength, long value, boolean signed) {
		this.signed = signed;
		if (!(bitLength == 0 && value == 0) && (bitLength < 1 || bitLength > 64)) {
			throw new IllegalArgumentException("Bit length must be >= 1 and <= 64");
		}
		this.bitLength = (byte) bitLength;

		this.value = value & BITMASKS[bitLength];
	}

	/**
	 * Returns true if scalar was created as a signed value
	 */
	public boolean isSigned() {
		return signed;
	}

	/**
	 * Constructor a new signed scalar object.
	 * @param bitLength number of bits
	 * @param value value of the scalar
	 */
	public Scalar(int bitLength, long value) {
		this(bitLength, value, true);
	}

	/**
	 * Get the value as signed.
	 */
	public long getSignedValue() {
		if (value == 0) {  // just in case the bitLength is 0
			return 0;
		}
		if (testBit(bitLength - 1)) {
			return (value | (~BITMASKS[bitLength]));
		}
		return value;
	}

	/**
	 * Get the value as unsigned.
	 */
	public long getUnsignedValue() {
		if (value == 0) {  // just in case the bitLength is 0
			return 0;
		}
		return (value & BITMASKS[bitLength]);
	}

	/**
	 * Returns the value as a signed value if it was created signed, otherwise the value is
	 * returned as an unsigned value
	 */
	public long getValue() {
		return signed ? getSignedValue() : value;
	}

	/**
	 * Returns the BigInteger representation of the value.
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
	 * <p>Creates a new Scalar of the same size as this scalar but with the
	 * given value
	 *
	 * @param  newValue  the Scalar value which will be used to initialize
	 *  the new Scalar.
	 * @return  the new Scalar.
	 */
	public Scalar newScalar(long newValue) {
		return new Scalar(bitLength, newValue, signed);
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

	/**
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
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
		return (int) (value ^ (value >>> 32));
	}

	/**
	 * @see java.lang.Comparable#compareTo(java.lang.Object)
	 */
	@Override
	public int compareTo(Scalar other) {
		if (bitLength == 64 || other.bitLength == 64) {
			return getBigInteger().compareTo(other.getBigInteger());
		}
		long v = getValue() - other.getValue();
		if (v > 0) {
			return 1;
		}
		else if (v < 0) {
			return -1;
		}
		return 0;
	}

	/**
	 * <p>Adds the integer n to <code>this</code>.
	 * Computes (<code>this = this + n</code>).
	 * @param n the value to add to this scalars value to produce a new scalar.
	 */
	public Scalar add(long n) {
		return new Scalar(bitLength, (value + n) & BITMASKS[bitLength]);
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
	 * <p>The bit number n in this Scalar is set to zero.  Computes
	 * (this = this &amp; ~(1&lt;&lt;n)).  Bits are numbered 0..bitlength()-1
	 * with 0 being the least significant bit.</p>
	 * @param n the bit to clear in this scalar.
	 *
	 * @throws  IndexOutOfBoundsException if n &gt;= bitLength().
	 */
	public Scalar clearBit(int n) {
		if (n < 0 || n > bitLength - 1) {
			throw new IllegalArgumentException();
		}
		return new Scalar(bitLength, value & ~(1 << n));
	}

	/**
	 * <p>The bit number n in this Scalar is flipped.  Computes
	 * (this = this ^ (1&lt;&lt;n)).  Bits are numbered 0..bitlength()-1
	 * with 0 being the least significant bit.</p>
	 * @param n the bit to flip.
	 * @throws  IndexOutOfBoundsException if n &gt;= bitLength().
	 */
	public Scalar flipBit(int n) {
		if (n < 0 || n > bitLength - 1) {
			throw new IllegalArgumentException();
		}
		return new Scalar(bitLength, value ^ (1 << n));
	}

	/**
	 * <p>The bit number n in this Scalar is set to one.  Computes
	 * (this = this | (1&lt;&lt;n)).  Bits are numbered 0..bitlength()-1
	 * with 0 being the least significant bit.</p>
	 *
	 * @param n the bit to set.
	 * @throws  IndexOutOfBoundsException if n &gt;= bitLength().
	 */
	public Scalar setBit(int n) {
		if (n < 0 || n > bitLength - 1) {
			throw new IllegalArgumentException();
		}
		return new Scalar(bitLength, value | (1 << n));
	}

	/**
	 * <p>Sets <code>this = this &lt;&lt; n</code>.</p>
	 * @param n the number of bits to shift left.
	 * @throws ArithmeticException if n &lt; 0.
	 */
	public Scalar shiftLeft(int n) {
		if (n < 0 || n > bitLength - 1) {
			throw new IllegalArgumentException();
		}
		return new Scalar(bitLength, value << n);
	}

	/**
	 * <p>Sets <code>this = this &gt;&gt; n</code> using 0 as the fill bit.</p>
	 * @param n the number of bits to shift right.
	 * @throws ArithmeticException if n &lt; 0.
	 */
	public Scalar shiftRight(int n) {
		if (n < 0 || n > bitLength - 1) {
			throw new IllegalArgumentException();
		}
		return new Scalar(bitLength, value >>> n);
	}

	/**
	 * <p>Sets <code>this = this &gt;&gt; n</code> replicating the sign bit.</p>
	 * @param n the number of bits to arithmetically shift.
	 * @throws ArithmeticException if n &lt; 0.
	 */
	public Scalar shiftRightSign(int n) {
		if (n < 0 || n > bitLength - 1) {
			throw new IllegalArgumentException();
		}
		return new Scalar(bitLength, value >> n);
	}

	/**
	 * <p>Sets <code>this = this - n</code>.</p>
	 * @param n the value to subtract from this scalar to produce a new scalar.
	 */
	public Scalar subtract(long n) {
		return add(-n);
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
		return (value & (1 << n)) != 0;
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

	/**
	 * @see java.lang.Object#toString()
	 */
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
