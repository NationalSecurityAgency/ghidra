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
package ghidra.pcode.floatformat;

import java.math.*;

import ghidra.pcode.utils.Utils;
import ghidra.util.SystemUtilities;

public strictfp class FloatFormat {
	private static final int INFINITE_SCALE = -(64 * 1024);
	public static final BigDecimal BIG_NaN = null;
	public static final BigDecimal BIG_POSITIVE_INFINITY =
		new BigDecimal(BigInteger.ONE, INFINITE_SCALE);
	public static final BigDecimal BIG_NEGATIVE_INFINITY =
		(new BigDecimal(BigInteger.ONE, INFINITE_SCALE)).negate();

	static final FloatFormat JAVA_FLOAT_FORMAT = new FloatFormat(4);
	static final FloatFormat JAVA_DOUBLE_FORMAT = new FloatFormat(8);

	private final int size; // Size of float in bytes (this format)
	private final int signbit_pos; // Bit position of signbit
	private final int frac_pos; // (lowest) bit position of fractional part
	private final int frac_size; // Number of bits in fractional part
	private final int exp_pos; // (lowest) bit position of exponent
	private final int exp_size; // Number of bits in exponent
	private final int bias; // What to add to real exponent to get encoding
	private final int maxexponent; // maximum stored biased/unsigned exponent
	private final boolean jbitimplied; // true if integer bit of 1 is assumed

	/**
	 * A constant holding the largest positive finite value
	 */
	public final BigFloat maxValue;

	/**
	 * A constant holding the smallest positive normal value
	 */
	public final BigFloat minValue;

	// used in string conversion
	private final MathContext displayContext;

	public int getSize() {
		return size;
	}

	/**
	 * Round {@code bigFloat} using this format's displayContext.
	 * 
	 * @param bigFloat any BigFloat
	 * @return a BigDecimal rounded according to this format's displayContext
	 */
	public BigDecimal round(BigFloat bigFloat) {
		BigDecimal bigDecimal = bigFloat.toBigDecimal();
		if (bigDecimal == null) {
			return null;
		}
		return bigDecimal.round(displayContext);
	}

	// Set format for given size according to IEEE 754 standards
	FloatFormat(int sz) throws UnsupportedFloatFormatException {
		size = sz;

		if (size == 2) {
			signbit_pos = 15;
			exp_pos = 10;
			exp_size = 5;
			frac_pos = 0;
			frac_size = 10;
			bias = 15;
			jbitimplied = true;
			displayContext = new MathContext(7, RoundingMode.HALF_EVEN);
		}
		else if (size == 4) {
			signbit_pos = 31;
			exp_pos = 23;
			exp_size = 8;
			frac_pos = 0;
			frac_size = 23;
			bias = 127;
			jbitimplied = true;
			displayContext = new MathContext(7, RoundingMode.HALF_EVEN);
		}
		else if (size == 8) {
			signbit_pos = 63;
			exp_pos = 52;
			exp_size = 11;
			frac_pos = 0;
			frac_size = 52;
			bias = 1023;
			jbitimplied = true;
			displayContext = new MathContext(16, RoundingMode.HALF_EVEN);
		}
		else if (size == 16) {
			signbit_pos = 127;
			exp_pos = 112;
			exp_size = 15;
			frac_pos = 0;
			frac_size = 112;
			bias = 16383;
			jbitimplied = true;
			displayContext = new MathContext(33, RoundingMode.HALF_EVEN);
		}
		else if (size == 10) {
			signbit_pos = 79;
			exp_pos = 64;
			exp_size = 15;
			frac_pos = 0;
			frac_size = 64;
			bias = 16383;
			jbitimplied = true;
			displayContext = new MathContext(18, RoundingMode.HALF_EVEN);
		}
		else if (size == 12) { // For the Motorola 68000, extended precision, in which bits 80 to 63 are always 0.
			// Note that m68k internal floating point regs are 80-bits, but 96 bits are moved to/from memory.
			// Also note this is not IEEE format.
			signbit_pos = 95;
			exp_pos = 80;
			exp_size = 15;
			frac_pos = 16;
			frac_size = 64;
			bias = 16383;
			jbitimplied = true;
			displayContext = new MathContext(18, RoundingMode.HALF_EVEN);
		}
		else {
			throw new UnsupportedFloatFormatException(sz);
		}
		maxexponent = (1 << exp_size) - 1;

		maxValue = new BigFloat(frac_size, exp_size, FloatKind.FINITE, +1,
			BigInteger.ONE.shiftLeft(frac_size + 1).subtract(BigInteger.ONE),
			(1 << (exp_size - 1)) - 1);
		minValue = new BigFloat(frac_size, exp_size, FloatKind.FINITE, +1, BigInteger.ONE,
			2 - (1 << (exp_size - 1)));

	}

	// Create a double given sign, 8-byte normalized mantissa, and unbiased scale
	static double createFloat(boolean sgn, long mantissa, int scale) {
		long exp = scale + 1023;
		long bits = mantissa >>> 11;// 11 = 64 (long size) - 52 (frac size)  - 1 (jbit))
		if (exp != 1) { // normal
			bits &= 0xfffffffffffffL;
			bits |= exp << 52;
		}

		if (sgn) {
			bits |= 0x8000000000000000L;
		}
		return Double.longBitsToDouble(bits);
	}

	FloatKind extractKind(long l) {
		int exp = extractExponentCode(l);
		if (exp == maxexponent) {
			long frac = extractFractionalCode(l);
			if (frac == 0L) {
				return FloatKind.INFINITE;
			}
			if (frac >>> (frac_size - 1) == 1) {
				return FloatKind.QUIET_NAN;
			}
			return FloatKind.SIGNALING_NAN;
		}
		return FloatKind.FINITE;
	}

	// Extract bits encoding fractional and return un-normalized long value
	private long extractFractionalCode(long x) {
		long mask = (1L << frac_size) - 1;
		x >>>= frac_pos; // Eliminate bits below
		return x & mask;
	}

	// Extract bits encoding fractional and returned un-normalized value
	private BigInteger extractFractionalCode(BigInteger x) {
		BigInteger mask = BigInteger.ONE.shiftLeft(frac_size).subtract(BigInteger.ONE);
		return x.shiftRight(frac_pos).and(mask);
	}

	// Extract the signbit from encoding if size <= 8
	private boolean extractSign(long x) {
		x >>>= signbit_pos;
		return ((x & 1) != 0);
	}

	// Extract the signbit from encoding
	private boolean extractSign(BigInteger x) {
		return x.testBit(signbit_pos);
	}

	// Extract bits encoding exponent if size <= 8
	private int extractExponentCode(long x) {
		x >>>= exp_pos;
		long mask = (1L << exp_size) - 1;
		return (int) (x & mask);
	}

	// Extract bits encoding exponent
	private int extractExponentCode(BigInteger x) {
		return x.shiftRight(exp_pos).intValue() & maxexponent;
	}

	// set sign bit and return the result if size <= 8
	private long setSign(long x, boolean sign) {
		if (!sign)
		 {
			return x; // Assume bit is already zero
		}
		long mask = 1;
		mask <<= signbit_pos;
		x |= mask; // Stick in the bit
		return x;
	}

	// set sign bit and return the result
	private BigInteger setSign(BigInteger x, boolean sign) {
		if (sign) {
			return x.setBit(signbit_pos);
		}
		return x;
	}

	public long getZeroEncoding(boolean sgn) {
		// Use IEEE 754 standard for zero encoding
		return setSign(0, sgn);
	}

	public long getInfinityEncoding(boolean sgn) {
		// Use IEEE 754 standard for infinity encoding
		long res = (long) maxexponent << exp_pos;
		return setSign(res, sgn);
	}

	public BigInteger getBigZeroEncoding(boolean sgn) {
		BigInteger res = BigInteger.ZERO;
		return setSign(res, sgn);
	}

	public Object getBigZero(boolean sgn) {
		return new BigFloat(frac_size, exp_size, FloatKind.FINITE, sgn ? -1 : +1, BigInteger.ZERO,
			2 - (1 << (exp_size - 1)));
	}

	public BigInteger getBigInfinityEncoding(boolean sgn) {
		// Use IEEE 754 standard for infinity encoding
		BigInteger res = BigInteger.valueOf(maxexponent).shiftLeft(exp_pos);
		return setSign(res, sgn);
	}

	public BigFloat getBigInfinity(boolean sgn) {
		return BigFloat.infinity(frac_size, exp_size, sgn ? -1 : 1);
	}

	public long getNaNEncoding(boolean sgn) {
		// Use IEEE 754 standard for NaN encoding
		long res = 1L << (frac_pos + frac_size - 1);
		res |= (long) maxexponent << exp_pos;
		return setSign(res, sgn);
	}

	public BigInteger getBigNaNEncoding(boolean sgn) {
		// Use IEEE 754 standard for NaN encoding
		BigInteger res = BigInteger.ONE.shiftLeft(frac_pos + frac_size - 1);
		res = res.or(BigInteger.valueOf(maxexponent).shiftLeft(exp_pos));
		return setSign(res, sgn);
	}

	public BigFloat getBigNaN(boolean sgn) {
		return BigFloat.quietNaN(frac_size, exp_size, sgn ? -1 : 1);
	}

	public BigFloat getBigFloat(float f) {
		BigFloat bf = FloatFormat.toBigFloat(f);
		return new BigFloat(frac_size, exp_size, bf.kind, bf.sign,
			bf.unscaled.shiftLeft(frac_size - bf.fracbits), bf.scale);
	}

	public BigFloat getBigFloat(double d) {
		BigFloat bf = FloatFormat.toBigFloat(d);
		return new BigFloat(frac_size, exp_size, bf.kind, bf.sign,
			bf.unscaled.shiftLeft(frac_size - bf.fracbits), bf.scale);
	}

	/**
	 * Decode {@code encoding} to a BigFloat using this format.
	 * 
	 * NB: this method should not be used if {@link #size}&gt;8
	 * 
	 * @param encoding the encoding
	 * @return the decoded value as a BigFloat
	 */
	public BigFloat getBigFloat(long encoding) {
		boolean sgn = extractSign(encoding);
		int exp = extractExponentCode(encoding);
		long frac = extractFractionalCode(encoding);
		FloatKind kind = extractKind(encoding);

		int scale;
		BigInteger unscaled = BigInteger.valueOf(frac);
		if (kind == FloatKind.FINITE) {
			if (exp == 0) { // subnormal
				scale = -bias + 1;
			}
			else {
				scale = exp - bias;
				unscaled = unscaled.setBit(frac_size);
			}
		}
		else {
			scale = 0;
		}
		return new BigFloat(frac_size, exp_size, kind, sgn ? -1 : 1, unscaled, scale);
	}

	/**
	 * Decode {@code encoding} to a SmallFloatData using this format.
	 * 
	 * NB: this method should not be used if {@link #size}>8
	 * 
	 * @param encoding the encoding
	 * @return the decoded value as a SmallFloatData
	 */
	SmallFloatData getSmallFloatData(long encoding) {
		boolean sgn = extractSign(encoding);
		int exp = extractExponentCode(encoding);
		long frac = extractFractionalCode(encoding);
		FloatKind kind = extractKind(encoding);
	
		int scale;
		long unscaled = frac;
		if (kind == FloatKind.FINITE) {
			if (exp == 0) { // subnormal
				scale = -bias + 1;
			}
			else {
				scale = exp - bias;
				unscaled |= 1L << frac_size;
			}
		}
		else {
			scale = 0;
		}
		return new SmallFloatData(frac_size, exp_size, kind, sgn ? -1 : 1, unscaled, scale);
	}

	// Convert floating point encoding into host's double if size <= 8
	public double getHostFloat(long encoding) {
		boolean sgn = extractSign(encoding);
		int exp = extractExponentCode(encoding);
		long frac = extractFractionalCode(encoding);

		boolean subnormal = false;
		if (exp == 0) {
			if (frac == 0) { // Floating point zero
				return sgn ? -0.0 : +0.0;
			}
			subnormal = true;
		}
		else if (exp == maxexponent) {
			if (frac == 0) { // Floating point infinity
				return sgn ? Double.NEGATIVE_INFINITY : Double.POSITIVE_INFINITY;
			}
			return Double.NaN;
		}

		// Get unbiased scale and normalized mantissa
		exp -= bias;
		long mantissa = frac << (8 * 8 - frac_size);
		if (!subnormal && jbitimplied) {
			mantissa >>= 1; // Make room for 1 jbit
			mantissa |= 0x8000000000000000L; // set bit in at top of normalized frac
		}

		return createFloat(sgn, mantissa, exp);
	}

	public BigFloat getHostFloat(BigInteger encoding) {
		boolean sgn = extractSign(encoding);
		int sign = sgn ? -1 : 1;
		BigInteger frac = extractFractionalCode(encoding);
		int exp = extractExponentCode(encoding);
		if (exp == 0) { // subnormals
			if (frac.signum() == 0) {
				return BigFloat.zero(frac_size, exp_size, sign);
			}
			return new BigFloat(frac_size, exp_size, FloatKind.FINITE, sign, frac, 1 - bias);
		}
		else if (exp == maxexponent) {
			if (frac.signum() == 0) { // Floating point infinity
				return new BigFloat(frac_size, exp_size, FloatKind.INFINITE, sign, BigInteger.ZERO,
					maxexponent);
			}
			return new BigFloat(frac_size, exp_size, FloatKind.QUIET_NAN, sign, BigInteger.ZERO,
				maxexponent);
		}

		if (jbitimplied) {
			frac = frac.setBit(frac_size);
		}
		return new BigFloat(frac_size, exp_size, FloatKind.FINITE, sign, frac, exp - bias);
	}

	// Convert host's double into floating point encoding if size <= 8
	public long getEncoding(double host) {
		SmallFloatData value = FloatFormat.getSmallFloatData(host);

		switch (value.kind) {
			case QUIET_NAN:
			case SIGNALING_NAN:
				return getNaNEncoding(false);
			case INFINITE:
				return getInfinityEncoding(value.sign < 0);
			case FINITE:
				break;
		}
		if (value.isZero()) {
			return getZeroEncoding(value.sign < 0);
		}
		int exp;
		long fraction;

		// handle the case where jbitimplied == true
		if (jbitimplied) {
			int lb_unscaled = leadBit(value.unscaled);
			if (value.scale - value.fracbits + lb_unscaled >= 1 - bias) {
				// normal case
				exp = value.scale - value.fracbits + lb_unscaled + bias;
				fraction = roundToLeadBit(value.unscaled, frac_size);
				// if carry..
				if (leadBit(fraction) > frac_size) {
					fraction = fraction >>> 1;
					exp += 1;
				}
				fraction &= (1L << frac_size) - 1;
			}
			else {
				// subnormal
				exp = 0;
				int n = value.scale - value.fracbits + lb_unscaled - 1 + bias + frac_size;
				if (n < 0) {
					// XXX is it possible to round up to a non-zero in this situation?
					return getZeroEncoding(value.sign < 0);
				}
				fraction = roundToLeadBit(value.unscaled, n); // XXX round into normal case?
			}
		}
		else {
			throw new AssertionError("Unexpected jbitimplied==false");
		}
		if (exp >= maxexponent) {
			return getInfinityEncoding(value.sign < 0);
		}

		long result = ((long) exp << exp_pos) | fraction;
		if (value.sign < 0) {
			result |= 1L << signbit_pos;
		}
		return result;
	}

	public BigInteger getEncoding(BigFloat value) {
		if (value == null) {
			return getBigNaNEncoding(false);
		}

		switch (value.kind) {
			case QUIET_NAN:
			case SIGNALING_NAN:
				return getBigNaNEncoding(false);
			case INFINITE:
				return getBigInfinityEncoding(value.sign < 0);
			case FINITE:
				break;
		}
		if (value.isZero()) {
			return getBigZeroEncoding(value.sign < 0);
		}
		int exp;
		BigInteger fraction;

		// handle the case where jbitimplied == true
		if (jbitimplied) {
			int lb_unscaled = leadBit(value.unscaled);
			if (value.scale - value.fracbits + lb_unscaled >= 1 - bias) {
				// normal case
				exp = value.scale - value.fracbits + lb_unscaled + bias;
				fraction = roundToLeadBit(value.unscaled, frac_size);
				// if carry..
				if (leadBit(fraction) > frac_size) {
					fraction = fraction.shiftRight(1);
					exp += 1;
				}
				fraction = fraction.clearBit(frac_size);
			}
			else {
				// subnormal
				exp = 0;
				int n = value.scale - value.fracbits + lb_unscaled - 1 + bias + frac_size;
				if (n < 0) {
					// XXX is it possible to round up to a non-zero in this situation?
					return getBigZeroEncoding(value.sign < 0);
				}
				fraction = roundToLeadBit(value.unscaled, n);
			}
		}
		else {
			throw new AssertionError("Unexpected jbitimplied==false");
		}
		if (exp >= maxexponent) {
			return getBigInfinityEncoding(value.sign < 0);
		}

		BigInteger result = BigInteger.valueOf(exp).shiftLeft(exp_pos).or(fraction);
		if (value.sign < 0) {
			result = result.setBit(signbit_pos);
		}
		return result;
	}

	/**
	 * Convert an encoded value to a binary floating point representation.
	 * 
	 * NB: this method should not be used if {@link #size}&gt;8
	 * 
	 * @param encoding the encoding of a floating point value in this format
	 * @return a binary string representation of the encoded floating point {@code encoding}
	 */
	public String toBinaryString(long encoding) {
		boolean sgn = extractSign(encoding);
		int exp = extractExponentCode(encoding);
		long frac = extractFractionalCode(encoding);
		FloatKind kind = extractKind(encoding);

		switch (kind) {
			case INFINITE:
				if (sgn) {
					return "-inf";
				}
				return "+inf";
			case QUIET_NAN:
				return "qNaN";
			case SIGNALING_NAN:
				return "sNaN";
			case FINITE:
				break;
			default:
				throw new AssertionError("unexpected kind");

		}
		String binary = Long.toBinaryString(frac);
		binary = "0".repeat(frac_size - binary.length()) + binary;
		binary = binary.replaceAll("0*$", "");
		if (binary.isEmpty()) {
			binary = "0";
		}
		String s = sgn ? "-" : "";

		if (exp == 0) { // subnormal
			if (frac == 0) {
				return String.format("%s0b0.0", s);
			}
			return String.format("%s0b0.%s * 2^%d", s, binary, -bias + 1);
		}
		return String.format("%s0b1.%s * 2^%d", s, binary, exp - bias);
	}

	/**
	 * @param f a float
	 * @return BigFloat equal to {@code f}
	 */
	public static BigFloat toBigFloat(float f) {
		return JAVA_FLOAT_FORMAT.getBigFloat(0xffffffffl & Float.floatToRawIntBits(f));
	}

	/**
	 * @param d a double
	 * @return BigFloat equal to {@code f}
	 */
	public static BigFloat toBigFloat(double d) {
		return JAVA_DOUBLE_FORMAT.getBigFloat(Double.doubleToRawLongBits(d));
	}

	static SmallFloatData getSmallFloatData(double d) {
		return JAVA_DOUBLE_FORMAT.getSmallFloatData(Double.doubleToRawLongBits(d));
	}

	/**
	 * @param f a float
	 * @return binary representation of {@code f}
	 */
	public static String toBinaryString(float f) {
		return JAVA_FLOAT_FORMAT.toBinaryString(0xffffffffl & Float.floatToRawIntBits(f));
	}

	/**
	 * @param d a double
	 * @return binary representation of {@code f}
	 */
	public static String toBinaryString(double d) {
		return JAVA_DOUBLE_FORMAT.toBinaryString(Double.doubleToRawLongBits(d));
	}

	private static int leadBit(BigInteger i) {
		return i.bitLength() - 1;
	}

	private static int leadBit(long l) {
		return 63 - Long.numberOfLeadingZeros(l);
	}

	/**
	 * right shift and round to nearest even or left shift to an integer with lead bit at newLeadBit.
	 * 
	 * The final round up might cause a carry that propagates up, so this must be followed by a test.
	 * 
	 * @param i integer representation of mantissa 1.xxxxx
	 * @param newLeadBit the bit position we want as a new lead bit
	 * @return integer representing 1.yyyy with a new lead bit position
	 */
	private static BigInteger roundToLeadBit(BigInteger i, int newLeadBit) {
		int amt = leadBit(i) - newLeadBit;
		if (amt == 0) {
			return i;
		}
		if (amt < 0) {
			return i.shiftLeft(-amt);
		}

		// round to nearest even
		int midbit = amt - 1;
		boolean midset = i.testBit(midbit);
		boolean eps = i.getLowestSetBit() < midbit;
		i = i.shiftRight(amt);
		boolean odd = i.testBit(0);
		if (midset && (eps || odd)) {
			i = i.add(BigInteger.ONE);
		}
		return i;
	}

	private static long roundToLeadBit(long i, int newLeadBit) {
		int amt = leadBit(i) - newLeadBit;
		if (amt == 0) {
			return i;
		}
		if (amt < 0) {
			return i << (-amt);
		}

		// round to nearest even
		long midbitmask = 1L << (amt - 1);
		boolean midset = (i & midbitmask) != 0;
		boolean eps = ((midbitmask - 1) & i) != 0;
		i >>>= amt;
		boolean odd = (i & 1) != 0;
		if (midset && (eps || odd)) {
			i += 1;
		}
		return i;
	}

	/**
	 * A small float ({@code float} and {@code double}) stand-in for {@code BigFloat}
	 */
	static class SmallFloatData {
		final int fracbits;
		final int expbits;

		final FloatKind kind;
		final int sign;

		final long unscaled;
		final int scale;

		/**
		 * Construct SmallFloat Data.
		 * If kind is FINITE, the value is <code>sign*unscaled*2^(scale-fracbits)</code>
		 * 
		 * @param fracbits number of fractional bits
		 * @param expbits maximum number of bits in exponent
		 * @param kind the Kind, FINITE, INFINITE, ...
		 * @param sign +1 or -1
		 * @param unscaled the value's mantissa
		 * @param scale value's scale
		 */
		public SmallFloatData(int fracbits, int expbits, FloatKind kind, int sign, long unscaled,
				int scale) {
			this.fracbits = fracbits;
			this.expbits = expbits;
			this.kind = kind;
			this.sign = sign;
			this.unscaled = unscaled;
			this.scale = scale;
		}

		public boolean isZero() {
			return this.kind == FloatKind.FINITE && unscaled == 0L;
		}

	}

	// Currently we emulate floating point operations on the target
	// By converting the encoding to the host's encoding and then
	// performing the operation using the host's floating point unit
	// then the host's encoding is converted back to the targets encoding

	// each operation is implemented for both encoding, long and BigInteger.
	// The long methods should not be used when size>8.

	public long opEqual(long a, long b) { // a == b
		double val1 = getHostFloat(a);
		double val2 = getHostFloat(b);
		long res = (val1 == val2) ? 1 : 0;
		return res;
	}

	public BigInteger opEqual(BigInteger a, BigInteger b) { // a == b
		BigFloat fa = getHostFloat(a);
		BigFloat fb = getHostFloat(b);
		if (fa.isNaN() || fb.isNaN()) {
			return BigInteger.ZERO;
		}
		BigInteger res = SystemUtilities.isEqual(fa, fb) ? BigInteger.ONE : BigInteger.ZERO;
		return res;
	}

	public long opNotEqual(long a, long b) { // a != b
		double val1 = getHostFloat(a);
		double val2 = getHostFloat(b);
		long res = (val1 != val2) ? 1 : 0;
		return res;
	}

	public BigInteger opNotEqual(BigInteger a, BigInteger b) { // a != b
		BigFloat fa = getHostFloat(a);
		BigFloat fb = getHostFloat(b);
		if (fa.isNaN() | fb.isNaN()) {
			return BigInteger.ONE;
		}
		BigInteger res = SystemUtilities.isEqual(fa, fb) ? BigInteger.ZERO : BigInteger.ONE;
		return res;
	}

	public long opLess(long a, long b) { // a < b
		double val1 = getHostFloat(a);
		double val2 = getHostFloat(b);
		long res = (val1 < val2) ? 1 : 0;
		return res;
	}

	public BigInteger opLess(BigInteger a, BigInteger b) { // a < b
		BigFloat fa = getHostFloat(a);
		BigFloat fb = getHostFloat(b);
		BigInteger res = (fa.compareTo(fb) < 0) ? BigInteger.ONE : BigInteger.ZERO;
		return res;
	}

	public long opLessEqual(long a, long b) { // a <= b
		double val1 = getHostFloat(a);
		double val2 = getHostFloat(b);
		long res = (val1 <= val2) ? 1 : 0;
		return res;
	}

	public BigInteger opLessEqual(BigInteger a, BigInteger b) { // a <= b
		BigFloat fa = getHostFloat(a);
		BigFloat fb = getHostFloat(b);
		BigInteger res = (fa.compareTo(fb) <= 0) ? BigInteger.ONE : BigInteger.ZERO;
		return res;
	}

	// true if a is "not a number"
	public long opNan(long a) {
		double val = getHostFloat(a);
		long res = Double.isNaN(val) ? 1 : 0;
		return res;
	}

	public BigInteger opNan(BigInteger a) {
		BigFloat val = getHostFloat(a);
		BigInteger res = (val.isNaN()) ? BigInteger.ONE : BigInteger.ZERO;
		return res;
	}

	public long opAdd(long a, long b) { // a + b
		double val1 = getHostFloat(a);
		double val2 = getHostFloat(b);
		return getEncoding(val1 + val2);
	}

	public BigInteger opAdd(BigInteger a, BigInteger b) { // a + b
		BigFloat fa = getHostFloat(a);
		BigFloat fb = getHostFloat(b);
		fa.add(fb);
		return getEncoding(fa);
	}

	public long opSub(long a, long b) { // a - b
		double val1 = getHostFloat(a);
		double val2 = getHostFloat(b);
		return getEncoding(val1 - val2);
	}

	public BigInteger opSub(BigInteger a, BigInteger b) { // a - b
		BigFloat fa = getHostFloat(a);
		BigFloat fb = getHostFloat(b);
		fa.sub(fb);
		return getEncoding(fa);
	}

	public long opDiv(long a, long b) { // a / b
		double val1 = getHostFloat(a);
		double val2 = getHostFloat(b);
		return getEncoding(val1 / val2);
	}

	public BigInteger opDiv(BigInteger a, BigInteger b) { // a / b
		BigFloat fa = getHostFloat(a);
		BigFloat fb = getHostFloat(b);
		fa.div(fb);
		return getEncoding(fa);
	}

	public long opMult(long a, long b) { // a * b
		double val1 = getHostFloat(a);
		double val2 = getHostFloat(b);
		return getEncoding(val1 * val2);
	}

	public BigInteger opMult(BigInteger a, BigInteger b) { // a * b
		BigFloat fa = getHostFloat(a);
		BigFloat fb = getHostFloat(b);
		fa.mul(fb);
		return getEncoding(fa);
	}

	public long opNeg(long a) { // -a
		double val = getHostFloat(a);
		return getEncoding(-val);
	}

	public BigInteger opNeg(BigInteger a) {
		BigFloat fa = getHostFloat(a);
		fa.negate();
		return getEncoding(fa);
	}

	public long opAbs(long a) { // absolute value of a
		double val = getHostFloat(a);
		return getEncoding(Math.abs(val));
	}

	public BigInteger opAbs(BigInteger a) {
		BigFloat fa = getHostFloat(a);
		fa.abs();
		return getEncoding(fa);
	}

	public long opSqrt(long a) { // square root of a
		double val = getHostFloat(a);
		return getEncoding(Math.sqrt(val));
	}

	public BigInteger opSqrt(BigInteger a) {
		BigFloat fa = getHostFloat(a);
		fa.sqrt();
		return getEncoding(fa);
	}

	// convert integer to floating point
	public long opInt2Float(long a, int sizein) {
		long ival = a;
		ival = Utils.zzz_sign_extend(ival, 8 * sizein - 1);
		double val = ival; // Convert integer to float
		return getEncoding(val);
	}

	public BigInteger opInt2Float(BigInteger a, int sizein, boolean signed) {
		if (signed) {
			a = Utils.convertToSignedValue(a, sizein);
		}
		else {
			a = Utils.convertToUnsignedValue(a, sizein);
		}
		return getEncoding(BigFloat.valueOf(frac_size, exp_size, a));
	}

	public long opFloat2Float(long a, FloatFormat outformat) { // convert between floating
		// point precisions
		double val = getHostFloat(a);
		return outformat.getEncoding(val);
	}

	public BigInteger opFloat2Float(BigInteger a, FloatFormat outformat) { // convert between floating
		BigFloat fa = getHostFloat(a);
		return outformat.getEncoding(fa);
	}

	public long opTrunc(long a, int sizeout) { // convert floating point to integer
		double val = getHostFloat(a);
		long res = (long) val; // Convert to integer
		res &= Utils.calc_mask(sizeout); // Truncate to proper size
		return res;
	}

	public BigInteger opTrunc(BigInteger a, int sizeout) { // convert floating point to integer
		BigFloat fa = getHostFloat(a);
		if (fa.isNaN()) {
			return BigInteger.ZERO; // consistent with Java Double->Long behavior
		}
		if (fa.isInfinite()) {
			if (fa.sign > 0) {
				// max positive int
				return BigInteger.ONE.shiftLeft((8 * size)).subtract(BigInteger.ONE).shiftRight(1);
			}

			// max negative int
			return BigInteger.ONE.shiftLeft((8 * size) - 1).negate();
		}
		return fa.toBigInteger();
	}

	public long opCeil(long a) { // integer ceiling of a
		double val = getHostFloat(a);
		return getEncoding(Math.ceil(val));
	}

	public BigInteger opCeil(BigInteger a) { // integer ceiling of a
		BigFloat fa = getHostFloat(a);
		fa.ceil();
		return getEncoding(fa);
	}

	public long opFloor(long a) { // integer floor of a
		double val = getHostFloat(a);
		return getEncoding(Math.floor(val));
	}

	public BigInteger opFloor(BigInteger a) { // integer floor of a
		BigFloat fa = getHostFloat(a);
		fa.floor();
		return getEncoding(fa);
	}

	public long opRound(long a) { // nearest integer to a
		double val = getHostFloat(a);
		return getEncoding(Math.floor(val + 0.5));
	}

	public BigInteger opRound(BigInteger a) { // nearest integer to a
		BigFloat fa = getHostFloat(a);
		fa.round();
		return getEncoding(fa);
	}

}
