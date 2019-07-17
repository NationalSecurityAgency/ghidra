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

public class FloatFormat {

	private static final int INFINITE_SCALE = -(64 * 1024);
	public static final BigDecimal BIG_NaN = null;
	public static final BigDecimal BIG_POSITIVE_INFINITY = new BigDecimal(BigInteger.ONE,
		INFINITE_SCALE);
	public static final BigDecimal BIG_NEGATIVE_INFINITY = (new BigDecimal(BigInteger.ONE,
		INFINITE_SCALE)).negate();

	private static final BigInteger BIG_INT_TWO = BigInteger.valueOf(2);
	private static final BigDecimal BIG_DEC_TWO = BigDecimal.valueOf(2);
	private static final BigDecimal BIG_DEC_THREE = BigDecimal.valueOf(3);

	private int size; // Size of float in bytes (this format)
	private int signbit_pos; // Bit position of signbit
	private int frac_pos; // (lowest) bit position of fractional part
	private int frac_size; // Number of bits in fractional part
	private int exp_pos; // (lowest) bit position of exponent
	private int exp_size; // Number of bits in exponent
	private int bias; // What to add to real exponent to get encoding
	private int maxexponent; // maximum stored biased/unsigned exponent
	private boolean jbitimplied; // true if integer bit of 1 is assumed

	/**
	 * A constant holding the largest positive finite value
	 */
	public final BigDecimal maxValue;

	/**
	 * A constant holding the smallest positive normal value
	 */
	public final BigDecimal minValue;

	private final MathContext resultContext;

	public int getSize() {
		return size;
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
			resultContext = new MathContext(7, RoundingMode.UP);
		}
		else if (size == 4) {
			signbit_pos = 31;
			exp_pos = 23;
			exp_size = 8;
			frac_pos = 0;
			frac_size = 23;
			bias = 127;
			jbitimplied = true;
			resultContext = new MathContext(7, RoundingMode.UP);
		}
		else if (size == 8) {
			signbit_pos = 63;
			exp_pos = 52;
			exp_size = 11;
			frac_pos = 0;
			frac_size = 52;
			bias = 1023;
			jbitimplied = true;
			resultContext = new MathContext(16, RoundingMode.UP);
		}
		else if (size == 16) {
			signbit_pos = 127;
			exp_pos = 112;
			exp_size = 15;
			frac_pos = 0;
			frac_size = 112;
			bias = 16383;
			jbitimplied = true;
			resultContext = new MathContext(33, RoundingMode.UP);
		}
		else if (size == 10) {
			signbit_pos = 79;
			exp_pos = 64;
			exp_size = 15;
			frac_pos = 0;
			frac_size = 64;
			bias = 16383;
			jbitimplied = true;
			resultContext = new MathContext(18, RoundingMode.UP);
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
			resultContext = new MathContext(18, RoundingMode.UP);
		}
		else {
			throw new UnsupportedFloatFormatException(sz);
		}
		maxexponent = (1 << exp_size) - 1;

		//  (2-(2^-frac_size))?2^bias
		maxValue =
			BIG_DEC_TWO.subtract(BIG_DEC_TWO.pow(-frac_size, resultContext)).multiply(
				BIG_DEC_TWO.pow(bias, resultContext));
		//  2^(-bias+1) normal
		//  2^(-bias)   denormalized TODO: verify
		minValue = BIG_DEC_TWO.pow(-bias, resultContext);
	}

	// Create a double given 8-byte normalized sign, fractional, and exponent
	static double createFloat(boolean sign, long mantissa, int exp) {
		exp += 1023;
		long bits = mantissa >>> 11;
		if (exp == 0) {
			bits = bits >> 1;
		}
		else {
			bits = bits & 0xfffffffffffffL;
		}
		bits |= (long) exp << 52;

		if (sign) {
			bits |= 0x8000000000000000L;
		}
		return Double.longBitsToDouble(bits);
	}

	// Create a BigDecimal given sign, fractional, and exponent
	static BigDecimal createFloat(boolean sign, BigInteger mantissa, int exp) {

		StringBuilder buf = new StringBuilder();
		buf.append(sign ? "-" : "+");
		buf.append(mantissa.toString());
		buf.append('e');
		buf.append(exp);

		return new BigDecimal(buf.toString());
	}

	// Extract sign, fractional, and exponent from x
	static FloatData extractExpSig(double x) {
		long bits = Double.doubleToRawLongBits(x);
		boolean sign = ((bits >> 63) != 0);
		if (x == 0.0) {
			return new FloatData(Floatclass.zero, sign, 0, 0);
		}
		if (Double.isInfinite(x)) {
			return new FloatData(Floatclass.infinity, sign, 0, 0);
		}
		if (Double.isNaN(x)) {
			return new FloatData(Floatclass.nan, sign, 0, 0);
		}
		int exp = (int) ((bits >> 52) & 0x7ffL);
		long mantissa =
			(exp == 0) ? (bits & 0xfffffffffffffL) << 1
					: (bits & 0xfffffffffffffL) | 0x10000000000000L;
		mantissa <<= 11;
		exp = exp - 1023;
		return new FloatData(Floatclass.normalized, sign, exp, mantissa);
	}

	// Extract bits encoding fractional and return normalized long value
	private long extractFractionalCode(long x) {
		x >>>= frac_pos; // Eliminate bits below
		x <<= 8 * 8 - frac_size; // Align with top of long word
		return x;
	}

	// Extract bits encoding fractional and returned un-normalized value
	private BigInteger extractFractionalCode(BigInteger x) {
		BigInteger mask = BigInteger.ONE.shiftLeft(frac_size).subtract(BigInteger.ONE);
		return x.shiftRight(frac_pos).and(mask);
	}

	// Extract the signbit from encoding
	private boolean extractSign(long x) {
		x >>>= signbit_pos;
		return ((x & 1) != 0);
	}

	// Extract the signbit from encoding
	private boolean extractSign(BigInteger x) {
		return x.testBit(signbit_pos);
	}

	// Extract bits encoding exponent
	private int extractExponentCode(long x) {
		x >>>= exp_pos;
		long mask = 1;
		mask = (mask << exp_size) - 1;
		return (int) (x & mask);
	}

	// Extract bits encoding exponent
	private int extractExponentCode(BigInteger x) {
		return x.shiftRight(exp_pos).intValue() & maxexponent;
	}

	private long setSign(long x, boolean sign) {
		if (!sign)
			return x; // Assume bit is already zero
		long mask = 1;
		mask <<= signbit_pos;
		x |= mask; // Stick in the bit
		return x;
	}

	private BigInteger setSign(BigInteger x, boolean sign) {
		if (sign) {
			return x.setBit(signbit_pos);
		}
		return x;
	}

	private long getZeroEncoding(boolean sgn) {
		// Use IEEE 754 standard for zero encoding
		return setSign(0, sgn);
	}

	private long getInfinityEncoding(boolean sgn) {
		// Use IEEE 754 standard for infinity encoding
		long res = (long) maxexponent << exp_pos;
		return setSign(res, sgn);
	}

	private BigInteger getBigInfinityEncoding(boolean sgn) {
		// Use IEEE 754 standard for infinity encoding
		BigInteger res = BigInteger.valueOf(maxexponent).shiftLeft(exp_pos);
		return setSign(res, sgn);
	}

	private long getNaNEncoding(boolean sgn) {
		// Use IEEE 754 standard for NaN encoding
		long res = 1L << (frac_pos + frac_size - 1);
		res |= (long) maxexponent << exp_pos;
		return setSign(res, sgn);
	}

	private BigInteger getBigNaNEncoding(boolean sgn) {
		// Use IEEE 754 standard for NaN encoding
		BigInteger res = BigInteger.ONE.shiftLeft(frac_pos + frac_size - 1);
		res = res.or(BigInteger.valueOf(maxexponent).shiftLeft(exp_pos));
		return setSign(res, sgn);
	}

	// Convert floating point encoding into host's double
	public double getHostFloat(long encoding) {
		boolean sgn = extractSign(encoding);
		long frac = extractFractionalCode(encoding);
		int exp = extractExponentCode(encoding);
		boolean normal = true;
		if (exp == 0) {
			if (frac == 0) { // Floating point zero
				// FIXME: add on sign-bit for +0 or -0 allowed by standard
				return sgn ? -0.0 : +0.0;
			}
			// Number is denormalized
			normal = false;
		}
		else if (exp == maxexponent) {
			if (frac == 0) { // Floating point infinity
				// FIXME: add on sign-bit for +inf or -inf allowed by standard
				return sgn ? Double.NEGATIVE_INFINITY : Double.POSITIVE_INFINITY;
			}
			// encoding is "Not a Number" NaN
			return Double.NaN;
		}

		// Get "true" exponent and fractional
		exp -= bias;
		if (normal && jbitimplied) {
			frac >>>= 1; // Make room for 1 jbit
			frac |= 0x8000000000000000L; // set bit in at top of normalized frac
		}
		return createFloat(sgn, frac, exp);
	}

	// Convert floating point encoding into host's double
	public BigDecimal getHostFloat(BigInteger encoding) {
		boolean sgn = extractSign(encoding);
		BigInteger frac = extractFractionalCode(encoding);
		int exp = extractExponentCode(encoding);
		if (exp == 0) {
			if (frac.signum() == 0) { // Floating point zero
				// FIXME: add on sign-bit for +0 or -0 allowed by standard
				return BigDecimal.ZERO;
			}
			// Number is denormalized
		}
		else if (exp == maxexponent) {
			if (frac.signum() == 0) { // Floating point infinity
				// FIXME: add on sign-bit for +inf or -inf allowed by standard
				return sgn ? BIG_NEGATIVE_INFINITY : BIG_POSITIVE_INFINITY;
			}
			// encoding is "Not a Number" NaN
			return BIG_NaN;
		}

		// Get "true" exponent and fractional
		exp -= bias;
		if (jbitimplied) {
			frac = frac.shiftRight(1); // Make room for 1 jbit 
			frac = frac.setBit(frac_size - 1); // set bit in at top frac
		}

		MathContext expandedContext =
			new MathContext(resultContext.getPrecision() * 3, resultContext.getRoundingMode());
		BigDecimal result = new BigDecimal(frac, expandedContext);
		result =
			result.multiply(BIG_DEC_TWO.pow(exp - frac_size + 1, expandedContext), resultContext);
		result = result.stripTrailingZeros();
		if (sgn) {
			result = result.negate();
		}

		return result;
	}

	// Convert host's double into floating point encoding
	public long getEncoding(double host) {

		FloatData data = extractExpSig(host); // has 8-byte normalized mantissa
		if (data.type == Floatclass.zero)
			return getZeroEncoding(data.sign);
		else if (data.type == Floatclass.infinity)
			return getInfinityEncoding(data.sign);
		else if (data.type == Floatclass.nan)
			return getNaNEncoding(data.sign);

		int exp = data.exp;
		long signif = data.mantisa;
		// convert exponent and fractional to their encodings
		exp += bias;
		if (exp < 0) // Exponent is too small to represent
			return getZeroEncoding(data.sign);
		if (exp > maxexponent) // Exponent is too big to represent
			return getInfinityEncoding(data.sign);
		if (exp != 0 && jbitimplied)
			signif <<= 1; // Cut of top bit for normal case only (which should be 1)

		long res = (signif >>> (64 - frac_size)) << frac_pos;
		res |= (long) exp << exp_pos;
		return setSign(res, data.sign);
	}

	// Convert host's double into floating point encoding
	// TODO: May not properly support denormalized values
	public BigInteger getEncoding(BigDecimal value) {

		if (value == BIG_NaN) { // null value
			return getBigNaNEncoding(false);
		}

		boolean neg = false;
		if (value.signum() < 0) {
			neg = true;
			value = value.negate();
		}

		if (value.compareTo(maxValue) >= 0) {
			return getBigInfinityEncoding(neg);
		}

		if (value.compareTo(minValue) <= 0) {
			return BigInteger.ZERO;
		}

		BigInteger integer = value.toBigInteger(); // positive floor
		BigInteger fraction = BigInteger.ZERO;
		int exp = bias;

		value = value.subtract(new BigDecimal(integer));
		if (value.signum() != 0) {
			for (int i = frac_size - 1; i >= 0; i--) {
				// value += value
				value = value.add(value);
				// fraction += floor(value) * pow(2,i) {value assumed to be positive}
				BigInteger floor = value.toBigInteger();
				BigDecimal valueFloor = new BigDecimal(floor);
				//BigDecimal valueFloor = value.round(FLOOR);
				fraction = fraction.add(floor.multiply(BIG_INT_TWO.pow(i)));
				// value -= floor(value)
				value = value.subtract(valueFloor);
			}
		}

		BigInteger fracMask1 = BigInteger.ONE.shiftLeft(frac_size - 1).subtract(BigInteger.ONE);

		while (!integer.equals(BigInteger.ONE) && exp > 0 && exp < maxexponent) {

			if (!integer.equals(BigInteger.ZERO)) {

				// fraction = (integer&1)<<(frac_size-1) + (fraction>>1)
				fraction = fraction.shiftRight(1);
				if (integer.testBit(0)) {
					fraction = fraction.add(BigInteger.ZERO.setBit(frac_size - 1));
				}
				// integer = integer>>1
				integer = integer.shiftRight(1);
				++exp;
			}
			else {
				// integer = (fraction & bit(frac_size-1)) >> (frac_size-1)
				integer = (fraction.testBit(frac_size - 1)) ? BigInteger.ONE : BigInteger.ZERO;
				// fraction = (fraction & fracMask1) << 1
				fraction = fraction.and(fracMask1).shiftLeft(1);
				// value += value
				value = value.add(value);
				// fraction += floor(value)
				BigInteger floor = value.toBigInteger();
				BigDecimal valueFloor = new BigDecimal(floor);
				//BigDecimal valueFloor = value.round(FLOOR);
				fraction = fraction.add(floor);
				// value -= floor(value)
				value = value.subtract(valueFloor);
				--exp;
			}
		}
		if (frac_pos != 0) {
			fraction = fraction.shiftLeft(frac_pos);
		}
		BigInteger result = BigInteger.valueOf(exp).shiftLeft(exp_pos).or(fraction);
		if (neg) {
			result = result.setBit(signbit_pos);
		}
		return result;
	}

	// Currently we emulate floating point operations on the target
	// By converting the encoding to the host's encoding and then
	// performing the operation using the host's floating point unit
	// then the host's encoding is converted back to the targets encoding

	public long opEqual(long a, long b) { // a == b
		double val1 = getHostFloat(a);
		double val2 = getHostFloat(b);
		long res = (val1 == val2) ? 1 : 0;
		return res;
	}

	public BigInteger opEqual(BigInteger a, BigInteger b) { // a == b
		BigDecimal val1 = getHostFloat(a);
		BigDecimal val2 = getHostFloat(b);
		if (val1 == BIG_NaN || val2 == BIG_NaN) {
			return BigInteger.ZERO;
		}
		BigInteger res = SystemUtilities.isEqual(val1, val2) ? BigInteger.ONE : BigInteger.ZERO;
		return res;
	}

	public long opNotEqual(long a, long b) { // a != b
		double val1 = getHostFloat(a);
		double val2 = getHostFloat(b);
		long res = (val1 != val2) ? 1 : 0;
		return res;
	}

	public BigInteger opNotEqual(BigInteger a, BigInteger b) { // a != b
		BigDecimal val1 = getHostFloat(a);
		BigDecimal val2 = getHostFloat(b);
		if (val1 == BIG_NaN || val2 == BIG_NaN) {
			return BigInteger.ONE;
		}
		BigInteger res = SystemUtilities.isEqual(val1, val2) ? BigInteger.ZERO : BigInteger.ONE;
		return res;
	}

	public long opLess(long a, long b) { // a < b
		double val1 = getHostFloat(a);
		double val2 = getHostFloat(b);
		long res = (val1 < val2) ? 1 : 0;
		return res;
	}

	public BigInteger opLess(BigInteger a, BigInteger b) { // a < b
		BigDecimal val1 = getHostFloat(a);
		BigDecimal val2 = getHostFloat(b);
		if (val1 == BIG_NaN || val2 == BIG_NaN) {
			return BigInteger.ZERO;
		}
		BigInteger res = (val1.compareTo(val2) < 0) ? BigInteger.ONE : BigInteger.ZERO;
		return res;
	}

	public long opLessEqual(long a, long b) { // a <= b
		double val1 = getHostFloat(a);
		double val2 = getHostFloat(b);
		long res = (val1 <= val2) ? 1 : 0;
		return res;
	}

	public BigInteger opLessEqual(BigInteger a, BigInteger b) { // a <= b
		BigDecimal val1 = getHostFloat(a);
		BigDecimal val2 = getHostFloat(b);
		if (val1 == BIG_NaN || val2 == BIG_NaN) {
			return BigInteger.ZERO;
		}
		BigInteger res = (val1.compareTo(val2) <= 0) ? BigInteger.ONE : BigInteger.ZERO;
		return res;
	}

	// true is a is "not a number"
	public long opNan(long a) {
		double val = getHostFloat(a);
		long res = Double.isNaN(val) ? 1 : 0;
		return res;
	}

	public BigInteger opNan(BigInteger a) {
		BigDecimal val = getHostFloat(a);
		BigInteger res = (val == BIG_NaN) ? BigInteger.ONE : BigInteger.ZERO;
		return res;
	}

	public long opAdd(long a, long b) { // a + b
		double val1 = getHostFloat(a);
		double val2 = getHostFloat(b);
		return getEncoding(val1 + val2);
	}

	public BigInteger opAdd(BigInteger a, BigInteger b) { // a + b
		BigDecimal val1 = getHostFloat(a);
		BigDecimal val2 = getHostFloat(b);
		if (val1 == BIG_NaN || val2 == BIG_NaN) {
			return getBigNaNEncoding(false);
		}
		if (val1 == BIG_POSITIVE_INFINITY) {
			if (val2 == BIG_NEGATIVE_INFINITY) {
				return getBigNaNEncoding(false);
			}
			return a;
		}
		if (val1 == BIG_NEGATIVE_INFINITY) {
			if (val2 == BIG_POSITIVE_INFINITY) {
				return getBigNaNEncoding(false);
			}
			return a;
		}
		return getEncoding(val1.add(val2, resultContext));
	}

	public long opSub(long a, long b) { // a - b
		double val1 = getHostFloat(a);
		double val2 = getHostFloat(b);
		return getEncoding(val1 - val2);
	}

	public BigInteger opSub(BigInteger a, BigInteger b) { // a - b
		BigDecimal val1 = getHostFloat(a);
		BigDecimal val2 = getHostFloat(b);
		if (val1 == BIG_NaN || val2 == BIG_NaN) {
			return getBigNaNEncoding(false);
		}
		if (val1 == BIG_POSITIVE_INFINITY) {
			if (val2 == BIG_POSITIVE_INFINITY) {
				return getBigNaNEncoding(false);
			}
			return a;
		}
		if (val1 == BIG_NEGATIVE_INFINITY) {
			if (val2 == BIG_NEGATIVE_INFINITY) {
				return getBigNaNEncoding(false);
			}
			return a;
		}
		return getEncoding(val1.subtract(val2, resultContext));
	}

	public long opDiv(long a, long b) { // a / b
		double val1 = getHostFloat(a);
		double val2 = getHostFloat(b);
		return getEncoding(val1 / val2);
	}

	public BigInteger opDiv(BigInteger a, BigInteger b) { // a / b
		BigDecimal val1 = getHostFloat(a);
		BigDecimal val2 = getHostFloat(b);
		if (val1 == BIG_NaN || val2 == BIG_NaN) {
			return getBigNaNEncoding(false);
		}
		if (val2.signum() == 0) {
			if (val1.signum() == 0) {
				return getBigNaNEncoding(false);
			}
			return getBigInfinityEncoding(val1.signum() < 0);
		}
		return getEncoding(val1.divide(val2, resultContext));
	}

	public long opMult(long a, long b) { // a * b
		double val1 = getHostFloat(a);
		double val2 = getHostFloat(b);
		return getEncoding(val1 * val2);
	}

	public BigInteger opMult(BigInteger a, BigInteger b) { // a * b
		BigDecimal val1 = getHostFloat(a);
		BigDecimal val2 = getHostFloat(b);
		if (val1 == BIG_NaN || val2 == BIG_NaN) {
			return getBigNaNEncoding(false);
		}
		return getEncoding(val1.multiply(val2, resultContext));
	}

	public long opNeg(long a) { // -a
		double val = getHostFloat(a);
		return getEncoding(-val);
	}

	public BigInteger opNeg(BigInteger a) {
		BigDecimal val = getHostFloat(a);
		if (val == BIG_NaN) {
			return a;
		}
		return getEncoding(val.negate());
	}

	public long opAbs(long a) { // absolute value of a
		double val = getHostFloat(a);
		return getEncoding(Math.abs(val));
	}

	public BigInteger opAbs(BigInteger a) {
		BigDecimal val = getHostFloat(a);
		if (val == BIG_NaN) {
			return a;
		}
		return getEncoding(val.abs());
	}

	public long opSqrt(long a) { // square root of a
		double val = getHostFloat(a);
		return getEncoding(Math.sqrt(val));
	}

	public BigInteger opSqrt(BigInteger a) {
		BigDecimal val = getHostFloat(a);
		if (val == BIG_NaN) {
			return a;
		}
		int signum = val.signum();
		if (signum < 0) {
			return getBigNaNEncoding(false);
		}
		if (signum == 0) {
			return BigInteger.ZERO;
		}

		int scale = resultContext.getPrecision() * 2;

		BigDecimal result = val.divide(BIG_DEC_THREE, scale, BigDecimal.ROUND_HALF_EVEN);
		BigDecimal lastResult = BigDecimal.ZERO;

		for (int i = 0; i < 50; i++) {
			result =
				val.add(result.multiply(result)).divide(result.multiply(BIG_DEC_TWO), scale,
					BigDecimal.ROUND_HALF_EVEN);
			if (result.compareTo(lastResult) == 0) {
				break;
			}
			lastResult = result;
		}

		return getEncoding(result);
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
		BigDecimal val = new BigDecimal(a);
		return getEncoding(val);
	}

	public long opFloat2Float(long a, FloatFormat outformat) { // convert between floating
		// point precisions
		double val = getHostFloat(a);
		return outformat.getEncoding(val);
	}

	public BigInteger opFloat2Float(BigInteger a, FloatFormat outformat) { // convert between floating
		BigDecimal val = getHostFloat(a);
		if (val == BIG_NaN) {
			return outformat.getBigNaNEncoding(false);
		}
		return outformat.getEncoding(val);
	}

	public long opTrunc(long a, int sizeout) { // convert floating point to integer
		double val = getHostFloat(a);
		long res = (long) val; // Convert to integer
		res &= Utils.calc_mask(sizeout); // Truncate to proper size
		return res;
	}

	public BigInteger opTrunc(BigInteger a, int sizeout) { // convert floating point to integer
		BigDecimal val = getHostFloat(a);
		if (val == BIG_NaN) {
			return BigInteger.ZERO; // consistent with Java Double->Long behavior
		}
		if (val == BIG_POSITIVE_INFINITY) {
			// max positive int
			return BigInteger.ONE.shiftLeft((8 * size)).subtract(BigInteger.ONE).shiftRight(1);
		}
		if (val == BIG_NEGATIVE_INFINITY) {
			// max negative int
			return BigInteger.ONE.shiftLeft((8 * size) - 1).negate();
		}
		BigInteger res = val.toBigInteger(); // Convert to integer
		return res;
	}

	public long opCeil(long a) { // integer ceiling of a
		double val = getHostFloat(a);
		return getEncoding(Math.ceil(val));
	}

	public BigInteger opCeil(BigInteger a) { // integer ceiling of a
		BigDecimal val = getHostFloat(a);
		if (val == BIG_NaN) {
			return a;
		}
		BigInteger intval = val.toBigInteger();
		if (intval.signum() > 0 && !val.unscaledValue().equals(intval)) {
			intval = intval.add(BigInteger.ONE);
		}
		return getEncoding(new BigDecimal(intval));
	}

	public long opFloor(long a) { // integer floor of a
		double val = getHostFloat(a);
		return getEncoding(Math.floor(val));
	}

	private BigInteger floor(BigDecimal val) {
		if (val.signum() < 0) {
			try {
				return val.toBigIntegerExact();
			}
			catch (ArithmeticException e) {
				return val.toBigInteger().subtract(BigInteger.ONE);
			}
		}
		return val.toBigInteger();
	}

	public BigInteger opFloor(BigInteger a) { // integer floor of a
		BigDecimal val = getHostFloat(a);
		if (val == BIG_NaN) {
			return a;
		}
		BigInteger intval = floor(val);
		return getEncoding(new BigDecimal(intval));
	}

	public long opRound(long a) { // nearest integer to a
		double val = getHostFloat(a);
		return getEncoding(Math.floor(val + 0.5));
	}

	public BigInteger opRound(BigInteger a) { // nearest integer to a
		BigDecimal val = getHostFloat(a);
		if (val == BIG_NaN) {
			return a;
		}
		BigInteger intval = floor(val.add(BigDecimal.valueOf(0.5d), resultContext));
		return getEncoding(new BigDecimal(intval));
	}

	static class FloatData {

		final Floatclass type;
		final boolean sign;
		final int exp;
		final long mantisa;

		public FloatData(Floatclass type, boolean sign, int exp, long mantisa) {
			this.type = type;
			this.sign = sign;
			this.exp = exp;
			this.mantisa = mantisa;
		}

	}
}
