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
package ghidra.program.emulation;

public enum HexagonFp64 {
	;
	public static final int FP64_FRAC_POS = 0;
	public static final int FP64_FRAC_SIZE = 52;
	public static final long FP64_FRAC_MASK = ((1L << FP64_FRAC_SIZE) - 1) << FP64_FRAC_POS;
	public static final int FP64_EXP_POS = FP64_FRAC_POS + FP64_FRAC_SIZE;
	public static final int FP64_EXP_SIZE = 11;
	public static final long FP64_EXP_MASK = ((1L << FP64_EXP_SIZE) - 1) << FP64_EXP_POS;
	public static final int FP64_SIGN_POS = FP64_EXP_POS + FP64_EXP_SIZE;
	public static final int FP64_BIAS = (1 << FP64_EXP_SIZE - 1) - 1;
	public static final int FP64_EXP_INF = (int) (FP64_EXP_MASK >>> FP64_EXP_POS);

	static long maskFp64Exponent(long valueBits) {
		return FP64_EXP_MASK & valueBits;
	}

	static long maskFp64Fraction(long valueBits) {
		return FP64_FRAC_MASK & valueBits;
	}

	static boolean isFp64Zero(long exp, long frac) {
		return exp == 0 && frac == 0;
	}

	static boolean isFp64Normal(long exp, long frac) {
		return exp != 0 && exp != FP64_EXP_MASK;
	}

	static boolean isFp64Subnormal(long exp, long frac) {
		return exp == 0 && frac != 0;
	}

	static boolean isFp64Infinite(long exp, long frac) {
		return exp == FP64_EXP_MASK && frac == 0;
	}

	static boolean isFp64Nan(long exp, long frac) {
		return exp == FP64_EXP_MASK && frac != 0;
	}

	static boolean isFp64Negative(long bits) {
		return bits < 0;
	}

	static long getFp64Fraction(long exp, long frac) {
		// Note: No additional shifting of frac necessary, as FP64_FRAC_POS = 0
		if (isFp64Normal(exp, frac)) {
			return frac | (1L << FP64_FRAC_SIZE);
		}
		if (isFp64Zero(exp, frac)) {
			return 0L;
		}
		if (!isFp64Subnormal(exp, frac)) {
			return -1L;
		}
		return frac;
	}

	static int getFp64Exponent(long exp, long frac) {
		if (isFp64Normal(exp, frac)) {
			return (int) (exp >>> FP64_EXP_POS);
		}
		if (isFp64Subnormal(exp, frac)) {
			return (int) (exp >>> FP64_EXP_POS) + 1;
		}
		return -1;
	}

	static long encSign(boolean negative) {
		return negative ? Long.MIN_VALUE : 0;
	}

	static long encExp(int exp, long mantUpper) {
		if ((mantUpper >>> (FP64_FRAC_SIZE - 32)) == 0) {
			return 0;
		}
		return Integer.toUnsignedLong(exp) << FP64_EXP_POS;
	}

	static long encFrac(long mantUpper, int mantLower) {
		return ((mantUpper << 32) | Integer.toUnsignedLong(mantLower)) & FP64_FRAC_MASK;
	}

	public static long dfmpyhh(long rdd, long rss, long rtt) {
		long expRss = maskFp64Exponent(rss);
		long fracRss = maskFp64Fraction(rss);

		long expRtt = maskFp64Exponent(rtt);
		long fracRtt = maskFp64Fraction(rtt);

		if (isFp64Zero(expRss, fracRss) || isFp64Nan(expRss, fracRss) ||
			isFp64Infinite(expRss, fracRss) ||
			isFp64Zero(expRtt, fracRtt) || isFp64Nan(expRtt, fracRtt) ||
			isFp64Infinite(expRtt, fracRtt)) {
			return Double.doubleToRawLongBits(
				Double.longBitsToDouble(rss) * Double.longBitsToDouble(rtt));
		}

		// Read Accumulated from rdd
		boolean sticky = (rdd & 1) != 0;
		int mantLower = (int) (rdd >> 1);
		long mantUpper = rdd >> 33;

		long prod = (getFp64Fraction(expRss, fracRss) >>> 32) *
			(getFp64Fraction(expRtt, fracRtt) >>> 32);
		mantUpper += prod;

		int exp = getFp64Exponent(expRss, fracRss) + getFp64Exponent(expRtt, fracRtt) -
			FP64_BIAS - 20;
		if (!isFp64Normal(expRss, fracRss) || !isFp64Normal(expRtt, fracRtt)) {
			// Crush to inexact 0
			sticky = true;
			exp = -4096;
		}

		boolean negative = isFp64Negative(rss) ^ isFp64Negative(rtt);

		// round
		boolean round = false;
		boolean guard = false;
		if (sticky && mantLower == 0 && mantUpper == 0) {
			return Double.doubleToRawLongBits(0.0);
		}

		// normalize right for fraction
		// 32 is size of mantLower
		for (; mantUpper >>> (FP64_FRAC_SIZE + 1 - 32) != 0; exp++) {
			sticky |= round;
			round = guard;
			guard = (mantLower & 1) != 0;
			mantLower >>>= 1;
			mantLower |= (mantUpper << 63) >>> 32;
			mantUpper >>>= 1;
		}
		// (else) normalize left for fraction
		for (; (mantUpper & (1L << FP64_FRAC_SIZE - 32)) == 0; exp--) {
			mantUpper <<= 1;
			mantUpper |= mantLower >>> 31;
			mantLower <<= 1;
			mantLower |= guard ? 1 : 0;
			guard = round;
			round = sticky;
		}
		// normalize right for exponent
		if (1 - exp > 130) { // if (exp < -129)
			sticky |= round | guard | (mantLower == 0 && mantUpper == 0);
			guard = false;
			round = false;
			exp = 1;
		}
		for (; 1 - exp >= 64; exp += 64) { // while (exp <= -63)
			// Can this be re-specialized to this 64|32-bit split?
			sticky |= round | guard | (mantLower == 0 && (mantUpper & 0x0_ffff_ffffL) == 0);
			guard = (mantUpper >>> 31) != 0;
			round = (mantUpper >>> 30) != 0;
			/**
			 * effective shift right 64 bits
			 *
			 * | ----- long upper ---- | int lower |
			 * 
			 * |BB:AA:99:88:77:66:55:44|33:22:11:00|
			 * 
			 * |00:00:00:00:00:00:00:00|BB:AA:99:88|
			 */
			mantLower = (int) (mantUpper >>> 32);
			mantUpper = 0;
		}
		for (; 1 - exp >= 0; exp++) {
			sticky |= round;
			round = guard;
			guard = (mantLower & 1) != 0;
			mantLower >>>= 1;
			mantLower |= (mantUpper << 63) >>> 32;
			mantUpper >>>= 1;
		}

		// one more normalize right for fraction
		if (mantUpper >>> (FP64_FRAC_SIZE + 1 - 32) != 0) {
			sticky |= round;
			round = guard;
			guard = (mantLower & 1) != 0;
			mantLower >>>= 1;
			mantLower |= (mantUpper << 63) >>> 32;
			mantUpper >>>= 1;
			exp++;
		}
		if (exp >= FP64_EXP_INF) {
			return Double.doubleToRawLongBits(negative
					? Double.NEGATIVE_INFINITY
					: Double.POSITIVE_INFINITY);
		}
		return encSign(negative) | encExp(exp, mantUpper) | encFrac(mantUpper, mantLower);
	}

	public static long dfmpyfix(long rss, long rtt) {
		long expRss = maskFp64Exponent(rss);
		long fracRss = maskFp64Fraction(rss);

		long expRtt = maskFp64Exponent(rtt);
		long fracRtt = maskFp64Exponent(rtt);

		if (!isFp64Normal(expRss, fracRss) && isFp64Normal(expRtt, fracRtt) &&
			expRtt >= (512 << FP64_EXP_POS)) {
			return Double.doubleToRawLongBits(Double.longBitsToDouble(rss) * 0x1.0p52);
		}
		if (!isFp64Normal(expRtt, fracRtt) && isFp64Normal(expRss, fracRss) &&
			expRss >= (512 << FP64_EXP_POS)) {
			return Double.doubleToRawLongBits(Double.longBitsToDouble(rss) * 0x1.0p-52);
		}
		return rss;
	}
}
