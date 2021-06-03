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

import java.math.BigDecimal;
import java.math.BigInteger;

/**
 * An IEEE 754 floating point class.
 *
 * <p>Values represented:
 * <ul>
 *      <li>QUIET_NAN, SIGNALED_NAN</li>
 *      <li>-INF, +INF</li>
 *      <li>value = sign * unscaled * 2 ^ (scale-fracbits)</li>
 * </ul>
 * sign = -1 or +1, unscaled has at most fracbits+1 bits, and scale is at most expbits bits.
 *      
 * <p>Operations compute exact result then round to nearest even.
 */
public strictfp class BigFloat implements Comparable<BigFloat> {
	final int fracbits; // there are fracbits+1 significant bits.
	final int expbits; // # bits used for exponent

	final int maxScale;
	final int minScale;

	FloatKind kind;

	// -1, +1
	int sign;
	// normal numbers have unscaled.bitLength() =  fracbits+1
	// subnormal numbers have scale=0 and unscaled.bitLength() <= fracbits 
	BigInteger unscaled;
	int scale;

	/**
	 * Construct a BigFloat.  If kind is FINITE, the value is <code>sign*unscaled*2^(scale-fracbits)</code>
	 * 
	 * @param fracbits number of fractional bits
	 * @param expbits maximum number of bits in exponent
	 * @param kind the Kind, FINITE, INFINITE, ...
	 * @param sign +1 or -1
	 * @param unscaled the value's mantissa
	 * @param scale value's scale
	 */
	public BigFloat(int fracbits, int expbits, FloatKind kind, int sign, BigInteger unscaled,
			int scale) {
		this.fracbits = fracbits;
		this.expbits = expbits;
		this.kind = kind;
		this.sign = sign;
		this.unscaled = unscaled;
		this.scale = scale;

		this.maxScale = (1 << (expbits - 1)) - 1;
		this.minScale = 1 - this.maxScale;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + expbits;
		result = prime * result + fracbits;
		result = prime * result + kind.hashCode();
		switch (kind) {
			case FINITE:
				result = prime * result + sign;
				result = prime * result + scale;
				result = prime * result + unscaled.hashCode();
				break;
			case INFINITE:
				result = prime * result + sign;
				break;
			case QUIET_NAN:
			case SIGNALING_NAN:
				break;
		}
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		BigFloat other = (BigFloat) obj;
		if (expbits != other.expbits) {
			return false;
		}
		if (fracbits != other.fracbits) {
			return false;
		}
		if (kind != other.kind) {
			return false;
		}
		switch (kind) {
			case FINITE:
				if (sign != other.sign) {
					return false;
				}
				if (scale != other.scale) {
					return false;
				}
				if (!unscaled.equals(other.unscaled)) {
					return false;

				}
				break;
			case INFINITE:
				if (sign != other.sign) {
					return false;
				}
				break;
			case QUIET_NAN:
			case SIGNALING_NAN:
				break;
		}
		return true;
	}

	/**
	 * Return the BigFloat with the given number of bits representing the given BigInteger.
	 * 
	 * @param fracbits number of fractional bits
	 * @param expbits number of bits in the exponent
	 * @param i an integer
	 * @return a BigFloat representing i
	 */
	public static BigFloat valueOf(int fracbits, int expbits, BigInteger i) {
		BigFloat f = new BigFloat(fracbits, expbits, FloatKind.FINITE, i.signum() >= 0 ? +1 : -1,
			i.abs(), fracbits);
		f.scaleUpTo(fracbits + 1);
		return f;
	}

	/**
	 * Return the BigFloat with the given number of bits representing zero.
	 * 
	 * @param fracbits number of fractional bits
	 * @param expbits number of bits in the exponent
	 * @param sign +1 or -1
	 * @return a BigFloat representing +zero or -zero
	 */
	public static BigFloat zero(int fracbits, int expbits, int sign) {
		return new BigFloat(fracbits, expbits, FloatKind.FINITE, sign, BigInteger.ZERO,
			2 - (1 << (expbits - 1)));
	}

	/**
	 * Return the BigFloat with the given number of bits representing (positive) zero.
	 * 
	 * @param fracbits number of fractional bits
	 * @param expbits number of bits in the exponent
	 * @return a BigFloat representing +zero
	 */
	public static BigFloat zero(int fracbits, int expbits) {
		return zero(fracbits, expbits, +1);
	}

	/**
	 * @param fracbits number of fractional bits
	 * @param expbits number of bits in the exponent
	 * @param sign +1 or -1
	 * @return +inf or -inf
	 */
	public static BigFloat infinity(int fracbits, int expbits, int sign) {
		return new BigFloat(fracbits, expbits, FloatKind.INFINITE, sign,
			BigInteger.ONE.shiftLeft(fracbits), (1 << (expbits - 1)) - 1);
	}

	/**
	 * Return the BigFloat with the given number of bits representing (quiet) NaN.
	 * 
	 * @param fracbits number of fractional bits
	 * @param expbits number of bits in the exponent
	 * @param sign +1 or -1
	 * @return a BigFloat representing (quiet) NaN
	 */
	public static BigFloat quietNaN(int fracbits, int expbits, int sign) {
		return new BigFloat(fracbits, expbits, FloatKind.QUIET_NAN, sign, BigInteger.ZERO,
			(1 << (expbits - 1)) - 1);
	}

	private void upscale(int nbits) {
		unscaled = unscaled.shiftLeft(nbits);
		scale -= nbits;
	}

	// guarantee at least significant bits (fractbits+1) plus one for rounding
	protected void scaleUpTo(int newLength) {
		if (kind != FloatKind.FINITE) {
			throw new AssertionError("scaling of non-finite float!");
		}
		int d = newLength - this.unscaled.bitLength();
		if (d > 0) {
			this.upscale(d);
		}
	}

	/**
	 * @return {@code true} if this BigFloat is FINITE and normal
	 */
	public boolean isNormal() {
		return kind == FloatKind.FINITE && unscaled.bitLength() >= fracbits + 1;
	}

	/**
	 * This function is used internally to round after a computation.
	 * 
	 * <p>Assume that the true value is
	 * <pre>   sign * (unscaled + eps) * 2 ^ (scale-fracbits)
	 * and
	 *   unscaled.bitLength() &gt; fracbits+1 
	 *
	 * (or the value is subnormal with at least 1 bit of extra precision)
	 * </pre> 
	 * @param eps &lt; 1
	 */
	protected void internalRound(boolean eps) {
		if (kind != FloatKind.FINITE) {
			throw new AssertionError("Rounding non-finite float");
		}
		if (unscaled.signum() == 0) {
			if (eps) {
				throw new AssertionError("Rounding zero + epsilon, need bit length");
			}
			makeZero();
			return;
		}

		int extrabits = Math.max(unscaled.bitLength() - (fracbits + 1), minScale - scale);

		if (extrabits <= 0) {
			throw new AssertionError("Rounding with no extra bits of precision");
		}

		int midbit = extrabits - 1;
		boolean midbitset = this.unscaled.testBit(midbit);
		eps |= unscaled.getLowestSetBit() < midbit;
		unscaled = unscaled.shiftRight(extrabits);
		scale += extrabits;
		boolean odd = unscaled.testBit(0);

		if (midbitset && (eps || odd)) {
			unscaled = unscaled.add(BigInteger.ONE);
			// handle overflowing carry
			if (unscaled.bitLength() > fracbits + 1) {
				assert (unscaled.bitLength() == unscaled.getLowestSetBit() + 1);
				unscaled = unscaled.shiftRight(1);
				scale += 1;
			}
		}

		if (scale > maxScale) {
			kind = FloatKind.INFINITE;
		}
	}

	protected int getLeadBitPos() {
		if (kind != FloatKind.FINITE || unscaled.signum() == 0) {
			throw new AssertionError("lead bit of non-finite or zero");
		}
		return unscaled.bitLength() - fracbits + scale;
	}

	/**
	 * If finite, the returned BigDecimal is exactly equal to this.  If not finite, one of the
	 * FloatFormat.BIG_* constants is returned.
	 * 
	 * @return a BigDecimal
	 */
	public BigDecimal toBigDecimal() {
		switch (kind) {
			case FINITE:
				// sign * unscaled * 2^(scale-fracbits)
				int iscale = scale - fracbits;
				BigDecimal x;
				if (iscale >= 0) {
					x = new BigDecimal(unscaled.shiftLeft(iscale));
				}
				else {
					x = new BigDecimal(unscaled.multiply(BigInteger.valueOf(5).pow(-iscale)),
						-iscale);
				}
				if (sign < 0) {
					x = x.negate();
				}
				return x;
			case INFINITE:
				return sign < 0 ? FloatFormat.BIG_NEGATIVE_INFINITY
						: FloatFormat.BIG_POSITIVE_INFINITY;
			case QUIET_NAN:
			case SIGNALING_NAN:
				return FloatFormat.BIG_NaN;
			default:
				throw new AssertionError("unknown BigFloat kind: " + kind);
		}
	}

	public String toBinaryString() {
		switch (kind) {
			case QUIET_NAN:
				return "qNaN";
			case SIGNALING_NAN:
				return "sNaN";
			case INFINITE:
				if (sign < 0) {
					return "-inf";
				}
				return "+inf";
			case FINITE:
				String s = (sign < 0) ? "-" : "";

				int ascale = scale;

				String binary;
				if (this.isNormal()) {
					binary = "1." + unscaled.toString(2).substring(1);
					ascale += (unscaled.bitLength() - (fracbits + 1));
				}
				else { // subnormal
					assert (unscaled.bitLength() <= fracbits);
					if (unscaled.equals(BigInteger.ZERO)) {
						return String.format("%s0b0.0", s);
					}
					binary =
						"0." + "0".repeat(fracbits - unscaled.bitLength()) + unscaled.toString(2);
				}
				binary = binary.replaceAll("0*$", "");
				if (binary.endsWith(".")) {
					binary += "0";
				}
				return String.format("%s0b%s * 2^%d", s, binary, ascale);
			default:
				throw new AssertionError("unexpected kind " + kind);
		}
	}

	protected void makeSignalingNaN() {
		this.kind = FloatKind.SIGNALING_NAN;
	}

	protected void makeQuietNaN() {
		this.kind = FloatKind.QUIET_NAN;
	}

	/**
	 * @return {@code true} if this BigFloat is NaN
	 */
	public boolean isNaN() {
		return kind == FloatKind.QUIET_NAN || kind == FloatKind.SIGNALING_NAN;
	}

	protected void makeZero() {
		this.kind = FloatKind.FINITE;
		this.unscaled = BigInteger.ZERO;
		this.scale = minScale;
	}

	/**
	 * @return {@code true} if this BigFloat is infinite
	 */
	public boolean isInfinite() {
		return kind == FloatKind.INFINITE;
	}

	/**
	 * @return {@code true} if this BigFloat is zero
	 */
	public boolean isZero() {
		return this.kind == FloatKind.FINITE && unscaled.equals(BigInteger.ZERO);
	}

	/**
	 * @return a copy of this BigFloat
	 */
	public BigFloat copy() {
		return new BigFloat(fracbits, expbits, kind, sign, unscaled, scale);
	}

	// assuming same fracbits and expbits...
	protected void copyFrom(BigFloat other) {
		this.kind = other.kind;
		this.sign = other.sign;
		this.unscaled = other.unscaled;
		this.scale = other.scale;
	}

	/**
	 * @param a a BigFloat
	 * @param b a BigFloat
	 * @return {@code a/b}
	 */
	public static BigFloat div(BigFloat a, BigFloat b) {
		BigFloat c = a.copy();
		c.div(b);
		return c;
	}

	/**
	 * {@code this/=other}
	 * 
	 * @param other a BigFloat
	 */
	public void div(BigFloat other) {
		if (this.isNaN() || other.isNaN()) {
			makeQuietNaN();
			return;
		}

		if (this.isInfinite()) {
			if (other.isInfinite()) {
				makeQuietNaN();
			}
			else {
				sign *= other.sign;
			}
			return;
		}

		// this is finite
		switch (other.kind) {
			case QUIET_NAN:
			case SIGNALING_NAN:
				this.makeQuietNaN();
				return;
			case INFINITE:
				makeZero();
				sign *= other.sign;
				return;
			case FINITE:
				break;
			default:
				throw new AssertionError("unexpected kind " + other.kind);
		}

		if (other.isZero()) {
			if (this.isZero()) {
				makeQuietNaN();
			}
			else {
				this.kind = FloatKind.INFINITE;
				this.sign *= other.sign;
			}
			return;
		}
		// this is finite, other is finite non zero

		// update representations so that this.unscaled has at fracbits+2 -- normal precision plus one for rounding.
		//
		// for numbers a,b
		//   floor(a)-floor(b)-1 <= floor(a-b) <= floor(a)-floor(b)
		//  nbits(x) = floor(log_2(x))+1, so
		//    nbits(x) - nbits(y) <= nbits(x/y) <= nbits(x) - nbits(y) + 1
		// so 
		//   this + lshift - other = fracbits+2 =>
		int lshift = fracbits + 2 + other.unscaled.bitLength() - this.unscaled.bitLength();
		this.upscale(lshift);

		BigInteger qr[] = this.unscaled.divideAndRemainder(other.unscaled);
		BigInteger q = qr[0];
		BigInteger r = qr[1];

		this.sign *= other.sign;
		this.scale -= other.scale - fracbits;
		this.unscaled = q;
		this.internalRound(r.signum() != 0);
	}

	/**
	 * @param a a BigFloat
	 * @param b a BigFloat
	 * @return {@code a*b}
	 */
	public static BigFloat mul(BigFloat a, BigFloat b) {
		BigFloat c = a.copy();
		c.mul(b);
		return c;
	}

	/**
	 * {@code this*=other}
	 * 
	 * @param other a BigFloat
	 */
	public void mul(BigFloat other) {
		if (this.isNaN() || other.isNaN()) {
			this.makeQuietNaN();
			return;
		}
		if ((this.isZero() && other.isInfinite()) || (this.isInfinite() && other.isZero())) {
			this.makeQuietNaN();
			return;
		}

		if (this.isInfinite() || other.isInfinite()) {
			this.kind = FloatKind.INFINITE;
			this.sign *= other.sign;
			return;
		}

		// this and other are finite
		this.sign *= other.sign;
		this.unscaled = this.unscaled.multiply(other.unscaled);
		this.scale += other.scale - fracbits;

		this.scaleUpTo(fracbits + 2);
		this.internalRound(false);
	}

	/**
	 * @param a a BigFloat
	 * @param b a BigFloat
	 * @return {@code a+b}
	 */
	public static BigFloat add(BigFloat a, BigFloat b) {
		BigFloat c = a.copy();
		c.add(b);
		return c;
	}

	/**
	 * {@code this+=other}
	 * 
	 * @param other a BigFloat
	 */
	public void add(BigFloat other) {
		if (this.isNaN() || other.isNaN()) {
			this.makeQuietNaN();
			return;
		}
		if (this.isInfinite() && other.isInfinite()) {
			if (this.sign != other.sign) {
				this.makeQuietNaN();
			}
			return;
		}
		if (this.isInfinite()) {
			return;
		}
		if (other.isInfinite()) {
			copyFrom(other);
			return;
		}

		if (other.isZero()) {
			if (this.isZero()) {
				this.sign = (this.sign < 0 && other.sign < 0) ? -1 : 1;
			}
			return;
		}
		if (this.isZero()) {
			copyFrom(other);
			return;
		}

		if (this.sign == other.sign) {
			add0(other);
		}
		else {
			sub0(other);
		}
	}

	/**
	 * @param a a BigFloat
	 * @param b a BigFloat
	 * @return {@code a-b}
	 */
	public static BigFloat sub(BigFloat a, BigFloat b) {
		BigFloat c = b.copy();
		c.sign *= -1;
		c.add(a);
		if (c.isZero()) {
			c.sign = (a.sign < 0 && b.sign > 0) ? -1 : 1;
		}
		return c;
	}

	/**
	 * {@code this-=other}
	 * 
	 * @param other a BigFloat
	 */
	public void sub(BigFloat other) {
		int thissign = this.sign;
		BigFloat nother = other.copy();
		nother.sign *= -1;
		this.add(nother);
		if (this.isZero()) {
			this.sign = (thissign < 0 && nother.sign < 0) ? -1 : 1;
		}
	}

	// assume this and other are finite with the same sign, neither is zero
	protected void add0(BigFloat other) {
		int d = this.scale - other.scale;

		if (d > fracbits + 1) {
			return;
		}
		else if (d < -(fracbits + 1)) {
			this.copyFrom(other);
			return;
		}
		boolean residue;
		BigFloat a;
		BigFloat b;

		if (d >= 0) {
			a = this;
			b = other;
		}
		else {
			d = -d;
			a = other;
			b = this;
		}

		residue = b.unscaled.getLowestSetBit() < d - 1;
		this.scale = a.scale - 1;
		this.unscaled = a.unscaled.shiftLeft(1).add(b.unscaled.shiftRight(d - 1));

		scaleUpTo(fracbits + 2);
		internalRound(residue);
	}

	// assume this and other are finite with the opposite sign, neither is zero
	protected void sub0(BigFloat other) {
		int d = this.scale - other.scale;

		if (d > fracbits + 2) {
			return;
		}
		else if (d < -(fracbits + 2)) {
			this.copyFrom(other);
			return;
		}
		boolean residue;
		BigFloat a;
		BigFloat b;
		if (d >= 0) {
			a = this;
			b = other;
		}
		else {
			d = -d;
			a = other;
			b = this;
		}

		// d <= 0 is ok.. no residue and right shift will become left shift
		residue = b.unscaled.getLowestSetBit() < d - 2;
		this.sign = a.sign;
		this.scale = a.scale - 2;
		BigInteger x = b.unscaled;
		x = x.shiftRight(d - 2);
		if (residue) {
			x = x.add(BigInteger.ONE);
		}

		this.unscaled = a.unscaled.shiftLeft(2).subtract(x);
		if (this.unscaled.signum() == 0) {
			this.sign = 1; // cancellation results in positive 0.
		}
		else if (this.unscaled.signum() < 0) {
			this.sign *= -1;
			this.unscaled = this.unscaled.negate();
		}
		scaleUpTo(fracbits + 2);
		internalRound(residue);
	}

	/**
	 * @param a a BigFloat
	 * @return the square root of {@code a}
	 */
	public static BigFloat sqrt(BigFloat a) {
		BigFloat c = a.copy();
		c.sqrt();
		return c;
	}

	/**
	 * {@code this=sqrt(this)}
	 * 
	 *	<p>Square root by abacus algorithm, Martin Guy @ UKC, June 1985.
	 *	From a book on programming abaci by Mr C. Woo.
	 *	Argument is a positive integer, as is result.
	 *
	 *  <p>adapted from http://medialab.freaknet.org/martin/src/sqrt/sqrt.c
	 */
	public void sqrt() {
		if (this.isZero()) {
			return;
		}

		if (this.isNaN() || this.sign == -1) {
			makeQuietNaN();
			return;
		}

		if (this.isInfinite()) {
			return;
		}
		BigInteger residue;
		BigInteger result;
		BigInteger bit;

		//// force at least fracbits+2 bits of precision in the result
		int sigbits = 2 * fracbits + 3;
		this.scaleUpTo(sigbits);

		// scale+fracbits needs to be even for the sqrt computation
		if (((scale + fracbits) & 1) != 0) {
			upscale(1);
		}

		residue = unscaled;
		result = BigInteger.ZERO;

		/* "bit" starts at the highest 4 power <= n. */
		int pow = residue.bitLength() - 1; // highest 2 power <= n
		pow -= pow & 1; // highest 4 power
		bit = BigInteger.ONE.shiftLeft(pow);

		while (bit.signum() != 0) {
			BigInteger resp1 = result.add(bit);
			if (residue.compareTo(resp1) >= 0) {
				residue = residue.subtract(resp1);
				result = result.add(bit.shiftLeft(1));
			}
			result = result.shiftRight(1);
			bit = bit.shiftRight(2);
		}

		unscaled = result;
		scale = (scale + fracbits) / 2;

		internalRound(residue.signum() != 0);
	}

	// floor, ignoring sign
	private void floor0() {
		// value = unscaled * 2^(scale-fracbits)
		if (scale < 0) {
			makeZero();
			return;
		}
		int nbitsUnderOne = fracbits - scale;
		unscaled = unscaled.shiftRight(nbitsUnderOne).shiftLeft(nbitsUnderOne);
	}

	// sign is not set
	private void makeOne() {
		kind = FloatKind.FINITE;
		scale = 0;
		unscaled = BigInteger.ONE.shiftLeft(fracbits);
	}

	// ceil, ignoring sign
	private void ceil0() {
		if (isZero()) {
			return;
		}
		else if (scale < 0) {
			makeOne();
			return;
		}

		int nbitsUnderOne = fracbits - scale;
		boolean increment = unscaled.getLowestSetBit() < nbitsUnderOne;
		unscaled = unscaled.shiftRight(nbitsUnderOne).shiftLeft(nbitsUnderOne);
		if (increment) {
			unscaled = unscaled.add(BigInteger.ONE.shiftLeft(nbitsUnderOne));
		}

		// if we carry to a new bit, change the scale
		if (unscaled.bitLength() > fracbits + 1) {
			upscale(-1);
		}
	}

	/**
	 * @param a a BigFloat
	 * @return {@code floor(a)}
	 */
	public static BigFloat floor(BigFloat a) {
		BigFloat b = a.copy();
		b.floor();
		return b;
	}

	/**
	 * {@code this=floor(this)}
	 */
	public void floor() {
		switch (kind) {
			case INFINITE:
				return;
			case SIGNALING_NAN:
				makeQuietNaN();
			case QUIET_NAN:
				return;
			case FINITE:
				break;
		}

		if (sign >= 0) {
			floor0();
		}
		else {
			ceil0();
		}
	}

	/**
	 * @param a a BigFloat
	 * @return {@code ceil(a)}
	 */
	public static BigFloat ceil(BigFloat a) {
		BigFloat b = a.copy();
		b.ceil();
		return b;
	}

	/**
	 * {@code this=ceil(this)}
	 */
	public void ceil() {
		switch (kind) {
			case INFINITE:
				return;
			case SIGNALING_NAN:
				makeQuietNaN();
			case QUIET_NAN:
				return;
			case FINITE:
				break;
		}

		if (sign >= 0) {
			ceil0();
		}
		else {
			floor0();
		}
	}

	/**
	 * @param a a BigFloat
	 * @return {@code trunc(a)} (round toward zero)
	 */
	public static BigFloat trunc(BigFloat a) {
		BigFloat b = a.copy();
		b.trunc();
		return b;
	}

	/**
	 * {@code this=trunc(this)} (round toward zero)
	 */
	public void trunc() {
		floor0();
	}

	/**
	 * {@code this*=-1}
	 */
	public void negate() {
		this.sign *= -1;
	}

	/**
	 * @param a a BigFloat
	 * @return {@code -a}
	 */
	public static BigFloat negate(BigFloat a) {
		BigFloat b = a.copy();
		b.negate();
		return b;
	}

	/**
	 * @param a a BigFloat
	 * @return {@code abs(a)}
	 */
	public static BigFloat abs(BigFloat a) {
		BigFloat b = a.copy();
		b.abs();
		return b;
	}

	/**
	 * {@code this=abs(this)}
	 */
	public void abs() {
		this.sign = 1;
	}

	/**
	 * @return the truncated integer form of this BigFloat
	 */
	public BigInteger toBigInteger() {
		BigInteger res = unscaled.shiftRight(fracbits - scale);
		if (sign < 0) {
			return res.negate();
		}
		return res;
	}

	/**
	 * @param a a BigFloat
	 * @return {@code round(a)}
	 */
	public static BigFloat round(BigFloat a) {
		BigFloat b = a.copy();
		b.round();
		return b;
	}

	/**
	 * {@code this=round(this)}
	 */
	public void round() {
		BigFloat half = new BigFloat(fracbits, expbits, FloatKind.FINITE, +1,
			BigInteger.ONE.shiftLeft(fracbits), -1);
		add(half);
		floor();
	}

	@Override
	public int compareTo(BigFloat other) {
		// this == NaN
		if (isNaN()) {
			if (other.isNaN()) {
				return 0;
			}
			return 1;
		}
		// this != NaN
		if (other.isNaN()) {
			return -1;
		}
		if (isInfinite()) {
			// this == -inf
			if (sign < 0) {
				if (other.isInfinite() && other.sign < 0) {
					return 0;
				}
				return -1;
			}
			// this == +inf
			if (other.isInfinite() && other.sign > 0) {
				return 0;
			}
			return 1;
		}
		// this is finite
		if (other.isInfinite()) {
			return -other.sign;
		}

		// other is finite
		if (this.sign != other.sign) {
			return this.sign;
		}

		// both finite, same sign
		int c = Integer.compare(this.scale, other.scale);
		if (c != 0) {
			return c * this.sign;
		}

		return this.sign * this.unscaled.compareTo(other.unscaled);
	}

}
