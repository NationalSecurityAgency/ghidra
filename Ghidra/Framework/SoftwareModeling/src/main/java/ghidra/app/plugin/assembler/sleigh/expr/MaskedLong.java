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
package ghidra.app.plugin.assembler.sleigh.expr;

import ghidra.app.plugin.processors.sleigh.expression.TokenField;
import ghidra.util.NumericUtilities;

/**
 * A {@code 64}-bit value where each bit is {@code 0}, {@code 1}, or {@code x} (undefined)
 */
public class MaskedLong implements Comparable<MaskedLong> {
	public static final MaskedLong ZERO = new MaskedLong(-1, 0);
	public static final MaskedLong UNKS = new MaskedLong(0, 0);
	public static final MaskedLong ONES = new MaskedLong(-1, -1);

	protected long msk;
	protected long val;

	/**
	 * Create a masked long given a mask and value
	 */
	protected MaskedLong(long msk, long val) {
		this.msk = msk;
		this.val = val & msk;
	}

	/*
	 * ********************************************************************************************
	 * Static factory methods
	 */

	/**
	 * Create a masked value from a mask and a long
	 * 
	 * Any positions in {@code msk} set to 0 create an {@code x} in the corresponding position of
	 * the result. Otherwise, the position takes the corresponding bit from {@code val}.
	 * 
	 * @param msk the mask
	 * @param val the value
	 * @return the constructed masked long
	 */
	public static MaskedLong fromMaskAndValue(long msk, long val) {
		if (msk == 0) {
			return UNKS;
		}
		if (msk == -1 && val == 0) {
			return ZERO;
		}
		if (msk == -1 && val == -1) {
			return ONES;
		}
		return new MaskedLong(msk, val);
	}

	/**
	 * Create a fully-defined value from the bits of a long
	 * 
	 * @param val the value to take
	 * @return the constructed masked long
	 */
	public static MaskedLong fromLong(long val) {
		return fromMaskAndValue(-1, val);
	}

	/*
	 * ********************************************************************************************
	 * Accessor methods
	 */

	/**
	 * Obtain the value as a long, where all undefined bits are treated as {@code 0}
	 * 
	 * @return the value as a long
	 */
	public long longValue() {
		return val;
	}

	/**
	 * Get the mask as a long
	 * 
	 * Positions with a defined bit are {@code 1}; positions with an undefined bit are {@code 0}.
	 * 
	 * @return the mask as a long
	 */
	public long getMask() {
		return msk;
	}

	/**
	 * True iff there are no undefined bits
	 * 
	 * @return true if fully-defined, false otherwise
	 */
	public boolean isFullyDefined() {
		return msk == -1L;
	}

	/**
	 * True iff there are no defined bits
	 * 
	 * @return true if full-undefined, false otherwise
	 */
	public boolean isFullyUndefined() {
		return msk == 0L;
	}

	/*
	 * ********************************************************************************************
	 * Operators
	 */

	/**
	 * Apply an additional mask to this masked long
	 * 
	 * Any {@code 0} bit in {@code msk} will result in an undefined bit in the result. {@code 1}
	 * bits result in a copy of the corresponding bit in the result.
	 * 
	 * @param mask the mask to apply
	 * @return the result.
	 */
	public MaskedLong mask(long mask) {
		return fromMaskAndValue(this.msk & mask, this.val);
	}

	/**
	 * Sign extend the masked value, according to its mask, to a full long
	 * 
	 * The leftmost defined bit is taken as the sign bit, and extended to the left.
	 * 
	 * @return the sign-extended masked long
	 */
	public MaskedLong signExtend() {
		int bits = 64 - Long.numberOfLeadingZeros(this.msk);
		return signExtend(bits);
	}

	/**
	 * Zero extend the masked value, according to its mask, to a full long
	 * 
	 * All bits to the left of the leftmost defined bit are set to 0.
	 * 
	 * @return the zero-extended masked long
	 */
	public MaskedLong zeroExtend() {
		int bits = 64 - Long.numberOfLeadingZeros(this.msk);
		return zeroExtend(bits);
	}

	/**
	 * Mask out all but the lowest {@code n} bits of the value
	 * 
	 * @param n the number of bits to take (right-to-left)
	 * @return the unknown-extended masked long
	 */
	public MaskedLong unknownExtend(int n) {
		long newMsk = zeroExtend(this.msk, n);
		long newVal = zeroExtend(this.val, n);
		return fromMaskAndValue(newMsk, newVal);
	}

	/**
	 * Sign extend the masked value as if of the given size in bits, to a full long
	 * 
	 * @param n the number of bits to take (right-to-left)
	 * @return the sign-extended masked long
	 */
	public MaskedLong signExtend(int n) {
		long newMsk = signExtend(this.msk, n);
		long newVal = signExtend(this.val, n);
		return fromMaskAndValue(newMsk, newVal);
	}

	/**
	 * Zero extend the masked value as if of the given size in bits, to a full long
	 * 
	 * @param n the number of bits to take (right-to-left)
	 * @return the zero-extended masked long
	 */
	public MaskedLong zeroExtend(int n) {
		long newMsk = signExtend(this.msk, n);
		long newVal = zeroExtend(this.val, n);
		return fromMaskAndValue(newMsk, newVal);
	}

	/**
	 * Combine this and another masked long into one, by taking defined bits from either
	 * 
	 * If this masked long agrees with the other, then the two are combined. For each bit position
	 * in the result, the defined bit from either corresponding position is taken. If neither is
	 * defined, then the position is undefined in the result. If both are defined, they must agree.
	 * 
	 * @param that the other masked long
	 * @return the combined masked long
	 * @throws SolverException if this and the other masked long disagree
	 */
	public MaskedLong combine(MaskedLong that) throws SolverException {
		if (!agrees(that)) {
			throw new SolverException("Cannot combine masked longs that disagree");
		}
		return fromMaskAndValue(this.msk | that.msk, this.val | that.val);
	}

	/**
	 * Shift {@code size} bits @{code n) positions circularly in a given direction
	 *
	 * The shifted bits are the least significant {@code size} bits. The remaining bits are
	 * unaffected.
	 * 
	 * @param n the number of positions
	 * @param size the number of bits (least significant) to include in the shift
	 * @param dir the direction to shift (0 for left, 1 for right)
	 * @return the result
	 */
	public MaskedLong shiftCircular(long n, int size, int dir) {
		if (dir == 1) {
			n = (size - n) % size;
		}
		if (n == 0 | size == 0) {
			return this;
		}
		final long unaffected = size == 64 ? 0 : (-1L) << size;
		final long umsk = unaffected & msk;
		final long uval = unaffected & val;
		final long affected = ~unaffected;
		final long amsk = affected & msk;
		final long aval = affected & val;

		final long newMsk = (amsk >>> (size - n) | amsk << n | umsk) & affected;
		final long newVal = aval >>> (size - n) | aval << n | uval;
		return fromMaskAndValue(newMsk, newVal);
	}

	/**
	 * Shift {@code size} bits @{code n) positions circularly in a given direction
	 *
	 * The shifted bits are the least significant {@code size} bits. The remaining bits are
	 * unaffected.
	 * 
	 * @param n the number of positions
	 * @param size the number of bits (least significant) to include in the shift
	 * @param dir the direction to shift (0 for left, 1 for right)
	 * @return the result
	 */
	public MaskedLong shiftCircular(MaskedLong n, int size, int dir) {
		if (!n.isFullyDefined()) {
			throw new UnsupportedOperationException("Cannot circular shift by an unknown amount");
		}
		return shiftCircular(n.longValue(), size, dir);
	}

	/**
	 * Shift the bits @{code n} positions left
	 * 
	 * This implements both a signed and unsigned shift.
	 * 
	 * @param n the number of positions.
	 * @return the result.
	 */
	public MaskedLong shiftLeft(long n) {
		if (n == 0) {
			return this;
		}
		// Zeros, not unknowns, fill the right
		long atright = ~((-1L) << n);
		return fromMaskAndValue((this.msk << n) | atright, this.val << n);
	}

	/**
	 * Shift the bits {@code n} positions left
	 * 
	 * This implements both a signed and unsigned shift.
	 * 
	 * @param n the number of positions.
	 * @return the result.
	 */
	public MaskedLong shiftLeft(MaskedLong n) {
		if (!n.isFullyDefined()) {
			throw new UnsupportedOperationException("Cannot left shift by an unknown amount");
		}
		return shiftLeft(n.longValue());
	}

	/**
	 * Invert a left shift of {@code n} positions, that is shift right
	 * 
	 * This is different from a normal shift right, in that it inserts unknowns at the left. The
	 * normal right shift inserts zeros or sign bits. Additionally, if any ones would fall off the
	 * right, the inversion is undefined.
	 * 
	 * @param n the number of positions
	 * @return the result
	 * @throws SolverException if the inversion is undefined
	 */
	public MaskedLong invShiftLeft(long n) throws SolverException {
		if (n == 0) {
			return this;
		}
		long checkDef = ~(-1L << n) & val;
		if (checkDef != 0) {
			throw new SolverException("Cannot invert left shift where ones appear on the right");
		}
		return shiftRightPositional(n);
	}

	/**
	 * Invert a left shift of {@code n} positions, that is shift right
	 * 
	 * This is different from a normal shift right, in that it inserts unknowns at the left. The
	 * normal right shift inserts zeros or sign bits. Additionally, if any ones would fall off the
	 * right, the inversion is undefined.
	 * 
	 * @param n the number of positions
	 * @return the result
	 * @throws SolverException if the inversion is undefined
	 */
	public MaskedLong invShiftLeft(MaskedLong n) throws SolverException {
		if (!n.isFullyDefined()) {
			throw new UnsupportedOperationException("Cannot right shift by an unknown amount");
		}
		return invShiftLeft(n.longValue());
	}

	/**
	 * Shift the bits arithmetically {@code n} positions right
	 * 
	 * This implements a signed shift.
	 * 
	 * @param n the number of positions.
	 * @return the result.
	 */
	public MaskedLong shiftRight(long n) {
		if (n == 0) {
			return this;
		}
		return fromMaskAndValue(this.msk >> n, this.val >> n);
	}

	/**
	 * Shift the bits arithmetically {@code n} positions right
	 * 
	 * This implements a signed shift.
	 * 
	 * @param n the number of positions.
	 * @return the result.
	 */
	public MaskedLong shiftRight(MaskedLong n) {
		if (!n.isFullyDefined()) {
			throw new UnsupportedOperationException("Cannot right shift by an unknown amount");
		}
		return shiftRight(n.longValue());
	}

	/**
	 * Invert an arithmetic right shift of {@code n} positions, that is shift left
	 * 
	 * This is different from a normal shift left, in that it inserts unknowns at the right. The
	 * normal left shift inserts zeros. Additionally, all bits that fall off the left must match the
	 * resulting sign bit, or else the inversion is undefined.
	 * 
	 * @param n the number of positions
	 * @return the result
	 * @throws SolverException if the inversion is undefined
	 */
	public MaskedLong invShiftRight(long n) throws SolverException {
		if (n == 0) {
			return this;
		}
		long checkVal = (Long.MIN_VALUE >> n) & val;
		long checkMsk = (Long.MIN_VALUE >> n) & msk;
		if (checkMsk == 0) { // All fallen bits and sign bit unknown
			return new MaskedLong(msk << n, val << n);
		}
		// All defined bits must match.
		// Additionally, if the resulting sign bit is undefined, but any fallen bit is defined,
		// then the sign bits is actually defined
		if (checkVal == 0) { // All known (of fallen and sign bits) zero
			return new MaskedLong(msk << n | Long.MIN_VALUE, val << n);
		}
		if (checkVal == checkMsk) { // All known (of fallen and sign bits) one
			return new MaskedLong(msk << n | Long.MIN_VALUE, val << n | Long.MIN_VALUE);
		}
		throw new SolverException(
			"Cannot invert arithmetic right shift where bits to the left disagree");
	}

	/**
	 * Invert an arithmetic right shift of {@code n} positions, that is shift left
	 * 
	 * This is different from a normal shift left, in that it inserts unknowns at the right. The
	 * normal left shift inserts zeros. Additionally, all bits that fall off the left must match the
	 * resulting sign bit, or else the inversion is undefined.
	 * 
	 * @param n the number of positions
	 * @return the result
	 * @throws SolverException if the inversion is undefined
	 */
	public MaskedLong invShiftRight(MaskedLong n) throws SolverException {
		if (!n.isFullyDefined()) {
			throw new UnsupportedOperationException("Cannot left shift by an unknown amount");
		}
		return invShiftRight(n.longValue());
	}

	/**
	 * Shift the bits logically {@code n} positions right
	 * 
	 * This implements an unsigned shift.
	 * 
	 * @param n the number of positions.
	 * @return the result.
	 */
	public MaskedLong shiftRightLogical(long n) {
		if (n == 0) {
			return this;
		}
		// Zeros, not unknowns, fill in the left.
		long atleft = Long.MIN_VALUE >> (n - 1);
		return fromMaskAndValue((this.msk >>> n) | atleft, this.val >>> n);
	}

	/**
	 * Shift the bits logically {@code n} positions right
	 * 
	 * This implements an unsigned shift.
	 * 
	 * @param n the number of positions.
	 * @return the result.
	 */
	public MaskedLong shiftRightLogical(MaskedLong n) {
		if (!n.isFullyDefined()) {
			throw new UnsupportedOperationException(
				"Cannot right logical shift by an unknown amount");
		}
		return shiftRightLogical(n.longValue());
	}

	/**
	 * Shift the bits positionally {@code n} positions right
	 * 
	 * This fills the left with unknown bits
	 * 
	 * @param n
	 * @return
	 */
	public MaskedLong shiftRightPositional(long n) {
		return fromMaskAndValue(this.msk >>> n, this.val >>> n);
	}

	/**
	 * Invert a logical right shift of {@code n} positions, that is shift left
	 * 
	 * This is different from a normal shift left, in that it inserts unknowns at the right. The
	 * normal left shift inserts zeros. Additionally, if any ones would fall off the left, the
	 * inversion is undefined.
	 * 
	 * @param n the number of positions
	 * @return the result
	 * @throws SolverException if the inversion is undefined
	 */
	public MaskedLong invShiftRightLogical(long n) throws SolverException {
		if (n == 0) {
			return this;
		}
		long checkDef = Long.MIN_VALUE >> (n - 1) & val;
		if (checkDef != 0) {
			throw new SolverException(
				"Cannot invert logical right shift where ones appear on the left");
		}
		return new MaskedLong(msk << n, val << n);
	}

	/**
	 * Invert a logical right shift of {@code n} positions, that is shift left
	 * 
	 * This is different from a normal shift left, in that it inserts unknowns at the right. The
	 * normal left shift inserts zeros. Additionally, if any ones would fall off the left, the
	 * inversion is undefined.
	 * 
	 * @param n the number of positions
	 * @return the result
	 * @throws SolverException if the inversion is undefined
	 */
	public MaskedLong invShiftRightLogical(MaskedLong n) throws SolverException {
		if (!n.isFullyDefined()) {
			throw new UnsupportedOperationException("Cannot left shift by an unknown amount");
		}
		return invShiftRightLogical(n.longValue());
	}

	/**
	 * Reverse the least significant {@code n} bytes
	 * 
	 * This interprets the bits as an {@code n}-byte value and changes the endianness. Any bits
	 * outside of the interpretation are truncated, i.e., become unknown.
	 * 
	 * @param n the size, in bytes, of the interpreted value.
	 * @return the result.
	 */
	public MaskedLong byteSwap(int n) {
		return fromMaskAndValue(TokenField.byteSwap(msk, n), TokenField.byteSwap(val, n));
	}

	/**
	 * Compute the bitwise AND of this and another masked long
	 * 
	 * To handle unknown bits, the result is derived from the following truth table:
	 * 
	 * <pre>{@literal
	 *   0 x 1 <= A (this)
	 * 0 0 0 0
	 * x 0 x x
	 * 1 0 x 1
	 * ^
	 * B (that)
	 * }</pre>
	 * 
	 * @param that the other masked long ({@code B}).
	 * @return the result.
	 */
	public MaskedLong and(MaskedLong that) {
		long newMsk = this.msk & that.msk;
		long newVal = this.val & that.val;

		// If we have a definite 0 on either side, we know the results is definitely 0.
		// Careful we don't ignore the mask. Only definite 0s give a definite 0.
		newMsk |= this.msk & ~this.val;
		newMsk |= that.msk & ~that.val;

		// No need to remask. I checked the arithmetic.
		assert newVal == (newMsk & newVal);
		return fromMaskAndValue(newMsk, newVal);
	}

	/**
	 * Solves the expression {@code A & B = C, for B, given C and A}
	 * <p>
	 * To handle unknown bits, the solution is derived from the following truth table, where
	 * {@code *} indicates no solution:
	 * 
	 * <pre>{@literal
	 *   0 x 1 <= A (that)
	 * 0 x x 0
	 * x x x x
	 * 1 * 1 1
	 * ^
	 * B (this)
	 * }</pre>
	 * 
	 * @param that the other masked long ({@code B}).
	 * @return the result.
	 * @throws SolverException if no solution exists.
	 */
	public MaskedLong invAnd(MaskedLong that) throws SolverException {
		long newMsk = this.msk & that.msk;
		long newVal = this.val;

		// Check for the error case
		if ((newMsk & this.val & ~that.val) != 0) {
			throw new SolverException("0 & X == 1 cannot be solved.");
		}

		// Make 0,0 give x (this will also get everything where that==0)
		newMsk &= that.val;
		// Make x,1 give 1 (this will also get everything where this==1)
		newMsk |= this.val;

		// No need to remask. I checked the arithmetic.
		assert newVal == (newMsk & newVal);
		// Eh, the constructor does it anyway....
		return fromMaskAndValue(newMsk, newVal);
	}

	/**
	 * Compute the bitwise OR of this and another masked long
	 * 
	 * To handle unknown bits, the result is derived from the following truth table:
	 * 
	 * <pre>{@literal
	 *   0 x 1 <= A (this)
	 * 0 0 x 1
	 * x x x 1
	 * 1 1 1 1
	 * ^
	 * B (that)
	 * }</pre>
	 * 
	 * @param that the other masked long ({@code B}).
	 * @return the result.
	 */
	public MaskedLong or(MaskedLong that) {
		long newMsk = this.msk & that.msk;
		long newVal = this.val | that.val;

		// If we have a definite 1 on either side, we know the results is definitely 1.
		// We can ignore the mask. A 1 in the value must be a definite 1, or else it would have
		// been masked out.
		newMsk |= this.val;
		newMsk |= that.val;

		// No need to remask. I checked the arithmetic.
		assert newVal == (newMsk & newVal);
		// Eh, the constructor does it anyway....
		return fromMaskAndValue(newMsk, newVal);
	}

	/**
	 * Solves the expression A | B = C, for B, given C and A
	 * 
	 * To handle unknown bits, the solution is derived from the following truth table, where
	 * {@code *} indicates no solution:
	 * 
	 * <pre>{@literal
	 *   0 x 1 <= A (that)
	 * 0 0 0 *
	 * x x x x
	 * 1 1 x x
	 * ^
	 * B (this)
	 * }</pre>
	 * 
	 * @param that the other masked long ({@code B}).
	 * @return the result.
	 * @throws SolverException if not solution exists.
	 */
	public MaskedLong invOr(MaskedLong that) throws SolverException {
		long newMsk = this.msk & that.msk;
		long newVal = this.val;

		// Check for the error case
		if ((newMsk & ~this.val & that.val) != 0) {
			throw new SolverException("1 | X == 0 cannot be solved.");
		}

		// This time, we must be wary the masks.
		// Make 1,1 give x (this will also get everything where that==1)
		newMsk &= ~(that.msk & that.val);
		// Make x,0 give 0 (this will also get everything where this==0)
		newMsk |= (this.msk & ~this.val);

		// Remask taken care of by constructor.
		return fromMaskAndValue(newMsk, newVal);
	}

	/**
	 * Compute the bitwise XOR of this and another masked long
	 * 
	 * To handle unknown bits, the result is derived from the following truth table:
	 * 
	 * <pre>{@literal
	 *   0 x 1 <= A (this)
	 * 0 0 x 1
	 * x x x x
	 * 1 1 x 0
	 * ^
	 * B (that)
	 * }</pre>
	 * 
	 * @param that the other masked long ({@code B}).
	 * @return the result.
	 */
	public MaskedLong xor(MaskedLong that) {
		long newMsk = this.msk & that.msk;
		long newVal = this.val ^ that.val;

		// Remask taken care of by constructor.
		return fromMaskAndValue(newMsk, newVal);
	}

	/**
	 * Negate the value
	 * 
	 * @return the result.
	 */
	public MaskedLong negate() {
		if (!isFullyDefined()) {
			throw new UnsupportedOperationException("Cannot negate unknown values, yet.");
			// TODO: Work this using a ripple-carry method, if needed.
		}
		return fromMaskAndValue(-1, -val);
	}

	/**
	 * Compute the bitwise NOT
	 * 
	 * To handle unknown bits, the result is derived from the following truth table:
	 * 
	 * <pre>{@literal
	 * 0 x 1 <= A (this)
	 * 1 x 0
	 * }</pre>
	 * 
	 * @return the result.
	 */
	public MaskedLong not() {
		return fromMaskAndValue(msk, ~val);
	}

	/**
	 * Compute the arithmetic sum of this and another masked long
	 * 
	 * @param that the other masked long.
	 * @return the result.
	 */
	public MaskedLong add(MaskedLong that) {
		if (!this.isFullyDefined() || !that.isFullyDefined()) {
			return doRippleCarry(this, that, false);
		}
		return fromMaskAndValue(-1, this.val + that.val);
	}

	/**
	 * Compute the arithmetic difference: this masked long minus another
	 * 
	 * @param that the other masked long.
	 * @return the result.
	 */
	public MaskedLong subtract(MaskedLong that) {
		if (!this.isFullyDefined() || !that.isFullyDefined()) {
			return doRippleCarry(this, that, true);
		}
		return fromMaskAndValue(-1, this.val - that.val);
	}

	private static MaskedLong doRippleCarry(MaskedLong l, MaskedLong r, boolean subtract) {
		// Use ripple-carry method with unknowns
		// TODO: See if there's a faster way to go about this
		// NOTE: "bits" are represented with 2 bits: mask,val, e.g., 2 is known 0
		byte cmv = subtract ? (byte) 3 : 2; // carry: known 1 for subtract, known 0 for add
		long dmsk = 0;
		long dval = 0;
		for (long cur = 1; cur != 0; cur <<= 1) {
			byte lmv = 0;
			lmv |= (l.msk & cur) != 0 ? 2 : 0;
			lmv |= (l.val & cur) != 0 ? 1 : 0;

			byte rmv = 0;
			rmv |= (r.msk & cur) != 0 ? 2 : 0;
			rmv |= (r.val & cur) != 0 ^ subtract ? 1 : 0;

			byte nextcmv = or(and(cmv, lmv), and(cmv, rmv), and(lmv, rmv));
			byte dmv = xor(cmv, lmv, rmv);
			cmv = nextcmv;
			if ((dmv & 2) != 0) {
				dmsk |= cur;
				if ((dmv & 1) != 0) {
					dval |= cur;
				}
			}
		}
		return fromMaskAndValue(dmsk, dval);
	}

	private static byte and(byte rmv, byte lmv) {
		// See truth table for AND above
		if (lmv == 2 || rmv == 2) {
			return 2;
		}
		else if (lmv == 3 || rmv == 3) {
			return 3;
		}
		return 0;
	}

	private static byte or(byte rmv, byte lmv) {
		// See truth table for OR above
		if (lmv == 3 || rmv == 3) {
			return 3;
		}
		else if (lmv == 2 && rmv == 2) {
			return 2;
		}
		return 0;
	}

	private static byte or(byte t1, byte t2, byte t3) {
		return or(or(t1, t2), t3);
	}

	private static byte xor(byte rmv, byte lmv) {
		// See truth table for XOR above
		if ((lmv & 2) == 0 || (rmv & 2) == 0) {
			return 0;
		}
		return (byte) ((lmv ^ rmv) | 2);
	}

	private static byte xor(byte t1, byte t2, byte t3) {
		return xor(xor(t1, t2), t3);
	}

	/**
	 * Compute the arithmetic product of this and another masked long
	 * 
	 * @param that the other masked long.
	 * @return the result.
	 */
	public MaskedLong multiply(MaskedLong that) {
		if (this.isFullyDefined() && that.isFullyDefined()) {
			return fromMaskAndValue(-1, this.val * that.val);
		}
		else if (that.isFullyDefined()) {
			// If it's a power of 2, re-write as bit shift
			if (Long.bitCount(that.val) == 1) {
				return this.shiftLeft(Long.numberOfTrailingZeros(that.val));
			}
		}
		else if (this.isFullyDefined()) {
			if (Long.bitCount(this.val) == 1) {
				return that.shiftLeft(Long.numberOfTrailingZeros(this.val));
			}
		}

		// TODO: Distinguish size, don't knows, from don't cares.
		// Assume unknown bits to the left are actually don't cares. That is, they specify the size
		// of the "field"
		int thisSize = Long.numberOfTrailingZeros(~this.msk);
		int thatSize = Long.numberOfTrailingZeros(~that.msk);
		if (thisSize + Long.numberOfLeadingZeros(this.msk) == Long.SIZE) {
			if (thatSize + Long.numberOfLeadingZeros(that.msk) == Long.SIZE) {
				int newSize = thisSize + thatSize;
				return fromMaskAndValue(~(-1L << newSize), this.val * that.val);
			}
		}

		throw new UnsupportedOperationException("Cannot multiply unknown values, yet.");
		// TODO: Work this using a bitwise algorithm, if *really* needed.
	}

	public MaskedLong divideSigned(MaskedLong that) {
		if (this.isFullyDefined() && that.isFullyDefined()) {
			long newVal = this.val / that.val;
			return fromMaskAndValue(-1, newVal);
		}
		else if (that.isFullyDefined()) {
			// If it's a power of 2, re-write as bit shift
			if (Long.bitCount(that.val) == 1) {
				return shiftRight(Long.numberOfTrailingZeros(that.val));
			}
			// Ditto from #divideUnsigned
			else if (Long.numberOfLeadingZeros(this.msk) +
				Long.numberOfTrailingZeros(~this.msk) == Long.SIZE) {
				return fromMaskAndValue(this.msk, this.val / that.val);
			}
		}
		throw new UnsupportedOperationException("Cannot divide unknown values, yet.");
	}

	/**
	 * Compute the unsigned arithmetic quotient: this masked long divided by another
	 * 
	 * @param that the other masked long.
	 * @return the result.
	 */
	public MaskedLong divideUnsigned(MaskedLong that) {
		if (this.isFullyDefined() && that.isFullyDefined()) {
			//long newVal = this.val / that.val;
			long newVal = Long.divideUnsigned(this.val, that.val);
			return fromMaskAndValue(-1, newVal);
		}
		else if (that.isFullyDefined()) {
			// If it's a power of 2, re-write as bit shift
			if (Long.bitCount(that.val) == 1) {
				return shiftRightLogical(Long.numberOfTrailingZeros(that.val));
			}
			// TODO: Some way to distinguish size, or perhaps don't know from don't care
			// TODO: Some way to distinguish sign
			// If all unknown bits are at the far left, just assume they are zero
			// We may lose some possibilities, but we'll have at least found one
			else if (Long.numberOfLeadingZeros(this.msk) +
				Long.numberOfTrailingZeros(~this.msk) == Long.SIZE) {
				return fromMaskAndValue(this.msk, Long.divideUnsigned(this.val, that.val));
			}
		}
		throw new UnsupportedOperationException("Cannot divide unknown values, yet.");
		// TODO: Work this using a bitwise algorithm, if *really* needed.
		// AFAICT, a bitwise algorithm doesn't buy much at all
	}

	/**
	 * Compute the arithmetic quotient as a solution to unsigned multiplication
	 * 
	 * This is slightly different than {@link #divideUnsigned(MaskedLong)} in its treatment of
	 * unknowns.
	 * 
	 * @param that the known factor
	 * @return a solution to that*x == this, if possible
	 * @throws SolverException
	 */
	public MaskedLong invMultiplyUnsigned(MaskedLong that) throws SolverException {
		if (that.isFullyDefined()) {
			// If it's a power of 2, re-write as bit shift
			if (Long.bitCount(that.val) == 1) {
				return invShiftLeft(Long.numberOfTrailingZeros(that.val));
			}
			// Ditto comments from #divideUnsigned
			// TODO: Is this correct or even useful?
			else if (Long.numberOfLeadingZeros(this.msk) +
				Long.numberOfTrailingZeros(~this.msk) == Long.SIZE) {
				return fromMaskAndValue(this.msk, Long.divideUnsigned(this.val, that.val));
			}
		}
		throw new UnsupportedOperationException("Cannot divide unknown values, yet.");
	}

	/*
	 * ********************************************************************************************
	 * Equality and comparison stuff
	 */

	/**
	 * Checks if this and another masked long agree
	 * 
	 * Two masked longs agree iff their corresponding defined bit positions are equal. Where either
	 * or both positions are undefined, no check is applied. In the case that both masked longs are
	 * fully-defined, this is the same as an equality check on the values.
	 * 
	 * @param that the other masked long.
	 * @return true if this and that agree.
	 */
	public boolean agrees(MaskedLong that) {
		long bothmsk = this.msk & that.msk;
		if ((this.val & bothmsk) != (that.val & bothmsk)) {
			return false;
		}
		return true;
	}

	/**
	 * Checks if this and a long agree
	 * 
	 * The masked long agrees with the given long iff the masked long's defined bit positions agree
	 * with the corresponding bit positions in the given long. Where there are undefined bits, no
	 * check is applied. In the case that the masked long is fully-defined, this is the same as an
	 * equality check on the value.
	 * 
	 * @param that the long
	 * @return true if this and that agree.
	 */
	public boolean agrees(long that) {
		that &= msk;
		return val == that;
	}

	/**
	 * Check if this and another object agree
	 * 
	 * @param that a {@link MaskedLong} or {@link Long} to check.
	 * @see #agrees(MaskedLong)
	 * @see #agrees(long)
	 * @return true if this and that agree.
	 */
	public boolean agrees(Object that) {
		if (that instanceof Long) {
			return agrees(((Long) that).longValue());
		}
		else if (that instanceof MaskedLong) {
			return agrees((MaskedLong) that);
		}
		else {
			throw new IllegalArgumentException("must be Long or MaskedLong: " + that);
		}
	}

	/**
	 * Check if the masked value falls within a given range
	 * 
	 * The range is defined by a maximum and a signedness. The maximum must be one less than a
	 * positive power of 2. In other words, it defines a maximum number of bits, including the sign
	 * bit if applicable.
	 * 
	 * The defined bits of this masked long are then checked to fall in the given range. The
	 * effective value is derived by sign/zero extending the value according to its mask. In
	 * general, if any {@code 1} bits exist outside of the given max, the value is rejected, unless
	 * that {@code 1} is purely a result of signedness.
	 * 
	 * @param max the maximum value, taken as an unsigned long.
	 * @param signed true to interpret the masked value as signed.
	 * @return true if the masked value "fits" into the given range.
	 */
	public boolean isInRange(long max, boolean signed) {
		if (-1 == max) {
			return true; // Every long, signed or unsigned fits
		}
		long min = 0;
		if (signed) {
			max >>>= 1;
			min = ~max;
			long ckVal = signExtend().longValue();
			return min <= ckVal && ckVal <= max; // ---[--v--.--v--]---
		}
		// unsigned
		long ckVal = zeroExtend().longValue();
		if (max < 0) {
			return ckVal >= 0 || ckVal <= max; //   ---v--]--.[--v---
		}
		return ckVal >= 0 && ckVal <= max; //       ---.[--v--]---
	}

	/**
	 * "Compare" two masked longs
	 * 
	 * This is not meant to reflect a numerical comparison. Rather, this is just to impose an
	 * ordering for the sake of storing these in sorted collections.
	 */
	@Override
	public int compareTo(MaskedLong that) {
		long result = this.msk - that.msk;
		if (result < 0) {
			return -1;
		}
		if (result > 0) {
			return 1;
		}
		result = this.val - that.val;
		if (result < 0) {
			return -1;
		}
		if (result > 0) {
			return 1;
		}
		return 0;
	}

	/**
	 * Check for equality
	 * 
	 * This will only return true if the other object is a masked long, even if this one is
	 * fully-defined, and the value is equal to a given long (or {@link Long}). The other masked
	 * long must have the same mask and value to be considered equal. For other sorts of "equality"
	 * checks, see {@link #agrees(Object)} and friends.
	 */
	@Override
	public boolean equals(Object other) {
		if (!(other instanceof MaskedLong)) {
			return false;
		}
		MaskedLong that = (MaskedLong) other;
		return this.msk == that.msk && this.val == that.val;
	}

	@Override
	public int hashCode() {
		int result = Long.hashCode(msk);
		result *= 31;
		result += Long.hashCode(val);
		return result;
	}

	/*
	 * ********************************************************************************************
	 * Misc
	 */

	@Override
	public String toString() {
		return NumericUtilities.convertMaskedValueToHexString(msk, val, 16, true, 2, ":");
	}

	/**
	 * Sign extend a number of the given size in bits, to a full long
	 * 
	 * @param val the value to extend
	 * @param bits the number of bits to take (right-to-left)
	 * @return the sign-extended value as a long
	 */
	protected static long signExtend(long val, int bits) {
		int slam = 64 - bits;
		return (val << slam) >> slam;
	}

	/**
	 * Zero extend a number of the given size in bits, to a full long
	 * 
	 * @param val the value to extend
	 * @param bits the number of bits to take (right-to-left)
	 * @return the zero-extended value as a long
	 */
	protected static long zeroExtend(long val, int bits) {
		int slam = 64 - bits;
		return (val << slam) >>> slam;
	}

	/**
	 * Set all undefined bits to 0
	 * 
	 * @return the result
	 */
	public MaskedLong fillMask() {
		return new MaskedLong(-1, val);
	}
}
