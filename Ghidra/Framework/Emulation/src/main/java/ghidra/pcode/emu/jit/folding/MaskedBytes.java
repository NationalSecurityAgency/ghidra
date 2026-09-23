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
package ghidra.pcode.emu.jit.folding;

import java.math.BigInteger;
import java.util.Arrays;

import ghidra.pcode.utils.Utils;
import ghidra.program.model.lang.Endian;

/**
 * A masked array of bytes.
 * <p>
 * This consists of a pair of byte arrays. One that represents the values, if known, and another
 * that indicates which bits of the values array are actually known.
 */
public final class MaskedBytes {
	final byte[] val;
	final byte[] msk;

	/**
	 * Construct from arrays
	 * <p>
	 * The given arrays are copied, and the mask is applied so that all unknown bits have 0s in the
	 * values array.
	 * 
	 * @param val the value array
	 * @param msk the mask array
	 * @return the masked bytes
	 */
	public static MaskedBytes of(byte[] val, byte[] msk) {
		final int l = val.length;
		if (val.length != l) {
			throw new IllegalArgumentException("Lengths must match");
		}
		byte[] mval = new byte[l];
		for (int i = 0; i < l; i++) {
			mval[i] = (byte) (val[i] & msk[i]);
		}
		return new MaskedBytes(mval, Arrays.copyOf(msk, l));
	}

	/**
	 * Construct from big integers
	 * 
	 * @param val the value
	 * @param msk the bits of the value that are known
	 * @param length the size of the value in bytes
	 * @param endian the endianness of the bytes
	 * @return the masked bytes
	 */
	public static MaskedBytes of(BigInteger val, BigInteger msk, int length, Endian endian) {
		byte[] bVal = Utils.bigIntegerToBytes(val, length, endian.isBigEndian());
		byte[] bMsk = Utils.bigIntegerToBytes(msk, length, endian.isBigEndian());
		return of(bVal, bMsk);
	}

	/**
	 * Construct from longs
	 * 
	 * @param val the value
	 * @param msk the bits of the value that are known
	 * @param length the size of the value in bytes
	 * @param endian the endianness of the bytes
	 * @return the masked bytes
	 */
	public static MaskedBytes of(long val, long msk, int length, Endian endian) {
		byte[] bVal = Utils.longToBytes(val, length, endian.isBigEndian());
		byte[] bMsk = Utils.longToBytes(msk, length, endian.isBigEndian());
		return of(bVal, bMsk);
	}

	/**
	 * Construct from known bytes
	 * <p>
	 * The resulting mask is all 1s.
	 * 
	 * @param val the known values
	 * @return the masked bytes
	 */
	public static MaskedBytes ofKnown(byte[] val) {
		final int l = val.length;
		byte[] msk = new byte[l];
		Arrays.fill(msk, (byte) -1);
		return new MaskedBytes(Arrays.copyOf(val, l), msk);
	}

	/**
	 * Construct completely unknown
	 * <p>
	 * The contents of both arrays (value and mask) are all 0s
	 * 
	 * @param length the number of bytes
	 * @return the masked bytes
	 */
	public static MaskedBytes ofUnknown(int length) {
		return new MaskedBytes(new byte[length], new byte[length]);
	}

	MaskedBytes(byte[] val, byte[] msk) {
		assert val.length == msk.length;
		this.val = val;
		this.msk = msk;
	}

	@Override
	public boolean equals(Object o) {
		if (!(o instanceof MaskedBytes that)) {
			return false;
		}
		return Arrays.equals(this.val, that.val) && Arrays.equals(this.msk, that.msk);
	}

	private void byteToString(StringBuilder sb, int i) {
		byte v = val[i];
		byte m = msk[i];
		if (m == -1) {
			sb.append("%02x".formatted(v));
			return;
		}
		for (int j = 0; j < 2; j++) {
			if ((m & 0xf0) == 0xf0) {
				sb.append("%1x".formatted(Byte.toUnsignedInt(v) >>> 4));
				m <<= 4;
				v <<= 4;
			}
			else if ((m & 0xf0) == 0) {
				sb.append("X");
				m <<= 4;
				v <<= 4;
			}
			else {
				sb.append("[");
				for (int k = 0; k < 4; k++) {
					if ((m & 0x80) == 0x80) {
						sb.append("%1x".formatted(Byte.toUnsignedInt(v) >>> 7));
					}
					else {
						sb.append("x");
					}
					m <<= 1;
					v <<= 1;
				}
				sb.append("]");
			}
		}
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < val.length; i++) {
			byteToString(sb, i);
			sb.append(":");
		}
		return sb.substring(0, sb.length() - 1);
	}

	/**
	 * {@return true if <em>any</em> portion, even a single bit, of the value is unknown}
	 */
	public boolean isMasked() {
		for (int i = 0; i < msk.length; i++) {
			if (msk[i] != -1) {
				return true;
			}
		}
		return false;
	}

	/**
	 * {@return the value as an unsigned big integer}
	 * 
	 * @param endian the endianness of the bytes
	 */
	public BigInteger bigValue(Endian endian) {
		return Utils.bytesToBigInteger(val, val.length, endian.isBigEndian(), false);
	}

	/**
	 * {@return the value as a signed big integer}
	 * 
	 * @param endian the endianness of the bytes
	 */
	public BigInteger bigValueSigned(Endian endian) {
		return Utils.bytesToBigInteger(val, val.length, endian.isBigEndian(), true);
	}

	/**
	 * {@return the mask as an unsigned big integer}
	 * 
	 * @param endian the endianness of the bytes
	 */
	public BigInteger bigMask(Endian endian) {
		return Utils.bytesToBigInteger(msk, msk.length, endian.isBigEndian(), false);
	}

	/**
	 * {@return the mask as a signed big integer}
	 * 
	 * @param endian the endianness of the bytes
	 */
	public BigInteger bigMaskSigned(Endian endian) {
		return Utils.bytesToBigInteger(msk, msk.length, endian.isBigEndian(), true);
	}

	/**
	 * Invert the known bits
	 * 
	 * @return the new masked bytes
	 */
	public MaskedBytes negate() {
		byte[] neg = new byte[val.length];
		for (int i = 0; i < val.length; i++) {
			neg[i] = (byte) (~val[i] & msk[i]);
		}
		return new MaskedBytes(neg, msk);
	}

	/**
	 * Perform a bitwise and
	 * <p>
	 * Note that known 0s in either operand cause known 0s in the result, even if the same bit of
	 * the other operand was unknown.
	 * 
	 * @param that the other operand
	 * @return the result
	 */
	public MaskedBytes and(MaskedBytes that) {
		final int n = Math.min(this.val.length, that.val.length);
		final int l = Math.max(this.val.length, that.val.length);
		byte[] val = new byte[l];
		byte[] msk = new byte[l];
		for (int i = 0; i < n; i++) {
			val[i] = (byte) (this.val[i] & that.val[i]);
			int thisKnown0 = this.msk[i] & ~this.val[i];
			int thatKnown0 = that.msk[i] & ~that.val[i];
			msk[i] = (byte) (this.msk[i] & that.msk[i] | thisKnown0 | thatKnown0);
		}
		for (int i = n; i < l; i++) {
			// val[i] already 0
			msk[i] = -1;
		}
		return new MaskedBytes(val, msk);
	}

	/**
	 * Perform a bitwise or
	 * <p>
	 * Note that known 1s in either operand cause known ss in the result, even if the same bit of
	 * the other operand was unknown.
	 * 
	 * @param that the other operand
	 * @return the result
	 */
	public MaskedBytes or(MaskedBytes that) {
		final int n = Math.min(this.val.length, that.val.length);
		final int l = Math.max(this.val.length, that.val.length);
		byte[] val = new byte[l];
		byte[] msk = new byte[l];
		for (int i = 0; i < n; i++) {
			val[i] = (byte) (this.val[i] | that.val[i]);
			int thisKnown1 = this.msk[i] & this.val[i];
			int thatKnown1 = that.msk[i] & that.val[i];
			msk[i] = (byte) (this.msk[i] & that.msk[i] | thisKnown1 | thatKnown1);
		}
		byte[] v = this.val.length == n ? that.val : this.val;
		byte[] m = this.val.length == n ? that.msk : this.msk;
		for (int i = n; i < l; i++) {
			val[i] = v[i];
			msk[i] = m[i];
		}
		return new MaskedBytes(val, msk);
	}

	/**
	 * Perform a bitwise xor
	 * 
	 * @param that the other operand
	 * @return the result
	 */
	public MaskedBytes xor(MaskedBytes that) {
		final int n = Math.min(this.val.length, that.val.length);
		final int l = Math.max(this.val.length, that.val.length);
		byte[] val = new byte[l];
		byte[] msk = new byte[l];
		for (int i = 0; i < n; i++) {
			msk[i] = (byte) (this.msk[i] & that.msk[i]);
			val[i] = (byte) ((this.val[i] ^ that.val[i]) & msk[i]);
		}
		byte[] v = this.val.length == n ? that.val : this.val;
		byte[] m = this.val.length == n ? that.msk : this.msk;
		for (int i = n; i < l; i++) {
			val[i] = v[i];
			msk[i] = m[i];
		}
		return new MaskedBytes(val, msk);
	}

	/**
	 * Zero out the first bit
	 * <p>
	 * The first bit becomes a known 0 in the result, even if it was unknown.
	 * 
	 * @param endian the endianness of the bytes
	 * @return the result
	 */
	public MaskedBytes floatAbs(Endian endian) {
		final int l = this.val.length;
		int idxMsb = switch (endian) {
			case BIG -> 0;
			case LITTLE -> l - 1;
		};
		if ((this.msk[idxMsb] & 0x80) == 0x80 && (this.val[idxMsb] & 0x80) == 0) {
			return this;
		}
		final byte[] val;
		final byte[] msk;
		if ((this.val[idxMsb] & 0x80) == 0) {
			val = this.val;
		}
		else {
			val = Arrays.copyOf(this.val, l);
			val[idxMsb] &= 0x7f;
		}
		if ((this.msk[idxMsb] & 0x80) == 0x80) {
			msk = this.msk;
		}
		else {
			msk = Arrays.copyOf(this.msk, l);
			msk[idxMsb] |= 0x80;
		}
		return new MaskedBytes(val, msk);
	}

	/**
	 * Invert the first bit, if it is known
	 * 
	 * @param endian the endianness of the bytes
	 * @return the result
	 */
	public MaskedBytes floatNeg(Endian endian) {
		final int l = this.val.length;
		int idxMsb = switch (endian) {
			case BIG -> 0;
			case LITTLE -> l - 1;
		};
		if ((this.msk[idxMsb] & 0x80) == 0) {
			return this;
		}
		final byte[] val = Arrays.copyOf(this.val, l);
		val[idxMsb] ^= 0x80;
		return new MaskedBytes(val, msk);
	}

	private static void copy(MaskedBytes from, int fromOffset, MaskedBytes into, int intoOffset,
			int length) {
		System.arraycopy(from.val, fromOffset, into.val, intoOffset, length);
		System.arraycopy(from.msk, fromOffset, into.msk, intoOffset, length);
	}

	/**
	 * Copy a range of the masked bytes
	 * 
	 * @param start the first byte to include
	 * @param stop the last byte, exclusive
	 * @return the copy
	 */
	public MaskedBytes copyOfRange(int start, int stop) {
		return new MaskedBytes(
			Arrays.copyOfRange(val, start, stop),
			Arrays.copyOfRange(msk, start, stop));
	}

	private MaskedBytes shrink(MaskedBytes into, Endian endian) {
		final int l = into.val.length;
		int off = switch (endian) {
			case BIG -> this.val.length - l;
			case LITTLE -> 0;
		};
		copy(this, off, into, 0, l);
		return into;
	}

	private MaskedBytes grow(MaskedBytes into, byte signVal, byte signMsk, Endian endian) {
		final int lInfo = into.val.length;
		final int lThis = this.val.length;
		int copyOff;
		int slackStart;
		int slackEnd;
		switch (endian) {
			case BIG -> {
				copyOff = lInfo - lThis;
				slackStart = 0;
				slackEnd = copyOff;
			}
			case LITTLE -> {
				copyOff = 0;
				slackStart = lThis;
				slackEnd = lInfo;
			}
			default -> throw new AssertionError();
		}

		copy(this, 0, into, copyOff, lThis);
		for (int i = slackStart; i < slackEnd; i++) {
			into.val[i] = signVal;
			into.msk[i] = signMsk;
		}
		return into;
	}

	private byte sign(byte val) {
		return (byte) (val >> 7);
	}

	/**
	 * Perform sign extension
	 * <p>
	 * The sign bit (known 0, known 1, or unknown) is extended to fill the requested size.
	 * 
	 * @param size the size in bytes of the result
	 * @param endian the endianness of the bytes
	 * @return the extended masked bytes
	 */
	public MaskedBytes sext(int size, Endian endian) {
		if (size == val.length) {
			return this;
		}
		MaskedBytes result = MaskedBytes.ofUnknown(size);
		if (size < val.length) {
			return shrink(result, endian);
		}
		int idxMsb = switch (endian) {
			case BIG -> 0;
			case LITTLE -> val.length - 1;
		};
		return grow(result, sign(val[idxMsb]), sign(msk[idxMsb]), endian);
	}

	/**
	 * Perform zero/unsigned extension
	 * <p>
	 * Known 0s fill to the requested size
	 * 
	 * @param size the size in bytes of the result
	 * @param endian the endianness of the bytes
	 * @return the extended masked bytes
	 */
	public MaskedBytes zext(int size, Endian endian) {
		if (size == val.length) {
			return this;
		}
		MaskedBytes result = MaskedBytes.ofUnknown(size);
		if (size < val.length) {
			return shrink(result, endian);
		}
		return grow(result, (byte) 0, (byte) -1, endian);
	}
}
