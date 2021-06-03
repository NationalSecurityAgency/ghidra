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
package ghidra.app.plugin.assembler.sleigh.sem;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Iterator;
import java.util.concurrent.atomic.AtomicLong;

import ghidra.app.plugin.assembler.sleigh.expr.MaskedLong;
import ghidra.app.plugin.assembler.sleigh.expr.SolverException;
import ghidra.app.plugin.assembler.sleigh.util.SleighUtil;
import ghidra.app.plugin.processors.sleigh.ContextOp;
import ghidra.app.plugin.processors.sleigh.expression.ContextField;
import ghidra.app.plugin.processors.sleigh.expression.TokenField;
import ghidra.app.plugin.processors.sleigh.pattern.DisjointPattern;
import ghidra.app.plugin.processors.sleigh.pattern.PatternBlock;
import ghidra.program.model.lang.RegisterValue;
import ghidra.util.NumericUtilities;
import ghidra.util.StringUtilities;

/**
 * The analog of {@link PatternBlock}, designed for use by the assembler
 * 
 * It is suitable for the assembler because it is represented byte-by-byte, and it offers a number
 * of useful conversions and operations.
 * 
 * TODO A lot of this could probably be factored into the {@link PatternBlock} class, but it was
 * best to experiment in another class altogether to avoid breaking things.
 */
public class AssemblyPatternBlock implements Comparable<AssemblyPatternBlock> {
	protected static final String SHIFT_STR = "SS:";
	protected static final String SHIFT_STR_END = "SS";

	private final int offset; // offset relative to the start of the instruction

	private final byte[] mask;
	private final byte[] vals;

	/**
	 * Construct a new pattern block with the given mask, values, and offset
	 * @param offset an offset (0-up, left-to-right) where the pattern actually starts
	 * @param mask a mask: only {@code 1} bits are included in the pattern
	 * @param vals the value, excluding corresponding {@code 0} bits in the mask
	 */
	protected AssemblyPatternBlock(int offset, byte[] mask, byte[] vals) {
		assert mask.length == vals.length;
		this.offset = offset;
		this.mask = mask;
		this.vals = vals;
	}

	/**
	 * Construct a new empty pattern block at the given offset, prepared with the given capacity
	 * @param offset an offset (0-up, left-to-right) where the pattern will start
	 * @param capacity the space to allocate for the mask and values
	 */
	protected AssemblyPatternBlock(int offset, int capacity) {
		this.offset = offset;
		mask = new byte[capacity];
		vals = new byte[capacity];
	}

	/**
	 * Get an empty pattern block
	 * @return the pattern block
	 */
	public static AssemblyPatternBlock nop() {
		return new AssemblyPatternBlock(0, 0);
	}

	/**
	 * Get a pattern block with the given (fully-included) values at the given offset
	 * @param offset the offset (0-up, left-to-right)
	 * @param vals the values
	 * @return a pattern block (having a full mask)
	 */
	public static AssemblyPatternBlock fromBytes(int offset, byte[] vals) {
		byte[] mask = new byte[vals.length];
		for (int i = 0; i < mask.length; i++) {
			mask[i] = -1;
		}
		AssemblyPatternBlock res = new AssemblyPatternBlock(offset, mask, vals);
		return res;
	}

	/**
	 * Convert the given long to a pattern block (having offset 0 and a full mask)
	 * NOTE: The result will be 8 bytes in length
	 * @param value the value to convert
	 * @return the pattern block containing the big-endian representation of the value
	 */
	public static AssemblyPatternBlock fromLong(long value) {
		byte[] mask = new byte[8];
		byte[] vals = new byte[8];
		for (int i = vals.length; i >= 0; i--) {
			mask[i] = -1;
			vals[i] = (byte) (value & 0xff);
			value >>= 8;
		}
		AssemblyPatternBlock res = new AssemblyPatternBlock(0, mask, vals);
		return res;
	}

	/**
	 * Convert the given masked long to a pattern block (having offset 0)
	 * NOTE: The result will be 8 bytes in length
	 * @param ml the masked long, whose values and mask to convert
	 * @return the pattern block containing the big-endian representation of the value
	 */
	public static AssemblyPatternBlock fromMaskedLong(MaskedLong ml) {
		byte[] mask = new byte[8];
		byte[] vals = new byte[8];
		long lmask = ml.getMask();
		long value = ml.longValue();
		for (int i = vals.length; i >= 0; i--) {
			mask[i] = (byte) (lmask & 0xff);
			vals[i] = (byte) (value & 0xff);
			lmask >>= 8;
			value >>= 8;
		}
		AssemblyPatternBlock res = new AssemblyPatternBlock(0, mask, vals);
		return res;
	}

	/**
	 * Convert a string representation to a pattern block
	 * @see NumericUtilities#convertHexStringToMaskedValue(AtomicLong, AtomicLong, String, int, int, String)
	 * @param str the string to convert
	 * @return the resulting pattern block
	 */
	public static AssemblyPatternBlock fromString(String str) {
		if ("[]".equals(str)) {
			return new AssemblyPatternBlock(0, new byte[0], new byte[0]);
		}
		int pos = 0;
		int offset = 0;
		// Compute the offset, byte consuming SS:
		while (str.regionMatches(pos, SHIFT_STR, 0, SHIFT_STR.length())) {
			pos += SHIFT_STR.length();
			offset++;
		}
		if (str.regionMatches(pos, SHIFT_STR_END, 0, SHIFT_STR_END.length())) {
			return new AssemblyPatternBlock(offset, new byte[0], new byte[0]);
		}

		// Compute the length by counting the colons
		int length = 1;
		for (int p = pos; p < str.length();) {
			int newpos = str.indexOf(':', p);
			if (newpos == -1) {
				break;
			}
			length++;
			p = newpos + 1;
		}

		// Convert the bytes
		// TODO: Optimize this some
		byte[] mask = new byte[length];
		byte[] vals = new byte[length];
		AtomicLong msk = new AtomicLong();
		AtomicLong val = new AtomicLong();
		int i = 0;
		for (String hex : str.split(":")) {
			NumericUtilities.convertHexStringToMaskedValue(msk, val, hex, 2, 0, null);
			mask[i] = (byte) msk.get();
			vals[i] = (byte) val.get();
			i++;
		}

		return new AssemblyPatternBlock(offset, mask, vals);
	}

	/**
	 * Convert a block from a disjoint pattern into an assembly pattern block 
	 * @param pat the pattern to convert
	 * @param context true to select the context block, false to select the instruction block
	 * @return the converted pattern block
	 */
	public static AssemblyPatternBlock fromPattern(DisjointPattern pat, int minLen,
			boolean context) {
		PatternBlock block = pat.getBlock(context);
		if (block == null || block.alwaysTrue()) {
			return new AssemblyPatternBlock(0, minLen);
		}
		if (block.alwaysFalse()) {
			return null;
		}
		int offset = block.getOffset();
		int nzlen = Math.max(block.getLength(), minLen) - offset;

		int[] vec = block.getMaskVector();
		ByteBuffer buf = ByteBuffer.allocate(vec.length * 4);
		int datlen = Math.min(nzlen, buf.capacity());

		for (int i = 0; i < vec.length; i++) {
			buf.putInt(i * 4, vec[i]);
		}
		byte[] mask = new byte[nzlen];
		for (int i = 0; i < datlen; i++) {
			mask[i] = buf.get(i);
		}

		vec = block.getValueVector();
		for (int i = 0; i < vec.length; i++) {
			buf.putInt(i * 4, vec[i]);
		}
		byte[] vals = new byte[nzlen];
		for (int i = 0; i < datlen; i++) {
			vals[i] = buf.get(i);
		}
		return new AssemblyPatternBlock(offset, mask, vals);
	}

	/**
	 * Encode the given masked long into a pattern block as specified by a given token field
	 * @param tf the token field specifying the location of the value to encode
	 * @param val the value to encode
	 * @return the pattern block with the encoded value
	 */
	public static AssemblyPatternBlock fromTokenField(TokenField tf, MaskedLong val) {
		int size = tf.getByteEnd() - tf.getByteStart() + 1;

		val = val.mask(tf.maxValue());
		try {
			val = val.invShiftRightLogical(tf.getShift());
		}
		catch (SolverException e) {
			throw new AssertionError(e);
		}
		if (!tf.isBigEndian()) {
			val = val.byteSwap(size);
		}

		byte[] mask = new byte[size];
		byte[] vals = new byte[size];
		long lmsk = val.getMask();
		long lval = val.longValue();
		for (int i = size - 1; i >= 0; i--) {
			mask[i] = (byte) (lmsk & 0xff);
			vals[i] = (byte) (lval & 0xff);
			lmsk >>= 8;
			lval >>= 8;
		}
		return new AssemblyPatternBlock(tf.getByteStart(), mask, vals);
	}

	/**
	 * Encode the given masked long into a pattern block as specified by a given context field
	 * @param cf the context field specifying the location of the value to encode
	 * @param val the value to encode
	 * @return the pattern block with the encoded value
	 */
	public static AssemblyPatternBlock fromContextField(ContextField cf, MaskedLong val) {
		int size = cf.getByteEnd() - cf.getByteStart() + 1;

		val = val.mask(cf.maxValue());
		try {
			val = val.invShiftRightLogical(cf.getShift());
		}
		catch (SolverException e) {
			throw new AssertionError(e);
		}
		// Context does not have variable endianness

		byte[] mask = new byte[size];
		byte[] vals = new byte[size];
		long lmsk = val.getMask();
		long lval = val.longValue();
		for (int i = size - 1; i >= 0; i--) {
			mask[i] = (byte) (lmsk & 0xff);
			vals[i] = (byte) (lval & 0xff);
			lmsk >>= 8;
			lval >>= 8;
		}
		return new AssemblyPatternBlock(cf.getByteStart(), mask, vals);
	}

	/**
	 * Convert a register value into a pattern block
	 * @param rv the register value
	 * @return the pattern block
	 * 
	 * This is used primarily to compute default context register values, and pass them into an
	 * assembler.
	 */
	public static AssemblyPatternBlock fromRegisterValue(RegisterValue rv) {
		byte[] mb = rv.toBytes();
		byte[] mask = new byte[mb.length / 2];
		byte[] vals = new byte[mb.length / 2];
		System.arraycopy(mb, 0, mask, 0, mb.length / 2);
		System.arraycopy(mb, mb.length / 2, vals, 0, mb.length / 2);
		return new AssemblyPatternBlock(0, mask, vals);
	}

	/**
	 * Allocate a fully-undefined pattern block of the given length
	 * @param length the length in bytes
	 * @return the block of all unknown bits
	 */
	public static AssemblyPatternBlock fromLength(int length) {
		byte[] mask = new byte[length];
		byte[] vals = new byte[length];
		return new AssemblyPatternBlock(0, mask, vals);
	}

	/**
	 * Duplicate this pattern block
	 * @return the duplicate
	 */
	public AssemblyPatternBlock copy() {
		return new AssemblyPatternBlock(offset, Arrays.copyOf(mask, mask.length),
			Arrays.copyOf(vals, vals.length));
	}

	/**
	 * Get the length (plus the offset) of this pattern block
	 * @return the total length
	 */
	public int length() {
		return offset + mask.length;
	}

	/**
	 * Shift, i.e., increase the offset of, this pattern block
	 * @param amt the amount to shift right
	 * @return the shifted pattern block
	 */
	public AssemblyPatternBlock shift(int amt) {
		if (amt == 0) {
			return this;
		}
		return new AssemblyPatternBlock(this.offset + amt, mask, vals);
	}

	/**
	 * Truncate (unshift) this pattern block by removing bytes from the left
	 * @param amt the amount to truncate or shift left
	 * @return the truncated pattern block
	 */
	public AssemblyPatternBlock truncate(int amt) {
		if (amt == 0) {
			return this;
		}
		if (offset >= amt) {
			return new AssemblyPatternBlock(this.offset - amt, mask, vals);
		}
		int toCut = amt - offset;
		// This circumstance seems unsettling, but I think it's correct
		if (toCut >= this.mask.length) {
			return AssemblyPatternBlock.nop();
		}
		byte[] newMask = Arrays.copyOfRange(this.mask, toCut, this.mask.length);
		byte[] newVals = Arrays.copyOfRange(this.vals, toCut, this.vals.length);
		return new AssemblyPatternBlock(0, newMask, newVals);
	}

	/**
	 * Combine this pattern block with another given block
	 * 
	 * Two blocks can be combined in their corresponding defined bits agree. When blocks are
	 * combined, their bytes are aligned according to their shifts, and the defined bits are taken
	 * from either block. If neither block defines a bit (i.e., the mask bit at that position is
	 * {@code 0} for both input blocks, then the output has an undefined bit in the corresponding
	 * position. If both blocks define the bit, but they have opposite values, then the result is
	 * an error.
	 * @param that the other block
	 * @return the new combined block, or null if the blocks disagree for any bit
	 */
	public AssemblyPatternBlock combine(AssemblyPatternBlock that) {
		int newOffset = Math.min(this.offset, that.offset);
		int buflen = Math.max(this.length(), that.length()) - newOffset;
		byte[] cmsk = new byte[buflen]; // To check for conflicts;

		int diff = this.offset - newOffset;
		for (int i = 0; i < this.mask.length; i++) {
			cmsk[diff + i] = this.mask[i];
		}
		diff = that.offset - newOffset;
		for (int i = 0; i < that.mask.length; i++) {
			cmsk[diff + i] &= that.mask[i];
		}
		byte[] chek = new byte[buflen];
		diff = this.offset - newOffset;
		for (int i = 0; i < this.vals.length; i++) {
			chek[diff + i] = (byte) (cmsk[diff + i] & this.vals[i]);
		}
		diff = that.offset - newOffset;
		for (int i = 0; i < that.vals.length; i++) {
			if (chek[diff + i] != (byte) (cmsk[diff + i] & that.vals[i])) {
				return null;
			}
		}

		byte[] newMask = new byte[buflen];
		byte[] newVals = new byte[buflen];

		diff = this.offset - newOffset;
		for (int i = 0; i < this.mask.length; i++) {
			newMask[diff + i] = this.mask[i];
			newVals[diff + i] = this.vals[i];
		}
		diff = that.offset - newOffset;
		for (int i = 0; i < that.mask.length; i++) {
			newMask[diff + i] |= that.mask[i];
			newVals[diff + i] |= that.vals[i];
		}

		return new AssemblyPatternBlock(newOffset, newMask, newVals);
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < offset; i++) {
			sb.append(SHIFT_STR);
		}
		if (mask.length == 0) {
			if (sb.length() == 0) {
				return "[]";
			}
			return sb.substring(0, sb.length() - 1);
		}
		for (int i = 0; i < mask.length; i++) {
			if (i != 0) {
				sb.append(':');
			}
			sb.append(NumericUtilities.convertMaskedValueToHexString(mask[i], vals[i], 2, false, 0,
				null));
		}
		return sb.toString();
	}

	@Override
	public int hashCode() {
		int result = offset;
		for (int i = 0; i < mask.length; i++) {
			result *= 31;
			result += mask[i];
			result *= 31;
			result += vals[i];
		}
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof AssemblyPatternBlock)) {
			return false;
		}
		AssemblyPatternBlock that = (AssemblyPatternBlock) obj;
		int ckOffset = Math.min(this.offset, that.offset);
		int length = Math.max(this.length(), that.length());
		for (int i = ckOffset; i < length; i++) {
			if (checkRead(this.mask, i - this.offset, 0) != checkRead(that.mask, i - that.offset,
				0)) {
				return false;
			}
			if (checkRead(this.vals, i - this.offset, 0) != checkRead(that.vals, i - that.offset,
				0)) {
				return false;
			}
		}
		return true;
	}

	@Override
	public int compareTo(AssemblyPatternBlock that) {
		int result;
		result = this.offset - that.offset;
		if (result != 0) {
			return result;
		}

		result = SleighUtil.compareArrays(this.mask, that.mask);
		if (result != 0) {
			return result;
		}

		result = SleighUtil.compareArrays(this.vals, that.vals);
		if (result != 0) {
			return result;
		}
		return 0;
	}

	/**
	 * Read an array, returning a default if the index is out of bounds
	 * @param arr the array to read
	 * @param idx the index
	 * @param def the default value
	 * @return the read value
	 */
	protected static int checkRead(byte[] arr, int idx, int def) {
		// When there's an offset, idx can be < 0
		if (idx >= arr.length || idx < 0) {
			return 0xff & def;
		}
		return 0xff & arr[idx];
	}

	/**
	 * Encode the given value into a copy of this pattern block as specified by a context operation
	 * 
	 * NOTE: this method is given as a special operation, instead of a conversion factory method,
	 * because this is a write operation, not a combine operation. As such, the bits (including
	 * undefined bits) replace the bits in the existing pattern block. Were this a conversion
	 * method, we would lose the distinction between unknown bits being written, and bits whose
	 * values are simply not included in the write.
	 * 
	 * @param cop the context operation specifying the location of the value to encode
	 * @param val the value to encode
	 * @return the new copy with the encoded value
	 */
	public AssemblyPatternBlock writeContextOp(ContextOp cop, MaskedLong val) {
		// Do not consider compatibility (like in combine). Just overwrite.
		// This includes overwriting knowns with unknowns.

		// Take out of object early to reduce garbage.
		long vval = val.longValue();
		long vmsk = val.getMask();
		long cmsk = cop.getMask() & 0xffffffffL;

		vval <<= cop.getShift();
		vmsk <<= cop.getShift();
		vval &= cmsk;
		vmsk &= cmsk;

		int idx = cop.getWordIndex();

		int newOffset = Math.min(idx * 4, this.offset);
		int length = Math.max(idx * 4 + 4, this.length());

		byte[] newMask = new byte[length - newOffset];
		byte[] newVals = new byte[length - newOffset];
		System.arraycopy(this.mask, 0, newMask, this.offset - newOffset, this.mask.length);
		System.arraycopy(this.vals, 0, newVals, this.offset - newOffset, this.vals.length);

		for (int i = 3; i >= 0; i--) {
			newMask[idx * 4 + i] &= ~cmsk & 0xff;
			newMask[idx * 4 + i] |= vmsk & 0xff;
			newVals[idx * 4 + i] &= ~cmsk & 0xff;
			newVals[idx * 4 + i] |= vval & 0xff;
			vval >>= 8;
			vmsk >>= 8;
			cmsk >>= 8;
		}
		return new AssemblyPatternBlock(newOffset, newMask, newVals);
	}

	/**
	 * Read the input of a context operation from this pattern block
	 * @param cop the context operation
	 * @return the decoded input, as a masked value
	 */
	public MaskedLong readContextOp(ContextOp cop) {
		// Pull defined bits from the pattern block that also fall within the "mask" of the op.
		// It bothers me, this int => long conversion. Can a context operation not read more
		// than 32 bits?
		int idx = cop.getWordIndex();
		long cmsk = cop.getMask() & 0xffffffffL;
		long lmsk = 0;
		for (int i = 0; i < 4; i++) {
			lmsk <<= 8;
			lmsk |= checkRead(mask, idx * 4 + i - offset, 0);
		}
		long rmsk = lmsk & cmsk; // resulting mask
		if (rmsk == 0) {
			return MaskedLong.UNKS;
		}

		long rval = 0; // resulting value
		for (int i = 0; i < 4; i++) {
			rval <<= 8;
			rval |= checkRead(vals, idx * 4 + i - offset, 0);
		}
		// Shift the two separately to spare an object instantiation.
		return MaskedLong.fromMaskAndValue(rmsk >>> cop.getShift(), rval >>> cop.getShift());
	}

	/**
	 * Set all bits read by a given context operation to unknown
	 * @param cop the context operation
	 * @return the result
	 * 
	 * This is used during resolution to remove a context requirement passed upward by a child.
	 * When a parent constructor writes the required value to the context register, that
	 * requirement need not be passed further upward, since the write satisfies the requirement.
	 */
	public AssemblyPatternBlock maskOut(ContextOp cop) {
		byte[] newMask = Arrays.copyOf(this.mask, this.mask.length);
		byte[] newVals = Arrays.copyOf(this.vals, this.vals.length);
		int idx = cop.getWordIndex();
		int imsk = cop.getMask();
		for (int i = 3; i >= 0; i--) {
			byte bmsk = (byte) ~(imsk & 0xff); // Inverse: Getting ready to unset
			int index = idx * 4 + i - offset;
			// feels a little hacky, but if non-existent is assumed zero,
			// this should be fine
			if (index < newMask.length && index >= 0) {
				newMask[index] &= bmsk;
				newVals[index] &= bmsk; // for good measure
			}
			imsk >>= 8;
		}
		return new AssemblyPatternBlock(offset, newMask, newVals);
	}

	/**
	 * Get the values array
	 * @return the array
	 */
	public byte[] getVals() {
		return vals;
	}

	/**
	 * Get the mask array
	 * @return the array
	 */
	public byte[] getMask() {
		return mask;
	}

	/**
	 * Get the number of undefined bytes preceding the mask and values arrays
	 * @return the offset
	 */
	public int getOffset() {
		return offset;
	}

	/**
	 * Decode {@code} len value bytes in big-endian format, beginning at {@code start}
	 * @param start the first byte to decode
	 * @param len the number of bytes to decode
	 * @return the decoded long
	 */
	public long readValBytes(int start, int len) {
		long res = 0;
		for (int i = 0; i < len; i++) {
			res <<= 8;
			int index = start + i - offset;
			if (0 <= index && index < vals.length) {
				res |= 0xff & vals[index];
			}
		}
		return res;
	}

	/**
	 * Decode {@code} len mask bytes in big-endian format, beginning at {@code start}
	 * @param start the first byte to decode
	 * @param len the number of bytes to decode
	 * @return the decoded long
	 */
	public long readMaskBytes(int start, int len) {
		long res = 0;
		for (int i = 0; i < len; i++) {
			res <<= 8;
			int index = start + i - offset;
			if (0 <= index && index < mask.length) {
				res |= 0xff & mask[index];
			}
		}
		return res;
	}

	/**
	 * Decode {@code} len bytes (values and mask) in big-endian format, beginning at {@code start}
	 * @param start the first byte to decode
	 * @param len the number of bytes to decode
	 * @return the decoded masked long
	 */
	public MaskedLong readBytes(int start, int len) {
		return MaskedLong.fromMaskAndValue(readMaskBytes(start, len), readValBytes(start, len));
	}

	/**
	 * Fill all unknown bits with {@code 0} bits 
	 * @return the result
	 */
	public AssemblyPatternBlock fillMask() {
		byte[] newMask = new byte[this.mask.length];
		for (int i = 0; i < newMask.length; i++) {
			newMask[i] = (byte) 0xff;
		}
		return new AssemblyPatternBlock(offset, newMask, vals);
	}

	/**
	 * Check if there are any unknown bits
	 * @return true if no unknown bits are present, false otherwise
	 */
	public boolean isFullMask() {
		if (offset != 0) {
			return false;
		}
		for (byte element : mask) {
			if (element != (byte) 0xff) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Check if all bits are {@code 0} bits
	 * @return true if all are {@code 0}, false otherwise
	 */
	public boolean isZero() {
		if (!isFullMask()) {
			return false;
		}
		for (byte val : vals) {
			if (val != 0) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Decode the values array into a {@link BigInteger} of length {@code n} bytes
	 * 
	 * The array is either truncated or zero-extended <em>on the right</em> to match the requested
	 * number of bytes, then decoded in big-endian format as an unsigned value.
	 * @param n the number of bytes (left-to-right) to decode
	 * @return the decoded big integer
	 */
	public BigInteger toBigInteger(int n) {
		BigInteger res = new BigInteger(1, vals);
		if (n < length()) {
			res = res.shiftRight((length() - n) * 8);
		}
		else {
			res = res.shiftLeft((n - length()) * 8);
		}
		return res;
	}

	/**
	 * Counts the total number of known bits in the pattern
	 * 
	 * At a slightly lower level, counts the number of 1-bits in the mask.
	 * @return the count
	 */
	public int getSpecificity() {
		int result = 0;
		for (byte element : mask) {
			result += Integer.bitCount(0xff & element);
		}
		return result;
	}

	public int countPossibleVals() {
		int count0 = 0;
		for (byte element : mask) {
			byte m = element;
			for (int j = 0; j < 8; j++) {
				if ((m & 0x80) == 0) {
					count0++;
				}
				m <<= 1;
			}
		}
		return 1 << count0;
	}

	/**
	 * Get an iterable over all the possible fillings of the value, given a partial mask
	 * 
	 * This is meant to be used idiomatically, as in an enhanced for loop:
	 * 
	 * <pre>
	 * {@code
	 * for (byte[] val : pattern.possibleVals()) {
	 *     System.out.println(format(val));
	 * }
	 * }
	 * </pre>
	 * 
	 * NOTE: A single byte array is instantiated with the call to {@link Iterable#iterator()}. Each
	 * call to {@link Iterator#next()} modifies the one byte array and returns it. As such, if you
	 * intend to preserve the value in the array for later use, you <em>must</em> make a copy.
	 * @return the iterable.
	 */
	public Iterable<byte[]> possibleVals() {
		return () -> {
			byte[] cur = new byte[vals.length];
			System.arraycopy(vals, 0, cur, 0, vals.length);
			final int max = countPossibleVals();
			return new Iterator<byte[]>() {
				int c = 0;

				@Override
				public boolean hasNext() {
					return c < max;
				}

				@Override
				public byte[] next() {
					int cm = max >> 1;
					for (int i = 0; i < mask.length; i++) {
						byte m = mask[i];
						for (int j = 0; j < 8; j++) {
							if ((m & 0x80) == 0) {
								byte b = (byte) (0x80 >> j);
								if ((c & cm) == 0) {
									cur[i] &= ~b;
								}
								else {
									cur[i] |= b;
								}
								cm >>= 1;
							}
							m <<= 1;
						}
					}
					c++;
					return cur;
				}
			};
		};
	}
}
