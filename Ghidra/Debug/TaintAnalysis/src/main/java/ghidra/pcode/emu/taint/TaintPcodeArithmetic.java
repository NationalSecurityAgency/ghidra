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
package ghidra.pcode.emu.taint;

import java.util.Objects;

import ghidra.pcode.exec.ConcretionError;
import ghidra.pcode.exec.PcodeArithmetic;
import ghidra.program.model.lang.Endian;
import ghidra.program.model.lang.Language;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.taint.model.TaintVec;
import ghidra.taint.model.TaintVec.ShiftMode;

/**
 * The p-code arithmetic on the taint domain
 * 
 * <p>
 * The p-code arithmetic serves as the bridge between p-code and the domain of analysis.
 * Technically, the state itself also contributes minimally to that bridge.
 */
public enum TaintPcodeArithmetic implements PcodeArithmetic<TaintVec> {
	/** The instance for big-endian languages */
	BIG_ENDIAN(Endian.BIG),
	/** The instance for little-endian languages */
	LITTLE_ENDIAN(Endian.LITTLE);

	/**
	 * Get the taint arithmetic for the given endianness
	 * 
	 * <p>
	 * This method is provided since clients of this class may expect it, as they would for any
	 * realization of {@link PcodeArithmetic}.
	 * 
	 * @param bigEndian true for big endian, false for little
	 * @return the arithmetic
	 */
	public static TaintPcodeArithmetic forEndian(boolean bigEndian) {
		return bigEndian ? BIG_ENDIAN : LITTLE_ENDIAN;
	}

	/**
	 * Get the taint arithmetic for the given langauge
	 * 
	 * <p>
	 * This method is provided since clients of this class may expect it, as they would for any
	 * realization of {@link PcodeArithmetic}.
	 * 
	 * @param language the langauge
	 * @return the arithmetic
	 */
	public static TaintPcodeArithmetic forLanguage(Language language) {
		return forEndian(language.isBigEndian());
	}

	private final Endian endian;

	private TaintPcodeArithmetic(Endian endian) {
		this.endian = endian;
	}

	@Override
	public Endian getEndian() {
		return endian;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * We can't just naively return {@code in1}, because each unary op may mix the bytes of the
	 * operand a little differently. For {@link PcodeOp#COPY}, we can, since no mixing happens at
	 * all. This is also the case of both {@link NEGATE} operations ("negate" is a bit of a
	 * misnomer, as they merely inverts the bits.) For {@link PcodeOp#INT_ZEXT}, we append empties
	 * to the correct end of the vector. Similarly, we replicate the most-significant element and
	 * append for {@link PcodeOp#INT_SEXT}. For {@link PcodeOp#INT_2COMP} (which negates an integer
	 * in 2's complement), we have to consider that the "add one" step may cause a cascade of
	 * carries. All others, we assume every byte could be tainted by any other byte in the vector,
	 * so we union and broadcast.
	 */
	@Override
	public TaintVec unaryOp(int opcode, int sizeout, int sizein1, TaintVec in1) {
		switch (opcode) {
			case PcodeOp.COPY:
			case PcodeOp.BOOL_NEGATE:
			case PcodeOp.INT_NEGATE:
				return in1;
			case PcodeOp.INT_ZEXT:
				return in1.extended(sizeout, endian.isBigEndian(), false);
			case PcodeOp.INT_SEXT:
				return in1.extended(sizeout, endian.isBigEndian(), true);
			case PcodeOp.INT_2COMP:
				return in1.copy().setCascade(endian.isBigEndian());
			default:
				return TaintVec.copies(in1.union(), sizeout);
		}
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * We override the form taking the full p-code op, so that we can treat certain idioms. Notably,
	 * on x86, {@code XOR RAX,RAX} is a common optimization of {@code MOV RAX,0}, since it takes
	 * fewer bytes to encode. Thus, we must examine the input variables, not their values, to detect
	 * this. Note that, while less common, {@code SUB RAX,RAX} would accomplish the same.
	 * Additionally, in p-code {@link PcodeOp#INT_XOR} is identical to {@link PcodeOp#BOOL_XOR}.
	 * When we detect these idioms, we want to clear any taints, since the value output is constant.
	 * This is achieved intuitively, by deferring to {@link #fromConst(long, int)}, passing in 0 and
	 * the output size.
	 */
	@Override
	public TaintVec binaryOp(PcodeOp op, TaintVec in1, TaintVec in2) {
		// TODO: Detect immediate operands and be more precise
		switch (op.getOpcode()) {
			case PcodeOp.INT_XOR:
			case PcodeOp.INT_SUB:
			case PcodeOp.BOOL_XOR:
				if (Objects.equals(op.getInput(0), op.getInput(1))) {
					return fromConst(0, op.getOutput().getSize());
				}
			default:
		}
		return PcodeArithmetic.super.binaryOp(op, in1, in2);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * For bitwise operations, we pair-wise union corresponding elements of the two input taint
	 * vectors. For integer add and subtract, we do the same, but account for the carry bits
	 * possibly cascading into bytes of higher significance. For {@link PcodeOp#PIECE}, we perform
	 * the analog as on concrete state, since the operand sizes are constant. For all others, we
	 * must consider that every output byte is potentially affected by any or all bytes of both
	 * input operands. Thus, we union and broadcast.
	 */
	@Override
	public TaintVec binaryOp(int opcode, int sizeout, int sizein1, TaintVec in1,
			int sizein2, TaintVec in2) {
		switch (opcode) {
			case PcodeOp.BOOL_AND:
			case PcodeOp.BOOL_OR:
			case PcodeOp.BOOL_XOR:
			case PcodeOp.INT_AND:
			case PcodeOp.INT_OR:
			case PcodeOp.INT_XOR:
				return in1.zipUnion(in2);
			case PcodeOp.INT_ADD:
			case PcodeOp.INT_SUB: {
				TaintVec temp = in1.zipUnion(in2);
				return temp.setCascade(endian.isBigEndian());
			}
			case PcodeOp.PIECE: {
				TaintVec temp = in1.extended(sizeout, endian.isBigEndian(), false);
				temp.setShifted(endian.isBigEndian() ? -sizein2 : sizein2, ShiftMode.UNBOUNDED);
				return temp.set(endian.isBigEndian() ? sizeout - sizein2 : 0, in2);
			}
			default: {
				TaintVec temp = in1.zipUnion(in2);
				return temp.setCopies(temp.union());
			}
		}
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * Here we handle indirect taint for indirect writes
	 */
	@Override
	public TaintVec modBeforeStore(int sizeout, int sizeinAddress, TaintVec inAddress,
			int sizeinValue, TaintVec inValue) {
		return inValue.tagIndirectWrite(inAddress);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * Here we handle indirect taint for indirect reads
	 */
	@Override
	public TaintVec modAfterLoad(int sizeout, int sizeinAddress, TaintVec inAddress,
			int sizeinValue, TaintVec inValue) {
		return inValue.tagIndirectRead(inAddress);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * Constant values have no taint, so we just return a vector of empty taint sets
	 */
	@Override
	public TaintVec fromConst(byte[] value) {
		return TaintVec.empties(value.length);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * Taint vectors have no values. We're expect the taint arithmetic to be used as an auxiliary to
	 * concrete bytes, so the paired arithmetic should always defer to its concrete element. Thus,
	 * an {@link AssertionError} might also be fitting here, but we'll stick to convention, since
	 * technically a user script could attempt to concretize taint.
	 */
	@Override
	public byte[] toConcrete(TaintVec value, Purpose purpose) {
		throw new ConcretionError("Cannot make taint concrete", purpose);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * Taint vectors do have length, so return it here.
	 */
	@Override
	public long sizeOf(TaintVec value) {
		return value.length;
	}
}
