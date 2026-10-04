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

import ghidra.pcode.exec.*;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Endian;
import ghidra.program.model.lang.Language;
import ghidra.program.model.pcode.PcodeOp;

/**
 * The arithmetic for computing folded constants
 * <p>
 * For the most part, the result of any operation is only known if all inputs are known. In that
 * case, the result is equivalent to applying {@link BytesPcodeArithmetic}. Otherwise, the result is
 * completely unknown. Special treatment is given to bitwise boolean operators, extension operators,
 * and shift operators. We also give some special treatment for operators that only modify the sign
 * bit, e.g., {@link PcodeOp#FLOAT_ABS}.
 */
public enum FoldedArithmetic implements PcodeArithmetic<MaskedBytes> {
	/** The big-endian instance */
	BE(Endian.BIG),
	/** The little-endian instance */
	LE(Endian.LITTLE);

	/**
	 * {@return the instance for the given endian}
	 * 
	 * @param endian the endian
	 */
	public static FoldedArithmetic forEndian(Endian endian) {
		return switch (endian) {
			case BIG -> BE;
			case LITTLE -> LE;
		};
	}

	/**
	 * {@return the instance for the given language}
	 * 
	 * @param language the language
	 */
	public static FoldedArithmetic forLanguage(Language language) {
		return language.isBigEndian() ? BE : LE;
	}

	private final Endian endian;
	private final BytesPcodeArithmetic bytes;

	FoldedArithmetic(Endian endian) {
		this.endian = endian;
		this.bytes = BytesPcodeArithmetic.forEndian(endian.isBigEndian());
	}

	@Override
	public Class<MaskedBytes> getDomain() {
		return MaskedBytes.class;
	}

	@Override
	public Endian getEndian() {
		return endian;
	}

	MaskedBytes unaryAllOrTop(int opcode, int sizeout, int sizein1, MaskedBytes in1) {
		byte[] value1 = concreteOrNull(in1);
		if (value1 == null) {
			return MaskedBytes.ofUnknown(sizeout);
		}
		byte[] out = bytes.unaryOp(opcode, sizeout, sizein1, value1);
		return MaskedBytes.ofKnown(out);
	}

	@Override
	public MaskedBytes unaryOp(int opcode, int sizeout, int sizein1, MaskedBytes in1) {
		// 2COMP, ADD, SUB (in case higher bits are TOP)?
		// LZCOUNT (in case a high 1 appears, can disregard lower TOP)?
		return switch (opcode) {
			case PcodeOp.COPY -> in1;
			case PcodeOp.BOOL_NEGATE, PcodeOp.INT_NEGATE -> in1.negate();
			case PcodeOp.FLOAT_ABS -> in1.floatAbs(endian);
			case PcodeOp.FLOAT_NEG -> in1.floatNeg(endian);
			case PcodeOp.INT_SEXT -> in1.sext(sizeout, endian);
			case PcodeOp.INT_ZEXT -> in1.zext(sizeout, endian);
			default -> unaryAllOrTop(opcode, sizeout, sizein1, in1);
		};
	}

	MaskedBytes left(MaskedBytes value, MaskedBytes shift) {
		byte[] shiftC = concreteOrNull(shift);
		if (shiftC == null) {
			return MaskedBytes.ofUnknown(value.val.length);
		}
		int s = (int) bytes.toLong(shiftC, Purpose.OTHER);
		BigInteger m = value.bigMask(endian)
				.shiftLeft(s)
				.or(BigInteger.ONE.shiftLeft(s).subtract(BigInteger.ONE));
		BigInteger v = value.bigValue(endian).shiftLeft(s);
		return MaskedBytes.of(v, m, value.val.length, endian);
	}

	MaskedBytes right(MaskedBytes value, MaskedBytes shift) {
		byte[] shiftC = concreteOrNull(shift);
		if (shiftC == null) {
			return MaskedBytes.ofUnknown(value.val.length);
		}
		int s = (int) bytes.toLong(shiftC, Purpose.OTHER);
		BigInteger m = value.bigMask(endian)
				.shiftRight(s)
				.or(BigInteger.ONE.shiftLeft(s)
						.subtract(BigInteger.ONE)
						.shiftLeft(value.val.length * 8 - s));
		BigInteger v = value.bigValue(endian).shiftRight(s);
		return MaskedBytes.of(v, m, value.val.length, endian);
	}

	MaskedBytes sright(MaskedBytes value, MaskedBytes shift) {
		byte[] shiftC = concreteOrNull(shift);
		if (shiftC == null) {
			return MaskedBytes.ofUnknown(value.val.length);
		}
		int s = (int) bytes.toLong(shiftC, Purpose.OTHER);
		BigInteger m = value.bigMaskSigned(endian) // Let the mask's sign bit be extended
				.shiftRight(s);
		BigInteger v = value.bigValueSigned(endian) // Let the sign bit be extended
				.shiftRight(s);
		return MaskedBytes.of(v, m, value.val.length, endian);
	}

	MaskedBytes subpiece(MaskedBytes value, MaskedBytes offset, int sizeout) {
		byte[] offsetC = concreteOrNull(offset);
		if (offsetC == null) {
			// Should this be an assertion failure instead?
			return MaskedBytes.ofUnknown(value.val.length);
		}
		int off = (int) bytes.toLong(offsetC, Purpose.OTHER);
		BigInteger trunc = BigInteger.ONE.shiftLeft(sizeout * 8).subtract(BigInteger.ONE);
		int over = sizeout - value.val.length + off;
		BigInteger fill = over > 0
				? BigInteger.ONE.shiftLeft(over * 8)
						.subtract(BigInteger.ONE)
						.shiftLeft((value.val.length - off) * 8)
				: BigInteger.ZERO;

		BigInteger m = value.bigMask(endian)
				.shiftRight(off * 8)
				.or(fill)
				.and(trunc);
		BigInteger v = value.bigValue(endian)
				.shiftRight(off * 8);
		return MaskedBytes.of(v, m, sizeout, endian);
	}

	MaskedBytes binaryAllOrTop(int opcode, int sizeout, int sizein1, MaskedBytes in1,
			int sizein2, MaskedBytes in2) {
		byte[] value1 = concreteOrNull(in1);
		if (value1 == null) {
			return MaskedBytes.ofUnknown(sizeout);
		}
		byte[] value2 = concreteOrNull(in2);
		if (value2 == null) {
			return MaskedBytes.ofUnknown(sizeout);
		}
		byte[] out = bytes.binaryOp(opcode, sizeout, sizein1, value1, sizein2, value2);
		return MaskedBytes.ofKnown(out);
	}

	@Override
	public MaskedBytes binaryOp(int opcode, int sizeout, int sizein1, MaskedBytes in1,
			int sizein2, MaskedBytes in2) {
		// EQUAL, NOTEQUAL, because any known disagreement?
		// SLESS,LESS(EQUAL), because can short circuit at high bits?
		return switch (opcode) {
			case PcodeOp.BOOL_AND, PcodeOp.INT_AND -> in1.and(in2);
			case PcodeOp.BOOL_OR, PcodeOp.INT_OR -> in1.or(in2);
			case PcodeOp.BOOL_XOR, PcodeOp.INT_XOR -> in1.xor(in2);
			case PcodeOp.INT_LEFT -> left(in1, in2);
			case PcodeOp.INT_RIGHT -> right(in1, in2);
			case PcodeOp.INT_SRIGHT -> sright(in1, in2);
			case PcodeOp.SUBPIECE -> subpiece(in1, in2, sizeout);
			default -> binaryAllOrTop(opcode, sizeout, sizein1, in1, sizein2, in2);
		};
	}

	@Override
	public MaskedBytes modBeforeStore(int sizeinOffset, AddressSpace space, MaskedBytes inOffset,
			int sizeinValue, MaskedBytes inValue) {
		return inValue;
	}

	@Override
	public MaskedBytes modAfterLoad(int sizeinOffset, AddressSpace space, MaskedBytes inOffset,
			int sizeinValue, MaskedBytes inValue) {
		return inValue;
	}

	@Override
	public MaskedBytes fromConst(byte[] value) {
		return MaskedBytes.ofKnown(value);
	}

	static byte[] concreteOrNull(MaskedBytes value) {
		if (value.isMasked()) {
			return null;
		}
		return value.val;
	}

	@Override
	public byte[] toConcrete(MaskedBytes value, Purpose purpose) {
		byte[] result = concreteOrNull(value);
		if (result == null) {
			throw new ConcretionError("Part of the value is masked", purpose);
		}
		return Arrays.copyOf(result, result.length);
	}

	@Override
	public long sizeOf(MaskedBytes value) {
		return value.val.length;
	}
}
