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
package ghidra.pcode.emu.symz3;

import java.math.BigInteger;
import java.util.Objects;

import com.microsoft.z3.*;

import ghidra.pcode.exec.ConcretionError;
import ghidra.pcode.exec.PcodeArithmetic;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Endian;
import ghidra.program.model.lang.Language;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.symz3.model.SymValueZ3;
import ghidra.util.Msg;

public enum SymZ3PcodeArithmetic implements PcodeArithmetic<SymValueZ3> {

	/** The instance for big-endian languages */
	BIG_ENDIAN(Endian.BIG),
	/** The instance for little-endian languages */
	LITTLE_ENDIAN(Endian.LITTLE);

	static {
		SymZ3.loadZ3Libs();
		Msg.info(SymZ3PcodeArithmetic.class,
			"Z3 Version: " + com.microsoft.z3.Version.getFullVersion());
	}

	/**
	 * Get the arithmetic for the given endianness
	 * 
	 * <p>
	 * This method is provided since clients of this class may expect it, as they would for any
	 * realization of {@link PcodeArithmetic}.
	 * 
	 * @param bigEndian true for big endian, false for little
	 * @return the arithmetic
	 */
	public static SymZ3PcodeArithmetic forEndian(boolean bigEndian) {
		return bigEndian ? BIG_ENDIAN : LITTLE_ENDIAN;
	}

	/**
	 * Get the symbolic arithmetic for the given language
	 * 
	 * <p>
	 * This method is provided since clients of this class may expect it, as they would for any
	 * realization of {@link PcodeArithmetic}.
	 * 
	 * @param language the language
	 * @return the arithmetic
	 */
	public static SymZ3PcodeArithmetic forLanguage(Language language) {
		return forEndian(language.isBigEndian());
	}

	private final Endian endian;

	private SymZ3PcodeArithmetic(Endian endian) {
		this.endian = endian;
	}

	@Override
	public Endian getEndian() {
		return endian;
	}

	public static BitVecNum zero(Context ctx) {
		return ctx.mkBV(0, 8);
	}

	public static BitVecNum one(Context ctx) {
		return ctx.mkBV(1, 8);
	}

	public static BitVecNum isNumeral(BitVecExpr eb, Purpose purpose) {
		if (!eb.isNumeral()) {
			throw new ConcretionError("Not a numeral", purpose);
		}
		return (BitVecNum) eb;
	}

	public static int isInt(BitVecExpr eb, Purpose purpose) {
		return isNumeral(eb, purpose).getInt();
	}

	public static long isLong(BitVecExpr eb, Purpose purpose) {
		return isNumeral(eb, purpose).getLong();
	}

	@Override
	public long toLong(SymValueZ3 value, Purpose purpose) {
		try (Context ctx = new Context()) {
			return isLong(value.getBitVecExpr(ctx), purpose);
		}
	}

	public static BigInteger isBigInteger(BitVecExpr eb, Purpose purpose) {
		return isNumeral(eb, purpose).getBigInteger();
	}

	@Override
	public BigInteger toBigInteger(SymValueZ3 value, Purpose purpose) {
		try (Context ctx = new Context()) {
			return isBigInteger(value.getBitVecExpr(ctx), purpose);
		}
	}

	public static byte[] isConcrete(BitVecExpr eb, Purpose purpose, Endian endian) {
		BigInteger bi = isBigInteger(eb, purpose);
		return Utils.bigIntegerToBytes(bi, eb.getSortSize() * 8, endian.isBigEndian());
	}

	@Override
	public byte[] toConcrete(SymValueZ3 value, Purpose purpose) {
		try (Context ctx = new Context()) {
			return isConcrete(value.getBitVecExpr(ctx), purpose, endian);
		}
	}

	@Override
	public boolean isTrue(SymValueZ3 cond, Purpose purpose) {
		try (Context ctx = new Context()) {
			if (cond.hasBoolExpr()) {
				BoolExpr boolExpr = cond.getBoolExpr(ctx);
				if (boolExpr.isTrue()) {
					return true;
				}
				if (boolExpr.isFalse()) {
					return false;
				}
				throw new ConcretionError("Condition is not constant", purpose);
			}
			BitVecExpr bvExpr = cond.getBitVecExpr(ctx);
			if (bvExpr.isBVBitOne()) {
				return true;
			}
			if (bvExpr.isBVBitZero()) {
				return false;
			}
			throw new ConcretionError("Condition is not constant", purpose);
		}
	}

	@Override
	public SymValueZ3 unaryOp(int opcode, int sizeout, int sizein1, SymValueZ3 in1) {
		Objects.requireNonNull(in1);
		try (Context ctx = new Context()) {
			return switch (opcode) {
				case PcodeOp.COPY -> in1;
				case PcodeOp.INT_ZEXT -> in1.intZExt(ctx, sizeout);
				case PcodeOp.INT_SEXT -> in1.intSExt(ctx, sizeout);
				case PcodeOp.BOOL_NEGATE -> in1.boolNegate(ctx);
				case PcodeOp.POPCOUNT -> in1.popcount(ctx, sizeout);
				default -> throw new AssertionError(
					"need to implement unary op: " + PcodeOp.getMnemonic(opcode));
			};
		} // ctx
	}

	@Override
	public SymValueZ3 binaryOp(int opcode, int sizeout, int sizein1, SymValueZ3 in1, int sizein2,
			SymValueZ3 in2) {
		Objects.requireNonNull(in1);
		Objects.requireNonNull(in2);
		try (Context ctx = new Context()) {
			return switch (opcode) {
				case PcodeOp.INT_EQUAL -> in1.intEqual(ctx, in2);
				case PcodeOp.INT_NOTEQUAL -> in1.intNotEqual(ctx, in2);
				case PcodeOp.INT_SLESS -> in1.intSLess(ctx, in2);
				case PcodeOp.INT_SLESSEQUAL -> in1.intSLessEqual(ctx, in2);
				case PcodeOp.INT_LESS -> in1.intLess(ctx, in2);
				case PcodeOp.INT_LESSEQUAL -> in1.intLessEqual(ctx, in2);

				case PcodeOp.INT_ADD -> in1.intAdd(ctx, in2);
				case PcodeOp.INT_SUB -> in1.intSub(ctx, in2);
				case PcodeOp.INT_CARRY -> in1.intCarry(ctx, in2);
				case PcodeOp.INT_SCARRY -> in1.intSCarry(ctx, in2);
				case PcodeOp.INT_SBORROW -> in1.intSBorrow(ctx, in2);

				case PcodeOp.INT_XOR -> in1.intXor(ctx, in2);
				case PcodeOp.INT_AND -> in1.intAnd(ctx, in2);
				case PcodeOp.INT_OR -> in1.intOr(ctx, in2);

				case PcodeOp.INT_LEFT -> in1.intLeft(ctx, in2);
				case PcodeOp.INT_RIGHT -> in1.intRight(ctx, in2);
				case PcodeOp.INT_SRIGHT -> in1.intSRight(ctx, in2);

				case PcodeOp.INT_MULT -> in1.intMult(ctx, in2);
				case PcodeOp.INT_DIV -> in1.intDiv(ctx, in2);
				case PcodeOp.INT_SDIV -> in1.intSDiv(ctx, in2);

				case PcodeOp.BOOL_XOR -> in1.boolXor(ctx, in2);
				case PcodeOp.BOOL_AND -> in1.boolAnd(ctx, in2);
				case PcodeOp.BOOL_OR -> in1.boolOr(ctx, in2);

				// NOTE: Seeing these in low p-code would be unusual
				case PcodeOp.PIECE -> in1.piece(ctx, in2);
				case PcodeOp.SUBPIECE -> in1.subpiece(ctx, sizeout, in2);
				default -> throw new AssertionError(
					"need to implement binary op: " + PcodeOp.getMnemonic(opcode));
			};
		} // ctx
	}

	@Override
	public SymValueZ3 fromConst(long value, int size) {
		try (Context ctx = new Context()) {
			return new SymValueZ3(ctx, ctx.mkBV(value, size * 8));
		}
	}

	@Override
	public SymValueZ3 fromConst(BigInteger value, int size, boolean isContextreg) {
		try (Context ctx = new Context()) {
			return new SymValueZ3(ctx, ctx.mkBV(value.toString(), size * 8));
		}
	}

	@Override
	public SymValueZ3 fromConst(BigInteger value, int size) {
		return fromConst(value, size, false);
	}

	@Override
	public SymValueZ3 fromConst(byte[] value) {
		return fromConst(Utils.bytesToBigInteger(value, value.length, endian.isBigEndian(), false),
			value.length);
	}

	@Override
	public long sizeOf(SymValueZ3 value) {
		try (Context ctx = new Context()) {
			return value.getBitVecExpr(ctx).getSortSize() / 8;
		}
	}

	@Override
	public SymValueZ3 modBeforeStore(int sizeinOffset, AddressSpace space, SymValueZ3 inOffset,
			int sizeinValue, SymValueZ3 inValue) {
		return inValue;
	}

	@Override
	public SymValueZ3 modAfterLoad(int sizeinOffset, AddressSpace space, SymValueZ3 inOffset,
			int sizeinValue, SymValueZ3 inValue) {
		return inValue;
	}
}
