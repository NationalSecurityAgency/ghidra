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
/* IP: GHIDRA
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
package ghidra.symz3.model;

import static ghidra.pcode.emu.symz3.SymZ3PcodeArithmetic.*;

import java.math.BigInteger;
import java.util.Objects;

import com.microsoft.z3.*;

import ghidra.pcode.emu.symz3.lib.Z3InfixPrinter;
import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.util.Msg;

/**
 * A symbolic value consisting of a either a Z3 bit-vector expression, and an optional Z3 boolean
 * expression. We could simply always use a bit-vector, but we are hoping to avoid simplification of
 * complex ITE expressions. We explored having the value be either a bit-vector or a boolean, but
 * problems arise when we need to create a new symbolic value for a register like "ZF" that from
 * PCode perspective is a base register with 8 bits. Everything worked pretty much if we just made
 * it a Boolean, but that seems very fragile. Thus, we won't need code to convert from Boolean back
 * to bit-vector, because we will always have a bit-vector.
 */
public class SymValueZ3 {
	@SuppressWarnings("unchecked")
	public static String serialize(Context ctx, BitVecExpr b) {
		// serialization is a bit goofy, because we must create a boolean expression
		// see https://github.com/Z3Prover/z3/issues/2674.  
		Solver solver = ctx.mkSolver();
		solver.add(ctx.mkEq(b, b));
		return "V:" + solver.toString();
	}

	@SuppressWarnings("unchecked")
	public static String serialize(Context ctx, BoolExpr b) {
		Solver solver = ctx.mkSolver();
		solver.add(b);
		return "B:" + solver.toString();
	}

	// this is deserialization of a value from a string
	public static SymValueZ3 parse(String serialized) {
		int index = serialized.indexOf(":::::");
		String left = serialized.substring(0, index);
		String right = serialized.substring(index + 5);
		return new SymValueZ3(left, right);
	}

	public static BitVecExpr deserializeBitVecExpr(Context ctx, String s) {
		assert s != null;
		String smt = s.substring(2);
		BoolExpr f = ctx.parseSMTLIB2String(smt, null, null, null, null)[0];
		assert f != null;
		assert s.charAt(0) == 'V';
		return (BitVecExpr) f.getArgs()[0];
	}

	public static BoolExpr deserializeBoolExpr(Context ctx, String s) {
		assert s != null;
		String smt = s.substring(2);
		BoolExpr f = ctx.parseSMTLIB2String(smt, null, null, null, null)[0];
		assert f != null;
		assert s.charAt(0) == 'B';
		return f;
	}

	public final String bitVecExprString;
	public final String boolExprString;

	public SymValueZ3(Context ctx, BitVecExpr bve) {
		this.bitVecExprString = serialize(ctx, bve);
		this.boolExprString = null;
	}

	public SymValueZ3(Context ctx, BitVecExpr bve, BoolExpr be) {
		this.bitVecExprString = serialize(ctx, bve);
		this.boolExprString = serialize(ctx, be);
	}

	private SymValueZ3(String be, String bve) {
		if (be.isEmpty()) {
			this.boolExprString = null;
		}
		else {
			this.boolExprString = be;
		}
		if (bve.isEmpty()) {
			this.bitVecExprString = null;
		}
		else {
			this.bitVecExprString = bve;
		}

	}

	public BitVecExpr getBitVecExpr(Context ctx) {
		return deserializeBitVecExpr(ctx, this.bitVecExprString);
	}

	public BoolExpr getBoolExpr(Context ctx) {
		if (this.boolExprString == null) {
			BitVecExpr b = this.getBitVecExpr(ctx);
			BitVecExpr zero = ctx.mkBV(0, b.getSortSize());
			BoolExpr predicate = ctx.mkEq(b, zero);
			return (BoolExpr) ctx.mkITE(predicate, ctx.mkFalse(), ctx.mkTrue());
		}
		return deserializeBoolExpr(ctx, this.boolExprString);
	}

	public boolean hasBoolExpr() {
		return this.boolExprString != null;
	}

	public boolean hasBitVecExpr() {
		return this.bitVecExprString != null;
	}

	@Override
	public String toString() {
		return String.format("<SymValueZ3: %s>", toDisplay());
	}

	public String toDisplay() {
		try (Context ctx = new Context()) {
			Z3InfixPrinter z3p = new Z3InfixPrinter(ctx);
			if (this.hasBoolExpr()) {
				return z3p.infix(deserializeBoolExpr(ctx, boolExprString));
			}
			return z3p.infix(deserializeBitVecExpr(ctx, bitVecExprString));
		}
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!(obj instanceof SymValueZ3 that)) {
			return false;
		}
		return Objects.equals(this.bitVecExprString, that.bitVecExprString);
	}

	@Override
	public int hashCode() {
		return Objects.hash(this.bitVecExprString);
	}

	public String serialize() {
		String delimiter = ":::::";
		if (this.hasBoolExpr()) {
			return this.boolExprString + delimiter;
		}
		if (this.hasBitVecExpr()) {
			return delimiter + this.bitVecExprString;
		}
		throw new AssertionError("attempted to serialize a null SymValueZ3");
	}

	/** {@return BigInteger value or null if not a BigInteger} */
	public BigInteger toBigInteger() {
		try (Context ctx = new Context()) {
			BitVecExpr b = this.getBitVecExpr(ctx);
			if (b == null || !b.isNumeral()) {
				return null;
			}
			BitVecNum bvn = (BitVecNum) b;
			try {
				return bvn.getBigInteger();
			}
			catch (Exception e) {
				return null;
			}
		}
	}

	/** {@return Long value or null if not a long} */
	public Long toLong() {
		try (Context ctx = new Context()) {
			BitVecExpr b = this.getBitVecExpr(ctx);
			if (b == null || !b.isNumeral()) {
				return null;
			}
			BitVecNum bvn = (BitVecNum) b;
			try {
				return bvn.getLong();
			}
			catch (Exception e) {
				Msg.info(this, "tolong invoked bit not a long returning null " + this);
				return null;
			}
		}
	}

	private interface Z3CmpOp {
		BoolExpr apply(Context ctx, BitVecExpr l, BitVecExpr r);
	}

	private static SymValueZ3 ite(Context ctx, BoolExpr predicate) {
		return new SymValueZ3(ctx, (BitVecExpr) ctx.mkITE(predicate, one(ctx), zero(ctx)));
	}

	private static SymValueZ3 ite(Context ctx, SymValueZ3 l, Z3CmpOp op, SymValueZ3 r) {
		return ite(ctx, op.apply(ctx, l.getBitVecExpr(ctx), r.getBitVecExpr(ctx)));
	}

	private static SymValueZ3 iteInv(Context ctx, BoolExpr predicate) {
		return new SymValueZ3(ctx, (BitVecExpr) ctx.mkITE(predicate, zero(ctx), one(ctx)));
	}

	private static SymValueZ3 iteInv(Context ctx, SymValueZ3 l, Z3CmpOp op, SymValueZ3 r) {
		return iteInv(ctx, op.apply(ctx, l.getBitVecExpr(ctx), r.getBitVecExpr(ctx)));
	}

	public SymValueZ3 intEqual(Context ctx, SymValueZ3 that) {
		return ite(ctx, this, Context::mkEq, that);
	}

	public SymValueZ3 intNotEqual(Context ctx, SymValueZ3 that) {
		return iteInv(ctx, this, Context::mkEq, that);
	}

	public SymValueZ3 intSLess(Context ctx, SymValueZ3 that) {
		return ite(ctx, this, Context::mkBVSLT, that);
	}

	public SymValueZ3 intSLessEqual(Context ctx, SymValueZ3 that) {
		return ite(ctx, this, Context::mkBVSLE, that);
	}

	public SymValueZ3 intLess(Context ctx, SymValueZ3 that) {
		return ite(ctx, this, Context::mkBVULT, that);
	}

	public SymValueZ3 intLessEqual(Context ctx, SymValueZ3 that) {
		return ite(ctx, this, Context::mkBVULE, that);
	}

	public SymValueZ3 intZExt(Context ctx, int outSizeBytes) {
		BitVecExpr bv = this.getBitVecExpr(ctx);
		return new SymValueZ3(ctx, ctx.mkZeroExt(outSizeBytes * 8 - bv.getSortSize(), bv));
	}

	public SymValueZ3 intSExt(Context ctx, int outSizeBytes) {
		BitVecExpr bv = this.getBitVecExpr(ctx);
		return new SymValueZ3(ctx, ctx.mkSignExt(outSizeBytes * 8 - bv.getSortSize(), bv));
	}

	private interface Z3BinBitVecOp {
		BitVecExpr apply(Context ctx, BitVecExpr l, BitVecExpr r);
	}

	private static SymValueZ3 binBitVec(Context ctx, SymValueZ3 l, Z3BinBitVecOp op, SymValueZ3 r) {
		return new SymValueZ3(ctx, op.apply(ctx, l.getBitVecExpr(ctx), r.getBitVecExpr(ctx)));
	}

	public SymValueZ3 intAdd(Context ctx, SymValueZ3 that) {
		return binBitVec(ctx, this, Context::mkBVAdd, that);
	}

	public SymValueZ3 intSub(Context ctx, SymValueZ3 that) {
		return binBitVec(ctx, this, Context::mkBVSub, that);
	}

	private static BoolExpr carry(Context ctx, BitVecExpr l, BitVecExpr r) {
		return ctx.mkBVAddNoOverflow(l, r, false);
	}

	public SymValueZ3 intCarry(Context ctx, SymValueZ3 that) {
		return iteInv(ctx, this, SymValueZ3::carry, that);
	}

	private static BoolExpr scarry(Context ctx, BitVecExpr l, BitVecExpr r) {
		return ctx.mkBVAddNoOverflow(l, r, true);
	}

	public SymValueZ3 intSCarry(Context ctx, SymValueZ3 that) {
		return iteInv(ctx, this, SymValueZ3::scarry, that);
	}

	public SymValueZ3 intSBorrow(Context ctx, SymValueZ3 that) {
		return iteInv(ctx, this, Context::mkBVSubNoOverflow, that);
	}

	public SymValueZ3 intXor(Context ctx, SymValueZ3 that) {
		return binBitVec(ctx, this, Context::mkBVXOR, that);
	}

	public SymValueZ3 intAnd(Context ctx, SymValueZ3 that) {
		return binBitVec(ctx, this, Context::mkBVAND, that);
	}

	public SymValueZ3 intOr(Context ctx, SymValueZ3 that) {
		return binBitVec(ctx, this, Context::mkBVOR, that);
	}

	private static BitVecExpr matchSortSize(Context ctx, int sizeBits, BitVecExpr bv) {
		if (bv.getSortSize() == sizeBits) {
			return bv;
		}
		if (bv.getSortSize() > sizeBits) {
			return ctx.mkExtract(sizeBits - 1, 0, bv);
		}
		return ctx.mkZeroExt(sizeBits - bv.getSortSize(), bv);
	}

	private static SymValueZ3 shift(Context ctx, SymValueZ3 value, Z3BinBitVecOp op,
			SymValueZ3 amt) {
		BitVecExpr valBv = value.getBitVecExpr(ctx);
		BitVecExpr normAmt = matchSortSize(ctx, valBv.getSortSize(), amt.getBitVecExpr(ctx));
		return new SymValueZ3(ctx, op.apply(ctx, valBv, normAmt));
	}

	public SymValueZ3 intLeft(Context ctx, SymValueZ3 that) {
		return shift(ctx, this, Context::mkBVSHL, that);
	}

	public SymValueZ3 intRight(Context ctx, SymValueZ3 that) {
		return shift(ctx, this, Context::mkBVLSHR, that);
	}

	public SymValueZ3 intSRight(Context ctx, SymValueZ3 that) {
		return shift(ctx, this, Context::mkBVASHR, that);
	}

	public SymValueZ3 intMult(Context ctx, SymValueZ3 that) {
		return binBitVec(ctx, this, Context::mkBVMul, that);
	}

	public SymValueZ3 intDiv(Context ctx, SymValueZ3 that) {
		return binBitVec(ctx, this, Context::mkBVUDiv, that);
	}

	public SymValueZ3 intSDiv(Context ctx, SymValueZ3 that) {
		return binBitVec(ctx, this, Context::mkBVSDiv, that);
	}

	private interface Z3UnBoolOp {
		BoolExpr apply(Context ctx, BoolExpr u);
	}

	private interface Z3BinBoolOp {
		BoolExpr apply(Context ctx, BoolExpr l, BoolExpr r);
	}

	private interface Z3ArrBoolOp {
		BoolExpr apply(Context ctx, BoolExpr... e);
	}

	private static SymValueZ3 unBool(Context ctx, Z3UnBoolOp op, SymValueZ3 u) {
		return ite(ctx, op.apply(ctx, u.getBoolExpr(ctx)));
	}

	private static SymValueZ3 binBool(Context ctx, SymValueZ3 l, Z3BinBoolOp op, SymValueZ3 r) {
		return ite(ctx, op.apply(ctx, l.getBoolExpr(ctx), r.getBoolExpr(ctx)));
	}

	private static SymValueZ3 binABool(Context ctx, SymValueZ3 l, Z3ArrBoolOp op, SymValueZ3 r) {
		return ite(ctx, op.apply(ctx, l.getBoolExpr(ctx), r.getBoolExpr(ctx)));
	}

	public SymValueZ3 boolNegate(Context ctx) {
		return unBool(ctx, Context::mkNot, this);
	}

	public SymValueZ3 boolXor(Context ctx, SymValueZ3 that) {
		return binBool(ctx, this, Context::mkXor, that);
	}

	public SymValueZ3 boolAnd(Context ctx, SymValueZ3 that) {
		return binABool(ctx, this, Context::mkAnd, that);
	}

	public SymValueZ3 boolOr(Context ctx, SymValueZ3 that) {
		return binABool(ctx, this, Context::mkOr, that);
	}

	public SymValueZ3 piece(Context ctx, SymValueZ3 that) {
		return binBitVec(ctx, this, Context::mkConcat, that);
	}

	public SymValueZ3 subpiece(Context ctx, int outSizeBytes, SymValueZ3 that) {
		int outSizeBits = outSizeBytes * 8;
		BitVecExpr thisBv = this.getBitVecExpr(ctx);
		int thisSizeBits = thisBv.getSortSize();
		int shiftBits = isInt(that.getBitVecExpr(ctx), Purpose.BY_DEF) * 8;
		BitVecExpr out = thisSizeBits - shiftBits > outSizeBits
				? ctx.mkExtract(outSizeBits + shiftBits - 1, shiftBits, thisBv)
				: ctx.mkExtract(thisSizeBits - 1, shiftBits, thisBv);
		return new SymValueZ3(ctx, out);
	}

	public SymValueZ3 popcount(Context ctx, int outSizeBytes) {
		BitVecExpr outBv = ctx.mkBV(0, outSizeBytes * 8);
		BitVecExpr thisBv = this.getBitVecExpr(ctx);
		for (int i = 0; i < thisBv.getSortSize(); i++) {
			BitVecExpr theBit = ctx.mkZeroExt(outBv.getSortSize() - 1, ctx.mkExtract(i, i, thisBv));
			outBv = ctx.mkBVAdd(outBv, theBit);
		}
		return new SymValueZ3(ctx, outBv);
	}
}
