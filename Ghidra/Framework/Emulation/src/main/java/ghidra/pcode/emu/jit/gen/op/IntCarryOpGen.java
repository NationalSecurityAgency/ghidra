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
package ghidra.pcode.emu.jit.gen.op;

import static ghidra.pcode.emu.jit.gen.GenConsts.*;

import ghidra.pcode.emu.jit.analysis.JitType.*;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage;
import ghidra.pcode.emu.jit.gen.util.*;
import ghidra.pcode.emu.jit.gen.util.Emitter.*;
import ghidra.pcode.emu.jit.gen.util.Methods.Inv;
import ghidra.pcode.emu.jit.gen.util.Types.*;
import ghidra.pcode.emu.jit.op.JitIntCarryOp;

/**
 * The generator for a {@link JitIntCarryOp int_carry}.
 * <p>
 * This uses the integer predicate operator generator. First we have to consider which strategy we
 * are going to use. If the p-code type is strictly smaller than its host JVM type, we can simply
 * add the two operands and examine the next bit up. This is accomplished by emitting
 * {@link Op#iadd(Emitter) iadd} or {@link Op#ladd(Emitter) ladd}, depending on the type, followed
 * by a shift right and a mask.
 * <p>
 * If the p-code type exactly fits its host JVM type, we still add, but we will need to compare the
 * result to one of the operands. Thus, we emit code to duplicate the left operand. We can then add
 * and invoke {@link Integer#compareUnsigned(int, int)} (or similar for longs) to determine whether
 * there was overflow. If there was, then we know the carry bit would have been set. We can spare
 * the conditional flow by just shifting the sign bit into the 1's place.
 * <p>
 * For multi-precision integers, we invoke the subroutines in {@link IntAddOpGen}, but do not store
 * the results, because we only need the carry. When we reach the end, we take advantage of the fact
 * that the final stack result is actually the full 33-bit result for the last leg. We can just
 * shift it the required number of bytes (depending on the type of the input operands) and mask for
 * the desired carry bit.
 */
public enum IntCarryOpGen implements IntPredBinOpGen<JitIntCarryOp> {
	/** The generator singleton */
	GEN;

	@Override
	public boolean isSigned() {
		return false;
	}

	@Override
	public <N2 extends Next, N1 extends Ent<N2, TInt>, N0 extends Ent<N1, TInt>>
			Emitter<Ent<N2, TInt>> opForInt(Emitter<N0> em, IntJitType type) {
		if (type == IntJitType.I4) {
			return em
					.emit(Op::dup_x1) // r l r
					.emit(Op::iadd)
					.emit(Op::swap)
					.emit(Op::invokestatic, TR_INTEGER, "compareUnsigned", MDESC_INTEGER__COMPARE,
						false)
					.step(Inv::takeArg)
					.step(Inv::takeArg)
					.step(Inv::ret)
					// sum < l iff sign bit is 1
					.emit(Op::ldc__i, Integer.SIZE - 1)
					.emit(Op::iushr);
		}
		// Just add and extract the carry bit
		return em
				.emit(Op::iadd)
				.emit(Op::ldc__i, type.size() * Byte.SIZE)
				.emit(Op::ishr)
				// LATER: This mask may not be necessary....
				.emit(Op::ldc__i, 1)
				.emit(Op::iand);
	}

	@Override
	public <N2 extends Next, N1 extends Ent<N2, TLong>, N0 extends Ent<N1, TLong>>
			Emitter<Ent<N2, TInt>> opForLong(Emitter<N0> em, LongJitType type) {
		if (type == LongJitType.I8) {
			return em
					.emit(Op::dup2_x2_22) // r l r
					.emit(Op::ladd)
					.emit(Op::dup2_x2_22)
					.emit(Op::pop2__2)
					.emit(Op::invokestatic, TR_LONG, "compareUnsigned", MDESC_LONG__COMPARE,
						false)
					.step(Inv::takeArg)
					.step(Inv::takeArg)
					.step(Inv::ret)
					// sum < l iff sign bit is 1
					.emit(Op::ldc__i, Integer.SIZE - 1)
					.emit(Op::iushr);
		}
		// Just add and extract the carry bit
		return em
				.emit(Op::ladd)
				.emit(Op::ldc__i, type.size() * Byte.SIZE)
				.emit(Op::lshr)
				.emit(Op::l2i)
				// LATER: This mask may not be necessary....
				.emit(Op::ldc__i, 1)
				.emit(Op::iand);
	}

	@Override
	public <THIS extends JitCompiledPassage> Emitter<Ent<Bot, TInt>> genRunMpInt(Emitter<Bot> em,
			Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen, JitIntCarryOp op,
			MpIntJitType type, Scope scope) {
		/**
		 * Similar strategy as for INT_ADD. In fact, we call its per-leg logic.
		 */
		var left = gen.genReadToOpnd(em, localThis, op.l(), type, ext(), scope);
		var right = gen.genReadToOpnd(left.em(), localThis, op.r(), type, rExt(), scope);
		em = right.em();
		var lLegs = left.opnd().type().castLegsLE(left.opnd());
		assert lLegs.size() >= 2;
		var rLegs = right.opnd().type().castLegsLE(right.opnd());

		int legCount = type.legsAlloc();

		var first = IntAddOpGen.genMpIntLegAddGivesCarry(em, lLegs.getFirst(), rLegs.getFirst(),
			false, scope);
		var emCarry = first.em();
		for (int i = 1; i < legCount; i++) {
			var result = IntAddOpGen.genMpIntLegAddTakesAndGivesCarry(emCarry, lLegs.get(i),
				rLegs.get(i), false, scope);
			emCarry = result.em();
		}
		// carry on top of stack is really [carry][sum] in long
		if (type.partialSize() == 0) {
			// The last leg was full, so extract the carry bit
			return emCarry
					.emit(Op::ldc__i, Integer.SIZE)
					.emit(Op::lushr)
					.emit(Op::l2i);
		}
		// The last leg was partial, so just get the bit one to the right
		return emCarry
				.emit(Op::ldc__i, type.partialSize() * Byte.SIZE)
				.emit(Op::lushr)
				.emit(Op::l2i)
				// LATER: This mask probably not needed
				.emit(Op::ldc__i, 1)
				.emit(Op::iand);
	}
}
