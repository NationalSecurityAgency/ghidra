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

import java.util.function.Function;

import ghidra.pcode.emu.jit.analysis.JitType.IntJitType;
import ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType;
import ghidra.pcode.emu.jit.gen.GenConsts;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage;
import ghidra.pcode.emu.jit.gen.util.*;
import ghidra.pcode.emu.jit.gen.util.Emitter.*;
import ghidra.pcode.emu.jit.gen.util.Lbl.LblEm;
import ghidra.pcode.emu.jit.gen.util.Methods.Inv;
import ghidra.pcode.emu.jit.gen.util.Types.*;
import ghidra.pcode.emu.jit.op.JitIntTestOp;

/**
 * An extension for integer comparison operators
 * 
 * @param <T> the class of p-code op node in the use-def graph
 */
public interface IntCompareBinOpGen<T extends JitIntTestOp> extends IntPredBinOpGen<T> {

	/**
	 * Invert the boolean on top of the stack
	 * 
	 * @param <N1> the tail of the incoming stack
	 * @param <N0> the incoming stack with the boolean on top
	 * @param em the emitter typed with the incoming stack
	 * @return the emitter typed with the resulting stack, i.e., the tail with the result pushed
	 */
	static <N1 extends Next, N0 extends Ent<N1, TInt>> Emitter<Ent<N1, TInt>> not(Emitter<N0> em) {
		return em
				// Where this is used, the previous subroutines have already emitted &1
				//.emit(Op::ldc__i, 1)
				//.emit(Op::iand)
				.emit(Op::ldc__i, 1)
				.emit(Op::ixor);
	}

	/**
	 * Assuming a conditional jump bytecode was just emitted, emit bytecode to push 0 (false) onto
	 * the stack for the fall-through case, or 1 (true) onto the stack for the taken case.
	 * 
	 * @param <N> the incoming stack, i.e., that after emitting the conditional jump
	 * @param lblEmTrue the target label of the conditional jump just emitted, and the emitter typed
	 *            with the incoming stack
	 * @return the emitter with the resulting stack, i.e., having pushed the boolean result
	 */
	default <N extends Next> Emitter<Ent<N, TInt>> genBool(LblEm<N, N> lblEmTrue) {
		var lblEmDone = lblEmTrue.em()
				.emit(Op::ldc__i, 0)
				.emit(Op::goto_);
		return lblEmDone.em()
				.emit(Lbl::placeDead, lblEmTrue.lbl())
				.emit(Op::ldc__i, 1)
				.emit(Lbl::place, lblEmDone.lbl());
	}

	/**
	 * An implementation for (unsigned) int operands that invokes
	 * {@link Integer#compareUnsigned(int, int)} and then emits the given {@code if<cond>} jump.
	 * 
	 * @param <N2> the tail of the incoming stack
	 * @param <N1> the tail of the incoming stack including the right operand
	 * @param <N0> the incoming stack with the right and left operands on top
	 * @param em the emitter typed with the incoming stack
	 * @param opIf a method reference, e.g., to {@link Op#ifge(Emitter, Lbl)} for the conditional
	 *            jump
	 * @return the emitter typed with the resulting stack, i.e., the tail with the result pushed
	 */
	default <N2 extends Next, N1 extends Ent<N2, TInt>, N0 extends Ent<N1, TInt>>
			Emitter<Ent<N2, TInt>> genIntViaUcmpThenIf(Emitter<N0> em,
					Function<Emitter<Ent<N2, TInt>>, LblEm<N2, N2>> opIf) {
		return em
				.emit(Op::invokestatic, GenConsts.TR_INTEGER, "compareUnsigned",
					GenConsts.MDESC_INTEGER__COMPARE, false)
				.step(Inv::takeArg)
				.step(Inv::takeArg)
				.step(Inv::ret)
				.emit(this::genIntViaIf, opIf);
	}

	/**
	 * An implementation for (signed) int operands that simply emits the given {@code if_icmp<cond>}
	 * jump.
	 * 
	 * @param <N2> the tail of the incoming stack
	 * @param <N1> the tail of the incoming stack including the right operand
	 * @param <N0> the incoming stack with the right and left operands on top
	 * @param em the emitter typed with the incoming stack
	 * @param opIfIcmp a method reference, e.g., to {@link Op#if_icmpge(Emitter, Lbl)} for the
	 *            conditional jump
	 * @return the emitter typed with the resulting stack, i.e., the tail with the result pushed
	 */
	default <N2 extends Next, N1 extends Ent<N2, TInt>, N0 extends Ent<N1, TInt>>
			Emitter<Ent<N2, TInt>>
			genIntViaIfIcmp(Emitter<N0> em, Function<Emitter<N0>, LblEm<N2, N2>> opIfIcmp) {
		return genBool(opIfIcmp.apply(em));
	}

	/**
	 * A utility that emits the given {@code if<cond>} along with the logic that pushes the correct
	 * result depending on whether or not the jump is taken.
	 * 
	 * @param <N1> the tail of the incoming stack
	 * @param <N0> the incoming stack including the predicate, which is compared with 0
	 * @param em the emitter typed with the incoming stack
	 * @param opIf a method reference, e.g., to {@link Op#ifge(Emitter, Lbl)} for the conditional
	 *            jump
	 * @return the emitter typed with the resulting stack, i.e., the tail with the result pushed
	 */
	default <N1 extends Next, N0 extends Ent<N1, TInt>> Emitter<Ent<N1, TInt>>
			genIntViaIf(Emitter<N0> em, Function<Emitter<N0>, LblEm<N1, N1>> opIf) {
		return genBool(opIf.apply(em));
	}

	/**
	 * An implementation for (signed) long operands that emits {@link Op#lcmp(Emitter) lcmp} and
	 * then emits the given {@code if<cond>} jump.
	 * 
	 * @param <N2> the tail of the incoming stack
	 * @param <N1> the tail of the incoming stack including the right operand
	 * @param <N0> the incoming stack with the right and left operands on top
	 * @param em the emitter typed with the incoming stack
	 * @param opIf a method reference, e.g., to {@link Op#ifge(Emitter, Lbl)} for the conditional
	 *            jump
	 * @return the emitter typed with the resulting stack, i.e., the tail with the result pushed
	 */
	default <N2 extends Next, N1 extends Ent<N2, TLong>, N0 extends Ent<N1, TLong>>
			Emitter<Ent<N2, TInt>> genLongViaLcmpThenIf(Emitter<N0> em,
					Function<Emitter<Ent<N2, TInt>>, LblEm<N2, N2>> opIf) {
		return em
				.emit(Op::lcmp)
				.emit(this::genIntViaIf, opIf);
	}

	/**
	 * An implementation for (unsigned) long operands that invokes
	 * {@link Long#compareUnsigned(long, long)} and then emits the given {@code if<cond>} jump.
	 * 
	 * @param <N2> the tail of the incoming stack
	 * @param <N1> the tail of the incoming stack including the right operand
	 * @param <N0> the incoming stack with the right and left operands on top
	 * @param em the emitter typed with the incoming stack
	 * @param opIf a method reference, e.g., to {@link Op#ifge(Emitter, Lbl)} for the conditional
	 *            jump
	 * @return the emitter typed with the resulting stack, i.e., the tail with the result pushed
	 */
	default <N2 extends Next, N1 extends Ent<N2, TLong>, N0 extends Ent<N1, TLong>>
			Emitter<Ent<N2, TInt>> genLongViaUcmpThenIf(Emitter<N0> em,
					Function<Emitter<Ent<N2, TInt>>, LblEm<N2, N2>> opIf) {
		return em
				.emit(Op::invokestatic, GenConsts.TR_LONG, "compareUnsigned",
					GenConsts.MDESC_LONG__COMPARE, false)
				.step(Inv::takeArg)
				.step(Inv::takeArg)
				.step(Inv::ret)
				.emit(this::genIntViaIf, opIf);
	}

	/**
	 * {@inheritDoc}
	 * <p>
	 * The strategy for multi-precision comparison can be applied to all comparisons: Start with the
	 * most-significant legs and compare <em>for equality</em> until we find the first not-equal
	 * pair. Then, apply {@link #opForInt(Emitter, IntJitType)} to determine the overall result.
	 * There is no need to load or compare any legs beyond the most-significant not-equal pair. If
	 * we reach the final (least-significant) pair, we need not check them for equality. Just
	 * delegate to {@link #opForInt(Emitter, IntJitType)}.
	 */
	@Override
	default <THIS extends JitCompiledPassage> Emitter<Ent<Bot, TInt>> genRunMpInt(Emitter<Bot> em,
			Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen, T op, MpIntJitType type,
			Scope scope) {
		/**
		 * Need to examine from most-significant to least-significant. Stop at the first pair of
		 * legs which are not equal, or on the least-significant leg.
		 */
		int legCount = type.legsAlloc();
		Local<TInt> localLLeg = scope.decl(Types.T_INT, "lLeg");
		Local<TInt> localRLeg = scope.decl(Types.T_INT, "rLeg");
		Lbl<Bot> lblDone = Lbl.create();
		for (int i = legCount - 1; i > 0; i--) { // Yes, stop one before 0, so use >, not >=
			em = em
					.emit(gen::genReadLegToStack, localThis, op.l(), type, i, ext())
					.emit(Op::dup)
					.emit(Op::istore, localLLeg)
					.emit(gen::genReadLegToStack, localThis, op.r(), type, i, ext())
					.emit(Op::dup)
					.emit(Op::istore, localRLeg)
					.emit(IntNotEqualOpGen.GEN::opForInt, IntJitType.I4)
					.emit(Op::ifne, lblDone);
		}
		// We've reached the last leg. Just load them onto the stack
		var lblEmStaged = em
				.emit(gen::genReadLegToStack, localThis, op.l(), type, 0, ext())
				.emit(gen::genReadLegToStack, localThis, op.r(), type, 0, ext())
				.emit(Op::goto_);
		return lblEmStaged.em()
				.emit(Lbl::placeDead, lblDone)
				.emit(Op::iload, localLLeg)
				.emit(Op::iload, localRLeg)
				.emit(Lbl::place, lblEmStaged.lbl())
				.emit(this::opForInt, IntJitType.I4);
	}
}
