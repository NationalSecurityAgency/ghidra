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

import java.util.ArrayList;
import java.util.List;

import ghidra.pcode.emu.jit.analysis.JitType.*;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.gen.opnd.MpIntLocalOpnd;
import ghidra.pcode.emu.jit.gen.opnd.SimpleOpnd;
import ghidra.pcode.emu.jit.gen.opnd.SimpleOpnd.SimpleOpndEm;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage;
import ghidra.pcode.emu.jit.gen.util.*;
import ghidra.pcode.emu.jit.gen.util.Emitter.*;
import ghidra.pcode.emu.jit.gen.util.Types.*;
import ghidra.pcode.emu.jit.op.JitIntSubOp;

/**
 * The generator for a {@link JitIntSubOp int_sub}.
 * <p>
 * This uses the binary operator generator and simply emits {@link Op#isub(Emitter) isub} or
 * {@link Op#lsub(Emitter) lsub} depending on the type.
 * <p>
 * This uses the same multi-precision integer strategy and pattern as {@link IntAddOpGen}.
 */
public enum IntSubOpGen implements IntOpBinOpGen<JitIntSubOp> {
	/** The generator singleton */
	GEN;

	@Override
	public boolean isSigned() {
		return false;
	}

	@Override
	public <N2 extends Next, N1 extends Ent<N2, TInt>, N0 extends Ent<N1, TInt>>
			Emitter<Ent<N2, TInt>> opForInt(Emitter<N0> em, IntJitType type) {
		return Op.isub(em);
	}

	@Override
	public <N2 extends Next, N1 extends Ent<N2, TLong>, N0 extends Ent<N1, TLong>>
			Emitter<Ent<N2, TLong>> opForLong(Emitter<N0> em, LongJitType type) {
		return Op.lsub(em);
	}

	/**
	 * Emit bytecode to load a leg of the left operand and combine it with the borrow in
	 * <p>
	 * The borrow in is a long where the upper 32 bits all have the value 0 or 1. The lower 32 bits,
	 * which are actually the result of the previous legs' subtraction, are ignored. We use a long
	 * because it can hold the full result of subtraction, where the borrow out winds up in the
	 * upper 32 bits of the long. This routine emits bytecode to shift the previous difference out,
	 * so that the borrow bit now fills the full 64 bits, i.e., the long how has the value 0 or -1.
	 * It then loads and <em>adds</em> the left leg into that long.
	 * 
	 * @param em the emitter typed with a stack of one long, the borrow in
	 * @param left the operand containing the leg from the left multi-precision operand
	 * @return the emitter typed with a stack of one long, the summed left and borrow in
	 */
	static Emitter<Ent<Bot, TLong>> prepLeftAndBorrow(Emitter<Ent<Bot, TLong>> em,
			SimpleOpnd<TInt, IntJitType> left) {
		return em
				.emit(Op::ldc__i, Integer.SIZE)
				.emit(Op::lshr) // Signed so that ladd below effects subtraction
				.emit(left::read)
				.emit(Op::i2l)
				.emit(Op::ladd);
	}

	/**
	 * Emit bytecode to load a leg of the right operand and subtract it from the summed left and
	 * borrow in
	 * <p>
	 * This completes the subtraction of the left and right legs along with the borrow in. The long
	 * on the stack is now the result, with the borrow out in the upper 32 bits.
	 * 
	 * @param em the emitter typed with a stack of one long, the summed left and borrow in
	 * @param right the operand containing the leg from the right multi-precision operand
	 * @return the emitter typed with a stack of one long, the result and borrow out
	 */
	static Emitter<Ent<Bot, TLong>> subRight(Emitter<Ent<Bot, TLong>> em,
			SimpleOpnd<TInt, IntJitType> right) {
		return em
				.emit(right::read)
				.emit(Op::i2l)
				.emit(Op::lsub);
	}

	/**
	 * Emit bytecode to subtract two corresponding legs of the operands, leaving the borrow out on
	 * the stack.
	 * <p>
	 * This assumes the stack has a borrow from the previous legs' difference in the upper 32 bits.
	 * It signed shifts the borrow such that it adds 0 or -1 into the left leg, and then subtracts
	 * the right leg. It conditionally writes the lower 32 bits of that, i.e., the resulting
	 * difference, into an output operand, and then leaves the borrow out in the upper 32 bits of
	 * the long on the stack.
	 * <p>
	 * The returned value is always a non-null record, but the value of the operand may vary. If
	 * {@code store} is false, the operand is always null. This will be the case, e.g., for
	 * computing the borrow out of multi-precision subtraction, because the actual result is not
	 * needed. If {@code store} is true, the the returned operand may or may not be identical to the
	 * given {@code left} parameter, depending on whether or not that operand can be written. The
	 * caller must <em>always</em> use the returned operand to construct the legs of the final
	 * multi-precision output operand. It must <em>never</em> use {@code left}, nor the
	 * multi-precision operand containing it, as the final output.
	 * 
	 * @param em the emitter typed with a stack of one long, the borrow out of the previous legs'
	 *            difference, i.e., the borrow in for these legs' difference.
	 * @param left the leg for the left multi-precision operand
	 * @param right the leg for the right multi-precision operand
	 * @param storesResult true to receive the leg for the output multi-precision operand
	 * @param scope a scope for generating temporary local storage
	 * @return the output operand or null, and the emitter typed with a stack of one long whose
	 *         value is the borrow out for these legs' difference
	 */
	static SimpleOpndEm<TInt, IntJitType, Ent<Bot, TLong>> genMpIntLegSubTakesAndGivesBorrow(
			Emitter<Ent<Bot, TLong>> em, SimpleOpnd<TInt, IntJitType> left,
			SimpleOpnd<TInt, IntJitType> right, boolean storesResult, Scope scope) {
		return em
				.emit(IntSubOpGen::prepLeftAndBorrow, left)
				.emit(IntSubOpGen::subRight, right)
				.emit(IntAddOpGen::maybeStore, left, storesResult, scope);
	}

	/**
	 * Emit bytecode as in
	 * {@link #genMpIntLegSubTakesAndGivesBorrow(Emitter, SimpleOpnd, SimpleOpnd, boolean, Scope)}
	 * except that we do not expect a borrow in on the stack.
	 * <p>
	 * This should be used to initiate the subtraction, taking the least-significant legs of the
	 * input multi-precision operands.
	 * 
	 * @param em the emitter typed with the empty stack
	 * @param left the leg for the left multi-precision operand
	 * @param right the leg for the right multi-precision operand
	 * @param storesResult true to receive the leg for the output multi-precision operand
	 * @param scope a scope for generating temporary local storage
	 * @return the output operand or null, and the emitter typed with a stack of one long whose
	 *         value is the borrow out for these legs' difference
	 */
	static SimpleOpndEm<TInt, IntJitType, Ent<Bot, TLong>> genMpIntLegSubGivesBorrow(
			Emitter<Bot> em, SimpleOpnd<TInt, IntJitType> left, SimpleOpnd<TInt, IntJitType> right,
			boolean storesResult, Scope scope) {
		return em
				.emit(left::read)
				.emit(Op::i2l)
				.emit(IntSubOpGen::subRight, right)
				.emit(IntAddOpGen::maybeStore, left, storesResult, scope);
	}

	/**
	 * Emit bytecode as in
	 * {@link #genMpIntLegSubTakesAndGivesBorrow(Emitter, SimpleOpnd, SimpleOpnd, boolean, Scope)}
	 * except that we do not leave a borrow out on the stack.
	 * <p>
	 * This should be used to finalize the subtraction, taking the most-significant legs of the
	 * input multi-precision operands. Note that this always stores the result and returns an output
	 * operand. Otherwise, this would give no output at all, since it does not leave a borrow out on
	 * the stack.
	 * 
	 * @param em the emitter typed with a stack of one long, the borrow out of the previous legs'
	 *            difference, i.e., the borrow in for these legs' difference.
	 * @param left the leg for the left multi-precision operand
	 * @param right the leg for the right multi-precision operand
	 * @param scope a scope for generating temporary local storage
	 * @return the output operand and the emitter typed with the empty stack
	 */
	static SimpleOpndEm<TInt, IntJitType, Bot> genMpIntLegSubTakesBorrow(
			Emitter<Ent<Bot, TLong>> em, SimpleOpnd<TInt, IntJitType> left,
			SimpleOpnd<TInt, IntJitType> right, Scope scope) {
		return em
				.emit(IntSubOpGen::prepLeftAndBorrow, left)
				.emit(IntSubOpGen::subRight, right)
				.emit(Op::l2i)
				.emit(left::write, scope);
	}

	/**
	 * {@inheritDoc}
	 * <p>
	 * The strategy here follows from grade-school long subtraction. We assert that there are at
	 * least two legs, otherwise we would have just emitted a single sub bytecode. This allows us to
	 * unconditionally initialize the subtraction with
	 * {@link #genMpIntLegSubGivesBorrow(Emitter, SimpleOpnd, SimpleOpnd, boolean, Scope)} and
	 * terminate it with {@link #genMpIntLegSubTakesBorrow(Emitter, SimpleOpnd, SimpleOpnd, Scope)}.
	 * When there are more than 2 legs, we use
	 * {@link #genMpIntLegSubTakesAndGivesBorrow(Emitter, SimpleOpnd, SimpleOpnd, boolean, Scope)}
	 * as many times as necessary in the middle. For all legs, we store the result and append it as
	 * a leg to the final output.
	 */
	@Override
	public <THIS extends JitCompiledPassage> Emitter<Bot> genRunMpInt(Emitter<Bot> em,
			Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen, JitIntSubOp op,
			MpIntJitType type, Scope scope) {
		var left = gen.genReadToOpnd(em, localThis, op.l(), type, ext(), scope);
		var right = gen.genReadToOpnd(left.em(), localThis, op.r(), type, rExt(), scope);
		em = right.em();
		var lLegs = left.opnd().type().castLegsLE(left.opnd());
		assert lLegs.size() >= 2;
		var rLegs = right.opnd().type().castLegsLE(right.opnd());

		List<SimpleOpnd<TInt, IntJitType>> outLegs = new ArrayList<>();
		int legCount = type.legsAlloc();

		var first = genMpIntLegSubGivesBorrow(em, lLegs.getFirst(), rLegs.getFirst(), true, scope);
		var emCarry = first.em();
		outLegs.add(first.opnd());
		for (int i = 1; i < legCount - 1; i++) {
			var result =
				genMpIntLegSubTakesAndGivesBorrow(emCarry, lLegs.get(i), rLegs.get(i), true, scope);
			emCarry = result.em();
			outLegs.add(result.opnd());
		}
		var last = genMpIntLegSubTakesBorrow(emCarry, lLegs.getLast(), rLegs.getLast(), scope);
		em = last.em();
		outLegs.add(last.opnd());

		var out = MpIntLocalOpnd.of(type, "out", outLegs);
		return gen.genWriteFromOpnd(em, localThis, op.out(), out, ext(), scope);
	}
}
