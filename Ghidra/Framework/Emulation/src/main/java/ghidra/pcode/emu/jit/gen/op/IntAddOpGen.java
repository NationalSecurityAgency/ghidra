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
import ghidra.pcode.emu.jit.op.JitIntAddOp;

/**
 * The generator for a {@link JitIntAddOp int_add}.
 * <p>
 * This uses the binary operator generator and simply emits {@link Op#iadd(Emitter) iadd} or
 * {@link Op#ladd(Emitter) ladd} depending on the type.
 * <p>
 * The multi-precision integer logic is not such a simple matter.
 */
public enum IntAddOpGen implements IntOpBinOpGen<JitIntAddOp> {
	/** The generator singleton */
	GEN;

	@Override
	public boolean isSigned() {
		return false;
	}

	@Override
	public <N2 extends Next, N1 extends Ent<N2, TInt>, N0 extends Ent<N1, TInt>>
			Emitter<Ent<N2, TInt>> opForInt(Emitter<N0> em, IntJitType type) {
		return Op.iadd(em);
	}

	@Override
	public <N2 extends Next, N1 extends Ent<N2, TLong>, N0 extends Ent<N1, TLong>>
			Emitter<Ent<N2, TLong>> opForLong(Emitter<N0> em, LongJitType type) {
		return Op.ladd(em);
	}

	/**
	 * Emit bytecode to load a leg of the left operand and combine it with the carry in
	 * <p>
	 * The carry in is a long where bit 32 has the value 0 or 1. The lower 32 bits, which are
	 * actually the result of the previous legs' addition, are ignored. We use a long because it can
	 * hold the full result of addition, where the carry out winds up at bit 32 of the long. This
	 * routine emits bytecode to shift the previous sum out, so that the carry bit is now at bit 0,
	 * i.e., the long how has the value 0 or 1. It then loads and adds the left leg into that long.
	 * 
	 * @param em the emitter typed with a stack of one long, the carry in
	 * @param left the operand containing the leg from the left multi-precision operand
	 * @return the emitter typed with a stack of one long, the summed left and carry in
	 */
	static Emitter<Ent<Bot, TLong>> prepLeftAndCarry(Emitter<Ent<Bot, TLong>> em,
			SimpleOpnd<TInt, IntJitType> left) {
		return em
				.emit(Op::ldc__i, Integer.SIZE)
				.emit(Op::lushr)
				.emit(left::read)
				.emit(Op::i2l)
				.emit(Op::ladd);
	}

	/**
	 * Emit bytecode to load a leg of the right operand and add it to the summed left and carry in
	 * <p>
	 * This completes the addition of the left and right legs along with the carry in. The long on
	 * the stack is now the result, with the carry out in bit position 32.
	 * 
	 * @param em the emitter typed with a stack of one long, the summed left and carry in
	 * @param right the operand containing the leg from the right multi-precision operand
	 * @return the emitter typed with a stack of one long, the result and carry out
	 */
	static Emitter<Ent<Bot, TLong>> addRight(Emitter<Ent<Bot, TLong>> em,
			SimpleOpnd<TInt, IntJitType> right) {
		return em
				.emit(right::read)
				.emit(Op::i2l)
				.emit(Op::ladd);
	}

	/**
	 * Conditionally emit bytecode to store the result into a leg of the output operand
	 * <p>
	 * Other operators may borrow some components of this mp-int addition routine, e.g., to compute
	 * only the output carry bit. In those cases, storing the actual result of the addition is not
	 * necessary, but we still need to keep the intermediate carry bit. Thus, we provide this
	 * routine to conditionally tee the sum (lower 32-bits of the long on the stack) for a leg into
	 * a result leg. Whether or not we emit such bytecode, we ensure the value on the stack remains
	 * unchanged.
	 * <p>
	 * See
	 * {@link #genMpIntLegAddTakesAndGivesCarry(Emitter, SimpleOpnd, SimpleOpnd, boolean, Scope)}
	 * regarding the returned record.
	 * 
	 * @param em the emitter typed with a stack of one long, the result and carry out for a given
	 *            leg
	 * @param into the output leg operand for the multi-precision output operand
	 * @param store true to emit the bytecode, false to emit nothing
	 * @param scope a scope for generating temporary local storage
	 * @return the output operand or null, and the emitter typed with a stack of one long whose
	 *         value is unchanged.
	 */
	static SimpleOpndEm<TInt, IntJitType, Ent<Bot, TLong>> maybeStore(Emitter<Ent<Bot, TLong>> em,
			SimpleOpnd<TInt, IntJitType> into, boolean store, Scope scope) {
		if (!store) {
			return new SimpleOpndEm<>(null, em);
		}
		return em
				.emit(Op::dup2__2)
				.emit(Op::l2i)
				.emit(into::write, scope);
	}

	/**
	 * Emit bytecode to add two corresponding legs of the operands, leaving the carry out on the
	 * stack.
	 * <p>
	 * This assumes the stack has a carry from the previous legs' sum in bit position 32. It shifts
	 * it into position and then adds in the two given legs. It conditionally writes the lower 32
	 * bits of that, i.e., the resulting sum, into an output operand, and then leaves the carry out
	 * in bit position 32 of the long on the stack.
	 * <p>
	 * The returned value is always a non-null record, but the value of the operand may vary. If
	 * {@code store} is false, the operand is always null. This will be the case, e.g., for
	 * computing the carry out of multi-precision addition, because the actual result is not needed.
	 * If {@code store} is true, the the returned operand may or may not be identical to the given
	 * {@code left} parameter, depending on whether or not that operand can be written. The caller
	 * must <em>always</em> use the returned operand to construct the legs of the final
	 * multi-precision output operand. It must <em>never</em> use {@code left}, nor the
	 * multi-precision operand containing it, as the final output.
	 * 
	 * @param em the emitter typed with a stack of one long, the carry out of the previous legs'
	 *            sum, i.e., the carry in for these legs' sum.
	 * @param left the leg for the left multi-precision operand
	 * @param right the leg for the right multi-precision operand
	 * @param storesResult true to receive the leg for the output multi-precision operand
	 * @param scope a scope for generating temporary local storage
	 * @return the output operand or null, and the emitter typed with a stack of one long whose
	 *         value is the carry out for these legs' sum
	 */
	static SimpleOpndEm<TInt, IntJitType, Ent<Bot, TLong>> genMpIntLegAddTakesAndGivesCarry(
			Emitter<Ent<Bot, TLong>> em, SimpleOpnd<TInt, IntJitType> left,
			SimpleOpnd<TInt, IntJitType> right, boolean storesResult, Scope scope) {
		return em
				.emit(IntAddOpGen::prepLeftAndCarry, left)
				.emit(IntAddOpGen::addRight, right)
				.emit(IntAddOpGen::maybeStore, left, storesResult, scope);
	}

	/**
	 * Emit bytecode as in
	 * {@link #genMpIntLegAddTakesAndGivesCarry(Emitter, SimpleOpnd, SimpleOpnd, boolean, Scope)}
	 * except that we do not expect a carry in on the stack.
	 * <p>
	 * This should be used to initiate the addition, taking the least-significant legs of the input
	 * multi-precision operands.
	 * 
	 * @param em the emitter typed with the empty stack
	 * @param left the leg for the left multi-precision operand
	 * @param right the leg for the right multi-precision operand
	 * @param storesResult true to receive the leg for the output multi-precision operand
	 * @param scope a scope for generating temporary local storage
	 * @return the output operand or null, and the emitter typed with a stack of one long whose
	 *         value is the carry out for these legs' sum
	 */
	static SimpleOpndEm<TInt, IntJitType, Ent<Bot, TLong>> genMpIntLegAddGivesCarry(Emitter<Bot> em,
			SimpleOpnd<TInt, IntJitType> left, SimpleOpnd<TInt, IntJitType> right,
			boolean storesResult, Scope scope) {
		return em
				.emit(left::read)
				.emit(Op::i2l)
				.emit(IntAddOpGen::addRight, right)
				.emit(IntAddOpGen::maybeStore, left, storesResult, scope);
	}

	/**
	 * Emit bytecode as in
	 * {@link #genMpIntLegAddTakesAndGivesCarry(Emitter, SimpleOpnd, SimpleOpnd, boolean, Scope)}
	 * except that we do not leave a carry out on the stack.
	 * <p>
	 * This should be used to finalize the addition, taking the most-significant legs of the input
	 * multi-precision operands. Note that this always stores the result and returns an output
	 * operand. Otherwise, this would give no output at all, since it does not leave a carry out on
	 * the stack.
	 * 
	 * @param em the emitter typed with a stack of one long, the carry out of the previous legs'
	 *            sum, i.e., the carry in for these legs' sum.
	 * @param left the leg for the left multi-precision operand
	 * @param right the leg for the right multi-precision operand
	 * @param scope a scope for generating temporary local storage
	 * @return the output operand and the emitter typed with the empty stack
	 */
	static SimpleOpndEm<TInt, IntJitType, Bot> genMpIntLegAddTakesCarry(Emitter<Ent<Bot, TLong>> em,
			SimpleOpnd<TInt, IntJitType> left, SimpleOpnd<TInt, IntJitType> right, Scope scope) {
		return em
				.emit(IntAddOpGen::prepLeftAndCarry, left)
				.emit(IntAddOpGen::addRight, right)
				.emit(Op::l2i)
				.emit(left::write, scope);
	}

	/**
	 * {@inheritDoc}
	 * <p>
	 * The strategy here follows from grade-school long addition. We assert that there are at least
	 * two legs, otherwise we would have just emitted a single add bytecode. This allows us to
	 * unconditionally initialize the addition with
	 * {@link #genMpIntLegAddGivesCarry(Emitter, SimpleOpnd, SimpleOpnd, boolean, Scope)} and
	 * terminate it with {@link #genMpIntLegAddTakesCarry(Emitter, SimpleOpnd, SimpleOpnd, Scope)}.
	 * When there are more than 2 legs, we use
	 * {@link #genMpIntLegAddTakesAndGivesCarry(Emitter, SimpleOpnd, SimpleOpnd, boolean, Scope)} as
	 * many times as necessary in the middle. For all legs, we store the result and append it as a
	 * leg to the final output.
	 */
	@Override
	public <THIS extends JitCompiledPassage> Emitter<Bot> genRunMpInt(Emitter<Bot> em,
			Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen, JitIntAddOp op,
			MpIntJitType type, Scope scope) {
		/**
		 * The strategy here is fairly simple. Ensure both operands are stored in locals. One of the
		 * operands <em>must</em> be in temporaries to ensure we don't modify an input in place.
		 * <p>
		 * For each leg position, convert both right and left legs to a long and add them (along
		 * with a possible carry in). Store the result back into the temp locals. Shift the long sum
		 * right 32 to get the carry out, then continue to the next leg up. The final carry out can
		 * be dropped (overflow).
		 */
		var left = gen.genReadToOpnd(em, localThis, op.l(), type, ext(), scope);
		var right = gen.genReadToOpnd(left.em(), localThis, op.r(), type, rExt(), scope);
		em = right.em();
		var lLegs = left.opnd().type().castLegsLE(left.opnd());
		assert lLegs.size() >= 2;
		var rLegs = right.opnd().type().castLegsLE(right.opnd());

		List<SimpleOpnd<TInt, IntJitType>> outLegs = new ArrayList<>();
		int legCount = type.legsAlloc();

		var first = genMpIntLegAddGivesCarry(em, lLegs.getFirst(), rLegs.getFirst(), true, scope);
		var emCarry = first.em();
		outLegs.add(first.opnd());
		for (int i = 1; i < legCount - 1; i++) {
			var result =
				genMpIntLegAddTakesAndGivesCarry(emCarry, lLegs.get(i), rLegs.get(i), true, scope);
			emCarry = result.em();
			outLegs.add(result.opnd());
		}
		var last = genMpIntLegAddTakesCarry(emCarry, lLegs.getLast(), rLegs.getLast(), scope);
		em = last.em();
		outLegs.add(last.opnd());

		var out = MpIntLocalOpnd.of(type, "out", outLegs);
		return gen.genWriteFromOpnd(em, localThis, op.out(), out, ext(), scope);
	}
}
