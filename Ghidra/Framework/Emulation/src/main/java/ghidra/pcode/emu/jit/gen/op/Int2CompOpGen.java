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

import ghidra.pcode.emu.jit.analysis.JitType.IntJitType;
import ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType;
import ghidra.pcode.emu.jit.gen.GenConsts;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.gen.opnd.MpIntLocalOpnd;
import ghidra.pcode.emu.jit.gen.opnd.SimpleOpnd;
import ghidra.pcode.emu.jit.gen.opnd.SimpleOpnd.SimpleOpndEm;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage;
import ghidra.pcode.emu.jit.gen.util.*;
import ghidra.pcode.emu.jit.gen.util.Emitter.*;
import ghidra.pcode.emu.jit.gen.util.Methods.Inv;
import ghidra.pcode.emu.jit.gen.util.Types.*;
import ghidra.pcode.emu.jit.op.JitInt2CompOp;

/**
 * The generator for a {@link JitInt2CompOp int_2comp}.
 * <p>
 * This uses the unary operator generator and emits {@link Op#ineg(Emitter) ineg} or
 * {@link Op#lneg(Emitter) lneg}, depending on type.
 * <p>
 * The multi-precision logic is similar to {@link IntAddOpGen}. We follow the process "flip the bits
 * and add 1", so for each leg, we consider that it may have a carry in. We then invert all the bits
 * using ^-1 and then add that carry in. The least significant leg is assumed to have a carry in,
 * effecting the +1.
 */
public enum Int2CompOpGen implements IntOpUnOpGen<JitInt2CompOp> {
	/** The generator singleton */
	GEN;

	@Override
	public boolean isSigned() {
		return false; // TODO: Is it? Test with 3-byte operands to figure it out.
	}

	@Override
	public <N1 extends Next, N0 extends Ent<N1, TInt>> Emitter<Ent<N1, TInt>>
			opForInt(Emitter<N0> em) {
		return Op.ineg(em);
	}

	@Override
	public <N1 extends Next, N0 extends Ent<N1, TLong>> Emitter<Ent<N1, TLong>>
			opForLong(Emitter<N0> em) {
		return Op.lneg(em);
	}

	/**
	 * Emit bytecode to process a leg of the input operand with the carry in
	 * 
	 * @param em the emitter typed with a stack of one long, the carry in
	 * @param opnd the operand containing the leg from the input multi-precision operand
	 * @param shiftCarry indicates whether or not the long needs to be shifted to position the carry
	 *            bit
	 * @return the emitter typed with a stack of one long, the inverted leg and carry out
	 */
	static Emitter<Ent<Bot, TLong>> prepOpndAndCarry(Emitter<Ent<Bot, TLong>> em,
			SimpleOpnd<TInt, IntJitType> opnd, boolean shiftCarry) {
		if (shiftCarry) {
			em = em
					.emit(Op::ldc__i, Integer.SIZE)
					.emit(Op::lushr);
		}
		return em
				.emit(opnd::read)
				.emit(Op::ldc__i, -1 >>> (Integer.SIZE - opnd.type().size() * Byte.SIZE))
				.emit(Op::ixor)
				.emit(Op::invokestatic, GenConsts.TR_INTEGER, "toUnsignedLong",
					GenConsts.MDESC_INTEGER__TO_UNSIGNED_LONG, false)
				.step(Inv::takeArg)
				.step(Inv::ret)
				.emit(Op::ladd);
	}

	/**
	 * Emit bytecode to invert the given leg of the input operand, leaving the carry out on the
	 * stack.
	 * <p>
	 * This assumes the stack has a carry from the previous leg's complement. It is either in bit
	 * position 32, if {@code shiftCarry} is set, or bit position 0, otherwise. It shifts, if
	 * needed, the carry bit into position 0 and then adds the inverted leg. It writes the lower 32
	 * bits of that, i.e., the resulting complement, into an output operand, and then leaves the
	 * carry out in bit position 32 of the long on the stack.
	 * <p>
	 * If {@code opnd} is writable, the result is written there and that operand returned.
	 * Otherwise, a new operand is generated. The caller must em>always</em> use the returned
	 * operand to construct the legs of the final multi-precision output operand. It must
	 * <em>never</em> use {@code opnd}, nor the multi-precision operand containing it, as the final
	 * output.
	 * 
	 * @param em the emitter typed with a stack of one long, the carry out of the previous leg's
	 *            complement, i.e., the carry in for this leg's complement.
	 * @param opnd the leg for the input multi-precision operand
	 * @param shiftCarry true to indicate the carry bit must be shifted from position 32 to 0.
	 * @param scope a scope for generating temporary local storage
	 * @return the output operand and the emitter typed with a stack of one long whose value is the
	 *         carry out for this leg's complement.
	 */
	static SimpleOpndEm<TInt, IntJitType, Ent<Bot, TLong>> genMpIntLeg2CmpTakesAndGivesCarry(
			Emitter<Ent<Bot, TLong>> em, SimpleOpnd<TInt, IntJitType> opnd, boolean shiftCarry,
			Scope scope) {
		return em
				.emit(Int2CompOpGen::prepOpndAndCarry, opnd, shiftCarry)
				.emit(Op::dup2__2)
				.emit(Op::l2i)
				.emit(opnd::write, scope);
	}

	/**
	 * Emit bytecode as in
	 * {@link #genMpIntLeg2CmpTakesAndGivesCarry(Emitter, SimpleOpnd, boolean, Scope)} except that
	 * we do not leave a carry out on the stack.
	 * 
	 * @param em the emitter typed with a stack of one long, the carry out of the previous leg's
	 *            complement, i.e., the carry in for this leg's complement.
	 * @param opnd the leg for the input multi-precision operand
	 * @param shiftCarry true to indicate the carry bit must be shifted from position 32 to 0.
	 * @param scope a scope for generating temporary local storage
	 * @return the output operand and the emitter typed with the empty stack.
	 */
	static SimpleOpndEm<TInt, IntJitType, Bot> genMpIntLeg2CmpTakesCarry(
			Emitter<Ent<Bot, TLong>> em, SimpleOpnd<TInt, IntJitType> opnd, boolean shiftCarry,
			Scope scope) {
		return em
				.emit(Int2CompOpGen::prepOpndAndCarry, opnd, shiftCarry)
				.emit(Op::l2i)
				.emit(opnd::write, scope);
	}

	/**
	 * {@inheritDoc}
	 * <p>
	 * The strategy here follows after
	 * {@link IntAddOpGen#genRunMpInt(Emitter, Local, JitCodeGenerator, ghidra.pcode.emu.jit.op.JitIntAddOp, MpIntJitType, Scope)}.
	 * We no longer need to assert a minimum length, since we provide a "carry in" of 1 for the
	 * initial leg. We initialize the complement by loading that 1 onto the stack and invoking
	 * {@link #genMpIntLeg2CmpTakesAndGivesCarry(Emitter, SimpleOpnd, boolean, Scope)} with
	 * {@code shiftCarry} cleared. We terminate the operation with
	 * {@link #genMpIntLeg2CmpTakesCarry(Emitter, SimpleOpnd, boolean, Scope)}. We use
	 * {@link #genMpIntLeg2CmpTakesAndGivesCarry(Emitter, SimpleOpnd, boolean, Scope)} with
	 * {@code shiftCarry} set for each middle leg. The resulting legs are all appended to form the
	 * final multi-precision output.
	 */
	@Override
	public <THIS extends JitCompiledPassage> Emitter<Bot> genRunMpInt(Emitter<Bot> em,
			Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen, JitInt2CompOp op,
			MpIntJitType type, Scope scope) {
		var opnd = gen.genReadToOpnd(em, localThis, op.u(), type, ext(), scope);
		em = opnd.em();
		var legs = opnd.opnd().type().castLegsLE(opnd.opnd());

		int legCount = type.legsAlloc();
		List<SimpleOpnd<TInt, IntJitType>> outLegs = new ArrayList<>();
		var emCarry = em
				.emit(Op::ldc__l, 1);
		for (int i = 0; i < legCount - 1; i++) {
			var result = emCarry
					.emit(Int2CompOpGen::genMpIntLeg2CmpTakesAndGivesCarry, legs.get(i), i != 0,
						scope);
			emCarry = result.em();
			outLegs.add(result.opnd());
		}
		var result = emCarry
				.emit(Int2CompOpGen::genMpIntLeg2CmpTakesCarry, legs.getLast(), true, scope);
		em = result.em();
		outLegs.add(result.opnd());

		var out = MpIntLocalOpnd.of(type, "out", outLegs);
		return gen.genWriteFromOpnd(em, localThis, op.out(), out, ext(), scope);
	}
}
