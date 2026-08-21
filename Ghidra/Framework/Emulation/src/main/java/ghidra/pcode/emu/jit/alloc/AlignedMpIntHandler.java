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
package ghidra.pcode.emu.jit.alloc;

import java.util.ArrayList;
import java.util.List;

import ghidra.pcode.emu.jit.analysis.JitDataFlowArithmetic;
import ghidra.pcode.emu.jit.analysis.JitType.*;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.gen.opnd.*;
import ghidra.pcode.emu.jit.gen.opnd.Opnd.*;
import ghidra.pcode.emu.jit.gen.util.*;
import ghidra.pcode.emu.jit.gen.util.Emitter.Ent;
import ghidra.pcode.emu.jit.gen.util.Emitter.Next;
import ghidra.pcode.emu.jit.gen.util.Types.*;
import ghidra.program.model.lang.Endian;
import ghidra.program.model.pcode.Varnode;

/**
 * The handler used for a varnode requiring allocation of multiple integers, where those integers
 * correspond exactly to the variable's legs.
 * <p>
 * In this case, we can usually give the operators direct access to the underlying mp-int operand.
 * We do need to be careful that we don't unintentionally permit the operator to use the variable's
 * storage for intermediate values. Thus, we have some provision for saying each leg is read-only,
 * which will cause attempts to store into them to instead generate a writable temporary local. Such
 * intermediate results will get written only by a call to
 * {@link #genStoreFromOpnd(Emitter, JitCodeGenerator, Opnd, Ext, Scope)}.
 * 
 * @param legs the list of legs in little-endian order
 * @param type the type of the full multi-precision integer variable
 * @param vn the complete varnode accessible to this handler
 * @param opnd the (writable) list of local operands (in LE order)
 * @param roOpnd the read-only version of {@code opnd}.
 */
public record AlignedMpIntHandler(List<JvmLocal<TInt, IntJitType>> legs, MpIntJitType type,
		Varnode vn, MpIntLocalOpnd opnd, MpIntLocalOpnd roOpnd) implements VarHandler {

	/**
	 * Static utility for the {@link #AlignedMpIntHandler(List, MpIntJitType, Varnode)} constructor
	 * 
	 * @param legs the list o legs in little-endian order
	 * @param type the type of the full mp-int variable
	 * @param vn the complete varnode
	 * @return the writable operand
	 */
	private static MpIntLocalOpnd createOpnd(List<JvmLocal<TInt, IntJitType>> legs,
			MpIntJitType type, Varnode vn) {
		List<SimpleOpnd<TInt, IntJitType>> opndLegs = new ArrayList<>();
		for (JvmLocal<TInt, IntJitType> leg : legs) {
			opndLegs.add(leg.opnd());
		}
		return MpIntLocalOpnd.of(type, VarHandler.nameVn(vn), opndLegs);
	}

	/**
	 * Static utility for the {@link #AlignedMpIntHandler(List, MpIntJitType, Varnode)} constructor
	 * 
	 * @param legs the list o legs in little-endian order
	 * @param type the type of the full mp-int variable
	 * @param vn the complete varnode
	 * @return the read-only operand
	 */
	private static MpIntLocalOpnd createRoOpnd(List<JvmLocal<TInt, IntJitType>> legs,
			MpIntJitType type, Varnode vn) {
		List<SimpleOpnd<TInt, IntJitType>> opndLegs = new ArrayList<>();
		for (JvmLocal<TInt, IntJitType> leg : legs) {
			opndLegs.add(SimpleOpnd.ofIntReadOnly(leg.type(), leg.local()));
		}
		return MpIntLocalOpnd.of(type, VarHandler.nameVn(vn) + "_ro", opndLegs);
	}

	/**
	 * Preferred constructor
	 * 
	 * @param legs the list o legs in little-endian order
	 * @param type the type of the full muti-precision integer variable
	 * @param vn the complete varnode accessible to this handler
	 */
	public AlignedMpIntHandler(List<JvmLocal<TInt, IntJitType>> legs, MpIntJitType type,
			Varnode vn) {
		this(legs, type, vn, createOpnd(legs, type, vn), createRoOpnd(legs, type, vn));
	}

	@Override
	public <TT extends BPrim<?>, TJT extends SimpleJitType<TT, TJT>, N extends Next>
			Emitter<Ent<N, TT>>
			genLoadToStack(Emitter<N> em, JitCodeGenerator<?> gen, TJT to, Ext ext) {
		return switch (to) {
			case IntJitType t -> em
					.emit(legs.get(0)::genLoadToStack, gen, to, ext);
			case LongJitType t when legs.size() == 1 -> em
					.emit(legs.get(0)::genLoadToStack, gen, to, ext);
			case LongJitType t -> em
					.emit(legs.get(0)::genLoadToStack, gen, LongJitType.I8, Ext.ZERO)
					.emit(legs.get(1)::genLoadToStack, gen, LongJitType.I8, Ext.ZERO)
					.emit(Op::ldc__i, Integer.SIZE)
					.emit(Op::lshl)
					.emit(Op::lor)
					.emit(Opnd::convert, LongJitType.I8, to, ext);
			default -> throw new AssertionError();
		};
	}

	@Override
	public <N extends Next> OpndEm<MpIntJitType, N> genLoadToOpnd(Emitter<N> em,
			JitCodeGenerator<?> gen, MpIntJitType to, Ext ext, Scope scope) {
		return MpIntToMpInt.INSTANCE.convertOpndToOpnd(em, roOpnd, to, ext, scope);
	}

	@Override
	public <N extends Next> Emitter<Ent<N, TInt>> genLoadLegToStack(Emitter<N> em,
			JitCodeGenerator<?> gen, MpIntJitType type, int leg, Ext ext) {
		IntJitType toType = type.legTypesLE().get(leg);
		if (leg >= legs.size()) {
			return switch (ext) {
				case ZERO -> em
						.emit(Op::ldc__i, 0);
				case SIGN -> em
						.emit(legs.getLast()::genLoadToStack, gen, toType, ext)
						.emit(Op::ldc__i, Integer.SIZE - 1)
						.emit(Op::ishr);
			};
		}
		return em
				.emit(legs.get(leg)::genLoadToStack, gen, toType, ext);
	}

	@Override
	public <N extends Next> Emitter<Ent<N, TRef<int[]>>> genLoadToArray(Emitter<N> em,
			JitCodeGenerator<?> gen, MpIntJitType to, Ext ext, Scope scope, int slack) {
		return MpIntToMpInt.INSTANCE.convertOpndToArray(em, opnd, to, ext, scope, slack);
	}

	@Override
	public <N extends Next> Emitter<Ent<N, TInt>> genLoadToBool(Emitter<N> em,
			JitCodeGenerator<?> gen) {
		var result = em
				.emit(legs.get(0)::genLoadToStack, gen, IntJitType.I4, Ext.ZERO);
		for (JvmLocal<TInt, IntJitType> leg : legs) {
			result = result
					.emit(leg::genLoadToStack, gen, IntJitType.I4, Ext.ZERO)
					.emit(Op::ior);
		}
		return result.emit(Opnd::intToBool);
	}

	/**
	 * Emit bytecode to store a JVM int from the stack into the given local
	 * 
	 * @param <N1> the tail of the incoming stack
	 * @param <N0> the incoming stack, having the int on top
	 * @param em the emitter typed with the incoming stack
	 * @param gen the code generator
	 * @param type the p-code type of the int on the stack
	 * @param local the local to receive the value
	 * @param ext the kind of extension to apply
	 * @param scope a scope for generating local storage
	 * @return the emitter typed with the resulting stack, i.e., having popped the int
	 */
	protected <N1 extends Next, N0 extends Ent<N1, TInt>> Emitter<N1> doGenStoreInt(Emitter<N0> em,
			JitCodeGenerator<?> gen, IntJitType type, JvmLocal<TInt, IntJitType> local, Ext ext,
			Scope scope) {
		return em
				.emit(local::genStoreFromStack, gen, type, ext, scope);
	}

	/**
	 * Emit bytecode to compute the sign of the int on the stack, and store that int into a given
	 * local.
	 * <p>
	 * The int is copied and stored into the given local. Then, the sign of the int is computed and
	 * remains on the stack. Signed extension is assumed.
	 * 
	 * @param <N1> the tail of the incoming stack
	 * @param <N0> the incoming stack, having the int on top
	 * @param em the emitter typed with the incoming stack
	 * @param gen the code generator
	 * @param type the p-code type of the int on the stack. Note that this type determines the
	 *            position of the sign bit.
	 * @param local the local to receive the value
	 * @param scope a scope for generating local storage
	 * @return the emitter typed with the resulting stack, i.e., having popped the int and pushed
	 *         the sign
	 */
	protected <N1 extends Next, N0 extends Ent<N1, TInt>> Emitter<Ent<N1, TInt>>
			doGenStoreIntAndSign(Emitter<N0> em, JitCodeGenerator<?> gen, IntJitType type,
					JvmLocal<TInt, IntJitType> local, Scope scope) {
		return em
				.emit(Op::dup)
				.emit(this::doGenStoreInt, gen, type, local, Ext.SIGN, scope)
				.emit(Op::ldc__i, Integer.SIZE - 1)
				.emit(Op::ishr);
	}

	/**
	 * Emit bytecode to store a JVM long from the stack into two given locals
	 * 
	 * @param <N1> the tail of the incoming stack
	 * @param <N0> the incoming stack, having the long on top
	 * @param em the emitter typed with the incoming stack
	 * @param gen the code generator
	 * @param type the p-code type of the int on the stack
	 * @param lower the local to receive the lower 32 bits of the value
	 * @param upper the local to receive the upper 32 bits of the value
	 * @param ext the kind of extension to apply
	 * @param scope a scope for generating local storage
	 * @return the emitter typed with the resulting stack, i.e., having popped the long
	 */
	protected <N1 extends Next, N0 extends Ent<N1, TLong>> Emitter<N1> doGenStoreLong(
			Emitter<N0> em, JitCodeGenerator<?> gen, LongJitType type,
			JvmLocal<TInt, IntJitType> lower, JvmLocal<TInt, IntJitType> upper, Ext ext,
			Scope scope) {
		return em
				.emit(Op::dup2__2)
				.emit(lower::genStoreFromStack, gen, type, ext, scope)
				.emit(Op::ldc__i, Integer.SIZE)
				.emit(Op::lushr)
				.emit(upper::genStoreFromStack, gen,
					LongJitType.forSize(type.size() - Integer.BYTES), ext, scope);
	}

	/**
	 * Emit bytecode to compute the sign of the long on the stack, and store that long into two
	 * given locals.
	 * <p>
	 * The long is copied and stored into the given local. Then, the sign of the long is computed
	 * and remains on the stack as an int. Signed extension is assumed.
	 * 
	 * @param <N1> the tail of the incoming stack
	 * @param <N0> the incoming stack, having the long on top
	 * @param em the emitter typed with the incoming stack
	 * @param gen the code generator
	 * @param type the p-code type of the long on the stack. Note that this type determines the
	 *            position of the sign bit.
	 * @param lower the local to receive the lower 32 bits of the value
	 * @param upper the local to receive the upper 32 bits of the value
	 * @param scope a scope for generating local storage
	 * @return the emitter typed with the resulting stack, i.e., having popped the long and pushed
	 *         the sign
	 */
	protected <N1 extends Next, N0 extends Ent<N1, TLong>> Emitter<Ent<N1, TInt>>
			doGenStoreLongAndSign(Emitter<N0> em, JitCodeGenerator<?> gen, LongJitType type,
					JvmLocal<TInt, IntJitType> lower, JvmLocal<TInt, IntJitType> upper,
					Scope scope) {
		return em
				.emit(Op::dup2__2)
				.emit(lower::genStoreFromStack, gen, type, Ext.SIGN, scope)
				.emit(Op::ldc__i, Integer.SIZE)
				.emit(Op::lushr)
				.emit(Opnd::convert, type, IntJitType.I4, Ext.SIGN)
				.emit(Op::dup)
				.emit(upper::genStoreFromStack, gen, IntJitType.I4, Ext.SIGN, scope)
				.emit(Op::ldc__i, Integer.SIZE - 1)
				.emit(Op::ishr);
	}

	/**
	 * Emit bytecode to zero fill the given locals
	 * 
	 * @param <N> the incoming stack
	 * @param em the emitter typed with the incoming stack
	 * @param gen the code generator
	 * @param locals the locals to zero fill
	 * @param scope a scope for generating local storage
	 * @return the emitter typed with the incoming stack
	 */
	protected <N extends Next> Emitter<N> doGenZeroFill(Emitter<N> em, JitCodeGenerator<?> gen,
			List<JvmLocal<TInt, IntJitType>> locals, Scope scope) {
		for (JvmLocal<TInt, IntJitType> local : locals) {
			em = em
					.emit(Op::ldc__i, 0)
					.emit(local::genStoreFromStack, gen, IntJitType.I4, Ext.ZERO, scope);
		}
		return em;
	}

	/**
	 * Emit bytecode to sign fill the given locals
	 * 
	 * @param <N1> the tail of the incoming stack
	 * @param <N0> the incoming stack having the sign int on top
	 * @param em the emitter typed with the incoming stack
	 * @param gen the code generator
	 * @param locals the locals to sign fill
	 * @param scope a scope for generating local storage
	 * @return the emitter typed with the resulting stack, i.e., having popped the sign
	 */
	protected <N1 extends Next, N0 extends Ent<N1, TInt>> Emitter<N1> doGenSignFill(Emitter<N0> em,
			JitCodeGenerator<?> gen, List<JvmLocal<TInt, IntJitType>> locals, Scope scope) {
		for (JvmLocal<TInt, IntJitType> local : locals.subList(0, locals.size() - 1)) {
			em = em
					.emit(Op::dup)
					.emit(local::genStoreFromStack, gen, IntJitType.I4, Ext.SIGN, scope);
		}
		JvmLocal<TInt, IntJitType> last = locals.getLast();
		return em
				.emit(last::genStoreFromStack, gen, IntJitType.I4, Ext.SIGN, scope);
	}

	@Override
	public <FT extends BPrim<?>, FJT extends SimpleJitType<FT, FJT>, N1 extends Next,
		N0 extends Ent<N1, FT>> Emitter<N1> genStoreFromStack(Emitter<N0> em,
				JitCodeGenerator<?> gen, FJT from, Ext ext, Scope scope) {
		return switch (from) {
			case IntJitType t when legs.size() == 1 -> em
					.emit(Opnd::castStack1, from, t)
					.emit(this::doGenStoreInt, gen, t, legs.get(0), ext, scope);
			case IntJitType t -> switch (ext) {
				case ZERO -> em
						.emit(Opnd::castStack1, from, t)
						.emit(this::doGenStoreInt, gen, t, legs.get(0), ext, scope)
						.emit(this::doGenZeroFill, gen, legs.subList(1, legs.size()), scope);
				case SIGN -> em
						.emit(Opnd::castStack1, from, t)
						.emit(this::doGenStoreIntAndSign, gen, t, legs.get(0), scope)
						.emit(this::doGenSignFill, gen, legs.subList(1, legs.size()), scope);
			};
			case LongJitType t when legs.size() == 1 -> em
					.emit(legs.get(0)::genStoreFromStack, gen, from, ext, scope);
			case LongJitType t when legs.size() == 2 -> em
					.emit(Opnd::castStack1, from, t)
					.emit(this::doGenStoreLong, gen, t, legs.get(0), legs.get(1), ext, scope);
			case LongJitType t -> switch (ext) {
				case ZERO -> em
						.emit(Opnd::castStack1, from, t)
						.emit(this::doGenStoreLong, gen, t, legs.get(0), legs.get(1), ext, scope)
						.emit(this::doGenZeroFill, gen, legs.subList(2, legs.size()), scope);
				case SIGN -> em
						.emit(Opnd::castStack1, from, t)
						.emit(this::doGenStoreLongAndSign, gen, t, legs.get(0), legs.get(1), scope)
						.emit(this::doGenSignFill, gen, legs.subList(2, legs.size()), scope);
			};
			default -> throw new AssertionError();
		};
	}

	/**
	 * Emit bytecode to extend the value stored in our legs.
	 * 
	 * @param <N> the tail of the incoming stack
	 * @param em the emitter typed with the incoming stack
	 * @param gen the code generator
	 * @param defLegs the number of legs having the input value
	 * @param legsOut the number of legs to receive the output value. If this is less than or equal
	 *            to {@code defLegs}, there is no extension to apply, so no code is emitted.
	 * @param ext the kind of extension to apply
	 * @param scope a scope for generating temporary local storage
	 * @return the emitter typed with the incoming stack
	 */
	protected <N extends Next> Emitter<N> genExt(Emitter<N> em, JitCodeGenerator<?> gen,
			int defLegs, int legsOut, Ext ext, Scope scope) {
		if (legsOut <= defLegs) {
			return em;
		}
		return switch (ext) {
			case ZERO -> doGenZeroFill(em, gen, legs.subList(defLegs, legsOut), scope);
			case SIGN -> em
					.emit(Op::iload, legs.get(defLegs - 1).local())
					.emit(Op::ldc__i, Integer.SIZE - 1)
					.emit(Op::ishr) // Signed
					.emit(this::doGenSignFill, gen, legs.subList(defLegs, legsOut), scope);
		};
	}

	@Override
	public <N extends Next> Emitter<N> genStoreFromOpnd(Emitter<N> em, JitCodeGenerator<?> gen,
			Opnd<MpIntJitType> from, Ext ext, Scope scope) {
		List<SimpleOpnd<TInt, IntJitType>> fromLegs = from.type().castLegsLE(from);
		List<SimpleOpnd<TInt, IntJitType>> toLegs = opnd.type().castLegsLE(opnd);
		int legsIn = fromLegs.size();
		int legsOut = toLegs.size();
		int defLegs = Integer.min(legsIn, legsOut);

		for (int i = 0; i < defLegs; i++) {
			SimpleOpnd<TInt, IntJitType> fromLeg = fromLegs.get(i);
			SimpleOpnd<TInt, IntJitType> toLeg = toLegs.get(i);
			em = em
					.emit(fromLeg::read)
					.emit(Opnd::convertIntToInt, fromLeg.type(), toLeg.type(), ext)
					.emit(toLeg::writeDirect);
		}
		return genExt(em, gen, defLegs, legsOut, ext, scope);
	}

	@Override
	public <N1 extends Next, N0 extends Ent<N1, TRef<int[]>>> Emitter<N1> genStoreFromArray(
			Emitter<N0> em, JitCodeGenerator<?> gen, MpIntJitType from, Ext ext, Scope scope) {
		List<IntJitType> fromLegTypes = from.legTypesLE();
		List<SimpleOpnd<TInt, IntJitType>> toLegs = opnd.type().castLegsLE(opnd);
		int legsIn = fromLegTypes.size();
		int legsOut = toLegs.size();
		int defLegs = Integer.min(legsIn, legsOut);

		for (int i = 0; i < defLegs - 1; i++) {
			IntJitType fromLegType = fromLegTypes.get(i);
			SimpleOpnd<TInt, IntJitType> toLeg = toLegs.get(i);
			em = em
					.emit(Op::dup)
					.emit(Op::ldc__i, i)
					.emit(Op::iaload)
					.emit(Opnd::convertIntToInt, fromLegType, toLeg.type(), ext)
					.emit(toLeg::writeDirect);
		}
		IntJitType fromLegType = fromLegTypes.get(defLegs - 1);
		SimpleOpnd<TInt, IntJitType> toLeg = toLegs.get(defLegs - 1);
		return em
				.emit(Op::ldc__i, defLegs - 1)
				.emit(Op::iaload)
				.emit(Opnd::convertIntToInt, fromLegType, toLeg.type(), ext)
				.emit(toLeg::writeDirect)
				.emit(this::genExt, gen, defLegs, legsOut, ext, scope);
	}

	/**
	 * A utility for implementing {@link #subpiece(Endian, int, int)}, also used by
	 * {@link ShiftedMpIntHandler}.
	 * 
	 * @param endian the endianness of the emulation target. Technically, this is only used in the
	 *            naming of any temporary local variables.
	 * @param vn the varnode of the original handler
	 * @param parts the parts (perhaps aligned to the legs) of the original handler
	 * @param curShift if shifted, the number of bytes. If aligned, 0.
	 * @param addShift the offset (in bytes) of the subpiece, i.e., additional shift
	 * @param maxByteSize the size in bytes of the output operand, which indicate the maximum size
	 *            of the resulting handler's varnode.
	 * @return the resulting handler
	 */
	static VarHandler subHandler(Endian endian, Varnode vn, List<JvmLocal<TInt, IntJitType>> parts,
			int curShift, int addShift, int maxByteSize) {
		Varnode subVn = JitDataFlowArithmetic.subPieceVn(endian, vn, addShift, maxByteSize);
		int totalShift = curShift + addShift;
		int firstPart = totalShift / Integer.BYTES;
		int lastPartExcl = (totalShift + subVn.getSize() + Integer.BYTES - 1) / Integer.BYTES;
		List<JvmLocal<TInt, IntJitType>> subParts = parts.subList(firstPart, lastPartExcl);
		int subShift = totalShift % Integer.BYTES;

		if (subParts.size() == 1) {
			IntJitType subType = IntJitType.forSize(subVn.getSize());
			if (subShift == 0) {
				return new IntVarAlloc(subParts.getFirst(), subType);
			}
			return new IntInIntHandler(subParts.getFirst(), subType, subVn, subShift);
		}
		MpIntJitType subType = MpIntJitType.forSize(subVn.getSize());
		if (subShift == 0) {
			return new AlignedMpIntHandler(subParts, subType, subVn);
		}
		return new ShiftedMpIntHandler(subParts, subType, subVn, subShift);
	}

	@Override
	public VarHandler subpiece(Endian endian, int byteOffset, int maxByteSize) {
		return subHandler(endian, vn, legs, 0, byteOffset, maxByteSize);
	}
}
