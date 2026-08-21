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

import ghidra.pcode.emu.jit.analysis.JitType.*;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.gen.opnd.*;
import ghidra.pcode.emu.jit.gen.opnd.Opnd.*;
import ghidra.pcode.emu.jit.gen.opnd.SimpleOpnd.SimpleOpndEm;
import ghidra.pcode.emu.jit.gen.util.*;
import ghidra.pcode.emu.jit.gen.util.Emitter.Ent;
import ghidra.pcode.emu.jit.gen.util.Emitter.Next;
import ghidra.pcode.emu.jit.gen.util.Types.*;
import ghidra.program.model.lang.Endian;
import ghidra.program.model.pcode.Varnode;

/**
 * The handler used for a varnode requiring allocation of multiple integers, where those integers
 * <em>do not</em> align to the variable's legs.
 * <p>
 * The below diagram is an example shifted allocation, whose {@code byteShift} value is 3, and whose
 * varnode size is 11 (admittedly pathological, but made to illustrate a complicated example).
 * 
 * <pre>
 * +--*--*--*--+--*--*--*--+--*--*--*--+--*--*--*--+
 * | parts[3]  | parts[2]  | parts[1]  | parts[0]  |
 * +-----------+-----------+-----------+-----------+
 *       +--*--*--+--*--*--*--+--*--*--*--+
 *       |  leg2  |   leg1    |   leg0    |
 *       +--------+-----------+-----------+
 * </pre>
 * <p>
 * In the unaligned case, all loads and stores require copying the shifted value into a series of
 * temporary locals, representing the legs of the value. Because these are already temporary, the
 * operator may freely use the legs as temporary storage.
 * 
 * @param parts the list of locals spanned by the variable, in little-endian order.
 * @param type the type of the multi-precision integer variable (only considering the varnode, not
 *            the whole comprised of the spanned parts). In the diagram, this would be
 *            {@link MpIntJitType}{@code (size=11)}.
 * @param vn the complete varnode accessible to this handler. NOTE: The handler must take care not
 *            to modify or permit access to portions of the parts at either end not actually part of
 *            its varnode. In the example, the lower 24 bits of {@code parts[0]} and the upper 16
 *            bits of {@code parts[3]} cannot be accessed. Should a caller to
 *            {@link #genLoadToOpnd(Emitter, JitCodeGenerator, MpIntJitType, Ext, Scope)} specify a
 *            type larger than 11 bytes, only the 11-byte value is loaded, then extended to the
 *            requested size. We do not load the more sigificant portion of {@code parts[3]}.
 * @param byteShift the number of least-significant bytes of the handler's least-significant part
 *            that are <em>excluded</em> from the variable's least-significant leg. I.e., the number
 *            of bytes to shift right when loading the value. In the example, this is 3.
 */
public record ShiftedMpIntHandler(List<JvmLocal<TInt, IntJitType>> parts, MpIntJitType type,
		Varnode vn, int byteShift) implements VarHandler {

	@SuppressWarnings("javadoc")
	public ShiftedMpIntHandler {
		assert byteShift > 0 && byteShift < 4;
		assert parts.size() > 1;
	}

	private int bitShift() {
		return byteShift * Byte.SIZE;
	}

	/**
	 * Emit bytecode to load the right portion of a given leg
	 * 
	 * @param <N> the incoming stack
	 * @param em the emitter typed with the incoming stack
	 * @param gen the code generator
	 * @param i the index of the part, 0 being the least significant
	 * @param ext the kind of extension to apply
	 * @return the emitter typed with the resulting stack, i.e., having the portion pushed onto it
	 *         positioned in an int
	 */
	private <N extends Next> Emitter<Ent<N, TInt>> doGenLoadIntRight(Emitter<N> em,
			JitCodeGenerator<?> gen, int i, Ext ext) {
		return em
				.emit(parts.get(i)::genLoadToStack, gen, IntJitType.I4, ext)
				.emit(Op::ldc__i, bitShift())
				.emit(Op::iushr);
	}

	/**
	 * Emit bytecode to load and {@code or} in the left portion of a given leg
	 * 
	 * @param <N1> the tail of the incoming stack
	 * @param <N0> the incoming stack having the right portion of the same leg already on it
	 * @param em the emitter typed with the incoming stack
	 * @param gen the code generator
	 * @param i the index of the part, 0 being the least significant
	 * @param ext the kind of extension to apply
	 * @return the emitter typed with the incoming stack, though the top value has been modified.
	 */
	private <N1 extends Next, N0 extends Ent<N1, TInt>> Emitter<Ent<N1, TInt>>
			doGenLoadOrIntLeft(Emitter<N0> em, JitCodeGenerator<?> gen, int i, Ext ext) {
		if (i >= parts.size()) {
			// TODO: This may require attention to ext
			return Misc.cast1(em);
		}
		return em
				.emit(parts.get(i)::genLoadToStack, gen, IntJitType.I4, ext)
				.emit(Op::ldc__i, Integer.SIZE - bitShift())
				.emit(Op::ishl)
				.emit(Op::ior);
	}

	/**
	 * Emit bytecode to load the right portion of a long
	 * <p>
	 * This operates as if the long is positioned at the same byte offset as the least-sigificant
	 * leg. Adapting the example from the class documentation:
	 * 
	 * <pre>
	 * +--*--*--*--+--*--*--*--+--*--*--*--+--*--*--*--+
	 * | parts[3]  | parts[2]  | parts[1]  | parts[0]  |
	 * +-----------+-----------+-----------+-----------+
	 *       +--*--*--+--*--*--*--+--*--*--*--+
	 *       |  leg2  |   leg1    |   leg0    |
	 *       +--------+-----------+-----------+
	 *                +-----------------------+
	 *                |        as long        |
	 *                +-----------------------+
	 * </pre>
	 * <p>
	 * Thus, to load the full long, we need to retrieve and shift into place the values from
	 * {@code parts[0]}, {@code [1]}, and {@code [2]}. This method loads the right-most portion.
	 * 
	 * @param <N> the incoming stack
	 * @param em the emitter typed with the incoming stack
	 * @param gen the code generator
	 * @param i the index of the part, 0 being the least significant
	 * @param ext the kind of extension to apply
	 * @return the emitter typed with the resulting stack, i.e., having the portion pushed onto it
	 *         positioned in a long
	 */
	private <N extends Next> Emitter<Ent<N, TLong>> doGenLoadLongRight(Emitter<N> em,
			JitCodeGenerator<?> gen, int i, Ext ext) {
		return em
				.emit(parts.get(i)::genLoadToStack, gen, LongJitType.I8, ext)
				.emit(Op::ldc__i, bitShift())
				.emit(Op::lushr);
	}

	/**
	 * Emit bytecode to load and {@code or} in the middle portion of a long
	 * 
	 * @see #doGenLoadLongRight(Emitter, JitCodeGenerator, int, Ext)
	 * @param <N1> the tail of the incoming stack
	 * @param <N0> the incoming stack having the right portion of the long already on it
	 * @param em the emitter typed with the incoming stack
	 * @param gen the code generator
	 * @param i the index of the part, 0 being the least significant
	 * @param ext the kind of extension to apply
	 * @return the emitter typed with the incoming stack, though the top value has been modified.
	 */
	private <N1 extends Next, N0 extends Ent<N1, TLong>> Emitter<Ent<N1, TLong>>
			doGenLoadOrLongMiddle(Emitter<N0> em, JitCodeGenerator<?> gen, int i, Ext ext) {
		return em
				.emit(parts.get(i)::genLoadToStack, gen, LongJitType.I8, ext)
				.emit(Op::ldc__i, Integer.SIZE - bitShift())
				.emit(Op::lshl)
				.emit(Op::lor);
	}

	/**
	 * Emit bytecode to load and {@code or} in the left portion of a long
	 * 
	 * @see #doGenLoadLongRight(Emitter, JitCodeGenerator, int, Ext)
	 * @param <N1> the tail of the incoming stack
	 * @param <N0> the incoming stack having the right and middle portions of the long already
	 *            {@code or}ed together on it
	 * @param em the emitter typed with the incoming stack
	 * @param gen the code generator
	 * @param i the index of the part, 0 being least significant
	 * @param ext the kind of extension to apply
	 * @return the emitter typed with the incoming stack, though the top value has been modified.
	 */
	private <N1 extends Next, N0 extends Ent<N1, TLong>> Emitter<Ent<N1, TLong>>
			doGenLoadOrLongLeft(Emitter<N0> em, JitCodeGenerator<?> gen, int i, Ext ext) {
		return em
				.emit(parts.get(i)::genLoadToStack, gen, LongJitType.I8, ext)
				.emit(Op::ldc__i, Integer.SIZE * 2 - bitShift())
				.emit(Op::lshl)
				.emit(Op::lor);
	}

	@Override
	public <TT extends BPrim<?>, TJT extends SimpleJitType<TT, TJT>, N extends Next>
			Emitter<Ent<N, TT>>
			genLoadToStack(Emitter<N> em, JitCodeGenerator<?> gen, TJT type, Ext ext) {
		return switch (type) {
			case IntJitType t when t.size() + byteShift <= Integer.BYTES -> em
					// We know at most 4 bytes (1 part) are involved
					.emit(this::doGenLoadIntRight, gen, 0, ext)
					.emit(Opnd::convert, IntJitType.forSize(Integer.BYTES - byteShift), type, ext);
			case IntJitType t -> em
					.emit(this::doGenLoadIntRight, gen, 0, ext)
					.emit(this::doGenLoadOrIntLeft, gen, 1, ext)
					.emit(Opnd::convert, IntJitType.I4, type, ext);
			case LongJitType t when t.size() + byteShift <= Long.BYTES -> em
					// We know at most 8 bytes (2 parts) are involved
					.emit(this::doGenLoadLongRight, gen, 0, ext)
					.emit(this::doGenLoadOrLongMiddle, gen, 1, ext)
					.emit(Opnd::convert, LongJitType.forSize(Long.BYTES - byteShift), type, ext);
			case LongJitType t -> em
					.emit(this::doGenLoadLongRight, gen, 0, ext)
					.emit(this::doGenLoadOrLongMiddle, gen, 1, ext)
					.emit(this::doGenLoadOrLongLeft, gen, 2, ext)
					.emit(Opnd::convert, LongJitType.I8, type, ext);
			default -> throw new AssertionError();
		};
	}

	@Override
	public <N extends Next> OpndEm<MpIntJitType, N> genLoadToOpnd(Emitter<N> em,
			JitCodeGenerator<?> gen, MpIntJitType to, Ext ext, Scope scope) {
		/**
		 * NOTE: Even though we can access more significant parts, we should not incorporate
		 * anything beyond what is allowed by the type (which corresponds to the varnode size).
		 */
		List<IntJitType> fromLegTypes = type.legTypesLE();
		List<IntJitType> toLegTypes = to.legTypesLE();
		List<SimpleOpnd<TInt, IntJitType>> toLegs = new ArrayList<>();
		int legsOut = toLegTypes.size();
		int legsIn = fromLegTypes.size();
		int defLegs = Integer.min(legsIn, legsOut);

		for (int i = 0; i < defLegs; i++) {
			IntJitType fromLegType = fromLegTypes.get(i);
			IntJitType toLegType = toLegTypes.get(i);
			var result = em
					.emit(this::doGenLoadIntRight, gen, i, ext)
					.emit(this::doGenLoadOrIntLeft, gen, i + 1, ext)
					// This chained convert should blot out anything outside the varnode
					.emit(Opnd::convertIntToInt, IntJitType.I4, fromLegType, ext)
					.emit(Opnd::convertIntToInt, fromLegType, toLegType, ext)
					.emit(Opnd::createInt, toLegType, "%s_leg%d".formatted(name(), i), scope);
			em = result.em();
			toLegs.add(result.opnd());
		}
		if (legsOut > defLegs) {
			var sign = switch (ext) {
				case ZERO -> new SimpleOpndEm<>(IntConstOpnd.ZERO_I4, em);
				case SIGN -> em
						.emit(toLegs.getLast()::read)
						.emit(Op::ldc__i, Integer.SIZE - 1)
						.emit(Op::ishr) // Signed
						.emit(Opnd::createIntReadOnly, IntJitType.I4,
							"%s_sign".formatted(name()), scope);
			};
			em = sign.em();
			for (int i = defLegs; i < legsOut; i++) {
				toLegs.add(sign.opnd());
			}
		}
		return new OpndEm<>(MpIntLocalOpnd.of(to, name(), toLegs), em);
	}

	@Override
	public <N extends Next> Emitter<Ent<N, TInt>> genLoadLegToStack(Emitter<N> em,
			JitCodeGenerator<?> gen, MpIntJitType type, int leg, Ext ext) {
		List<IntJitType> fromLegTypes = type.legTypesLE();
		int fromLegCount = fromLegTypes.size();
		if (leg >= fromLegCount) {
			return switch (ext) {
				case ZERO -> em
						.emit(Op::ldc__i, 0);
				case SIGN -> em
						.emit(this::doGenLoadIntRight, gen, fromLegCount - 1, ext) // Remove ???
						.emit(this::doGenLoadOrIntLeft, gen, fromLegCount, ext)
						.emit(Opnd::convertIntToInt, IntJitType.I4, fromLegTypes.getLast(), ext)
						.emit(Op::ldc__i, Integer.SIZE - 1)
						.emit(Op::ishr);
			};
		}
		IntJitType fromLegType = fromLegTypes.get(leg);
		IntJitType toLegType = type.legTypesLE().get(leg);
		return em
				.emit(this::doGenLoadIntRight, gen, leg, ext)
				.emit(this::doGenLoadOrIntLeft, gen, leg + 1, ext)
				.emit(Opnd::convertIntToInt, IntJitType.I4, fromLegType, ext)
				.emit(Opnd::convertIntToInt, fromLegType, toLegType, ext);
	}

	@Override
	public <N extends Next> Emitter<Ent<N, TRef<int[]>>> genLoadToArray(Emitter<N> em,
			JitCodeGenerator<?> gen, MpIntJitType to, Ext ext, Scope scope, int slack) {
		List<IntJitType> fromLegTypes = type.legTypesLE();
		List<IntJitType> toLegTypes = to.legTypesLE();
		int legsOut = toLegTypes.size();
		int legsIn = fromLegTypes.size();
		int defLegs = Integer.min(legsIn, legsOut);

		Local<TRef<int[]>> arr = scope.decl(Types.T_INT_ARR, name());
		em = em
				.emit(Op::ldc__i, legsOut + slack)
				.emit(Op::newarray, Types.T_INT)
				.emit(Op::astore, arr);

		for (int i = 0; i < defLegs; i++) {
			IntJitType fromLegType = fromLegTypes.get(i);
			IntJitType toLegType = toLegTypes.get(i);
			em = em
					.emit(Op::aload, arr)
					.emit(Op::ldc__i, i)
					.emit(this::doGenLoadIntRight, gen, i, ext)
					.emit(this::doGenLoadOrIntLeft, gen, i + 1, ext)
					.emit(Opnd::convertIntToInt, IntJitType.I4, fromLegType, ext)
					.emit(Opnd::convertIntToInt, fromLegType, toLegType, ext)
					.emit(Op::iastore);
		}
		return em
				.emit(MpIntToMpInt::doGenArrExt, arr, legsOut, defLegs, ext, scope)
				.emit(Op::aload, arr);
	}

	@Override
	public <N extends Next> Emitter<Ent<N, TInt>> genLoadToBool(Emitter<N> em,
			JitCodeGenerator<?> gen) {
		int maskRight = -1 << bitShift();
		var result = em
				.emit(Op::iload, parts.get(0).local())
				.emit(Op::ldc__i, maskRight)
				.emit(Op::iand);
		for (int i = 0; i < parts.size(); i++) {
			int bytesLeft = type.size() - byteShift - i * Integer.SIZE;
			var twoInts = result
					.emit(Op::iload, parts.get(i).local());
			if (bytesLeft < Integer.SIZE) {
				int maskLeft = -1 >>> (Integer.SIZE - bytesLeft);
				twoInts = twoInts
						.emit(Op::ldc__i, maskLeft)
						.emit(Op::iand);
			}
			result = twoInts
					.emit(Op::ior);
		}
		return result.emit(Opnd::intToBool);
	}

	/**
	 * Emit bytecode to store from the stack into a given part
	 * <p>
	 * This will combined the existing value and the positioned value using a mask of the accessible
	 * portion of the given part. This code will compute that mask and emit the bytecode to apply
	 * it.
	 * 
	 * @param <N1> the tail of the incoming stack
	 * @param <N0> the incoming stack having the value on top, positioned in an int
	 * @param em the emitter typed with the incoming stack
	 * @param i the index of the part, 0 being the least significant
	 * @return the emitter typed with the resulting stack, i.e., having popped the value
	 */
	private <N1 extends Next, N0 extends Ent<N1, TInt>> Emitter<N1> doGenStoreInt(Emitter<N0> em,
			int i) {
		int bitShift = byteShift * Byte.SIZE;
		int mask = -1;
		if (i == 0) {
			mask &= -1 << bitShift;
		}
		// bytes we'd exceed to the left
		int bytesToRight = Integer.BYTES * (i + 1) - type.size() - byteShift;
		if (bytesToRight > 0) {
			mask &= -1 >>> (bytesToRight * Byte.SIZE);
		}
		JvmLocal<TInt, IntJitType> part = parts.get(i);
		assert mask != 0;
		return mask == -1
				? em
						.emit(Op::istore, part.local())
				: em
						.emit(Op::ldc__i, mask)
						.emit(Op::iand)
						.emit(Op::iload, part.local())
						.emit(Op::ldc__i, ~mask)
						.emit(Op::iand)
						.emit(Op::ior)
						.emit(Op::istore, part.local());
	}

	@Override
	public <FT extends BPrim<?>, FJT extends SimpleJitType<FT, FJT>, N1 extends Next,
		N0 extends Ent<N1, FT>> Emitter<N1> genStoreFromStack(Emitter<N0> em,
				JitCodeGenerator<?> gen, FJT from, Ext ext, Scope scope) {
		int bitShift = byteShift * Byte.SIZE;
		return switch (from) {
			case IntJitType t -> {
				var emConvPos = em
						.emit(Opnd::convert, from, LongJitType.I8, ext)
						.emit(Op::ldc__i, bitShift)
						.emit(Op::lshl);
				for (int i = 0; i < parts.size() - 1; i++) {
					emConvPos = emConvPos
							.emit(Op::dup2__2)
							.emit(Op::l2i)
							.emit(this::doGenStoreInt, i)
							.emit(Op::ldc__i, Integer.SIZE)
							.emit(Opnd::lextshr, ext);
				}
				yield emConvPos
						.emit(Op::l2i)
						.emit(this::doGenStoreInt, parts.size() - 1);
			}
			case LongJitType t -> {
				var emConvPos = em
						.emit(Opnd::convert, from, LongJitType.I8, ext)
						.emit(Op::dup2__2)
						.emit(Op::l2i)
						.emit(Op::ldc__i, bitShift)
						.emit(Op::ishl)
						.emit(this::doGenStoreInt, 0)
						.emit(Op::ldc__i, Integer.SIZE - bitShift)
						.emit(Opnd::lextshr, ext);
				for (int i = 1; i < parts.size() - 1; i++) {
					emConvPos = emConvPos
							.emit(Op::dup2__2)
							.emit(Op::l2i)
							.emit(this::doGenStoreInt, i)
							.emit(Op::ldc__i, Integer.SIZE)
							.emit(Opnd::lextshr, ext);
				}
				yield emConvPos
						.emit(Op::l2i)
						.emit(this::doGenStoreInt, parts.size() - 1);
			}
			default -> throw new AssertionError();
		};
	}

	/**
	 * Emit bytecode to load a leg from the source operand and position it within a long on the
	 * stack.
	 * 
	 * @param <N> the incoming stack
	 * @param em the emitter typed with the incoming stack
	 * @param leg the leg to load
	 * @param bitShift the number of bits to shift left
	 * @param ext the kind of extension to apply
	 * @return the emitter typed with the resulting stack, i.e., having pushed the long
	 */
	private <N extends Next> Emitter<Ent<N, TLong>> positionOpndLeg(Emitter<N> em,
			SimpleOpnd<TInt, IntJitType> leg, int bitShift, Ext ext) {
		return em
				.emit(leg::read)
				.emit(Opnd::convert, leg.type(), LongJitType.I8, ext)
				.emit(Op::ldc__i, bitShift)
				.emit(Op::lshl);
	}

	/**
	 * Emit bytecode to store a leg into its two overlapped parts, then load the next leg from the
	 * source positioning it and the remainder into the long on the top of the stack.
	 * 
	 * @param <N1> the tail of the incoming stack
	 * @param <N0> the incoming stack
	 * @param em the emitter typed with the incoming stack
	 * @param fromLegs the list of source legs in little-endian order
	 * @param i the index of the part to store into, 0 being the least significant
	 * @param bitShift the number of bits to shift the next leg left
	 * @param ext the kind of extension to apply
	 * @return the emitter typed with the incoming stack, though the top value has been modified
	 */
	private <N1 extends Next, N0 extends Ent<N1, TLong>> Emitter<Ent<N1, TLong>>
			storePartAndPositionNextOpndLeg(Emitter<N0> em,
					List<SimpleOpnd<TInt, IntJitType>> fromLegs, int i, int bitShift, Ext ext) {
		var emStored = em
				.emit(Op::dup2__2)
				.emit(Op::l2i)
				.emit(this::doGenStoreInt, i);
		return i + 1 < fromLegs.size()
				? emStored
						.emit(Op::ldc__i, Integer.SIZE)
						.emit(Op::lushr)
						.emit(this::positionOpndLeg, fromLegs.get(i + 1), bitShift, ext)
						.emit(Op::lor)
				: emStored
						.emit(Op::ldc__i, Integer.SIZE)
						.emit(Opnd::lextshr, ext);
	}

	/**
	 * {@inheritDoc}
	 * <p>
	 * The general strategy is to load the source operand one leg at a time. In order to put each
	 * leg with the remaining portion of the previous leg in position, we use a long on the stack as
	 * a temporary. This eases "gluing" the legs together and then writing the shifted portion into
	 * each part.
	 */
	@Override
	public <N extends Next> Emitter<N> genStoreFromOpnd(Emitter<N> em, JitCodeGenerator<?> gen,
			Opnd<MpIntJitType> opnd, Ext ext, Scope scope) {
		List<SimpleOpnd<TInt, IntJitType>> fromLegs = opnd.type().castLegsLE(opnd);
		int bitShift = byteShift * Byte.SIZE;
		var emConvPos = em.emit(this::positionOpndLeg, fromLegs.get(0), bitShift, ext);
		for (int i = 0; i < parts.size() - 1; i++) {
			emConvPos =
				emConvPos.emit(this::storePartAndPositionNextOpndLeg, fromLegs, i, bitShift, ext);
		}
		return emConvPos
				.emit(Op::l2i)
				.emit(this::doGenStoreInt, parts.size() - 1);
	}

	/**
	 * The analog to {@link #positionOpndLeg(Emitter, SimpleOpnd, int, Ext)}, but for a source value
	 * in an array.
	 * 
	 * @param <N> the incoming stack
	 * @param em the emitter typed with the incoming stack
	 * @param arr a handle to the local holding the source array reference
	 * @param legType the type of the leg being loaded
	 * @param bitShift the number of bits to shift left
	 * @param ext the kind of extension to apply
	 * @return the emitter typed with the resulting stack, i.e., having pushed the long
	 */
	private <N extends Next> Emitter<Ent<N, TLong>> positionArrLeg(Emitter<N> em,
			Local<TRef<int[]>> arr, IntJitType legType, int bitShift, Ext ext) {
		return em
				.emit(Op::aload, arr)
				.emit(Op::ldc__i, 0)
				.emit(Op::iaload)
				.emit(Opnd::convert, legType, LongJitType.I8, ext)
				.emit(Op::ldc__i, bitShift)
				.emit(Op::lshl);
	}

	/**
	 * The analog to {@link #storePartAndPositionNextOpndLeg(Emitter, List, int, int, Ext)}, but for
	 * a source value in an array.
	 * 
	 * @param <N1> the tail of the incoming stack
	 * @param <N0> the incoming stack
	 * @param em the emitter typed with the incoming stack
	 * @param arr a handle to the local holding the source array reference
	 * @param fromLegTypes the list of leg types in the source value, in little-endian order
	 * @param i the index of the part to store into, 0 being the least significant
	 * @param bitShift the number of bits to shift the next leg left
	 * @param ext the kind of extension to apply
	 * @return the emitter typed with the incoming stack, though the top value has been modified
	 */
	private <N1 extends Next, N0 extends Ent<N1, TLong>> Emitter<Ent<N1, TLong>>
			storePartAndPositionNextArrLeg(Emitter<N0> em, Local<TRef<int[]>> arr,
					List<IntJitType> fromLegTypes, int i, int bitShift, Ext ext) {
		var emStored = em
				.emit(Op::dup2__2)
				.emit(Op::l2i)
				.emit(this::doGenStoreInt, i);
		return i + 1 < fromLegTypes.size()
				? emStored
						.emit(Op::ldc__i, Integer.SIZE)
						.emit(Op::lushr)
						.emit(this::positionArrLeg, arr, fromLegTypes.get(i + 1), bitShift, ext)
						.emit(Op::lor)
				: emStored
						.emit(Op::ldc__i, Integer.SIZE)
						.emit(Opnd::lextshr, ext);
	}

	/**
	 * {@inheritDoc}
	 * <p>
	 * The strategy here is the same as for
	 * {@link #genStoreFromOpnd(Emitter, JitCodeGenerator, Opnd, Ext, Scope)}
	 */
	@Override
	public <N1 extends Next, N0 extends Ent<N1, TRef<int[]>>> Emitter<N1> genStoreFromArray(
			Emitter<N0> em, JitCodeGenerator<?> gen, MpIntJitType from, Ext ext, Scope scope) {
		try (SubScope ss = scope.sub()) {
			Local<TRef<int[]>> arr = ss.decl(Types.T_INT_ARR, "temp_arr");
			List<IntJitType> fromLegTypes = from.legTypesLE();
			int bitShift = byteShift + Byte.SIZE;
			var emConvPos = em
					.emit(Op::astore, arr)
					.emit(this::positionArrLeg, arr, fromLegTypes.get(0), bitShift, ext);
			for (int i = 0; i < parts.size() - 1; i++) {
				emConvPos = emConvPos.emit(this::storePartAndPositionNextArrLeg, arr, fromLegTypes,
					i, bitShift, ext);
			}
			return emConvPos
					.emit(Op::l2i)
					.emit(this::doGenStoreInt, parts.size() - 1);
		}
	}

	@Override
	public VarHandler subpiece(Endian endian, int byteOffset, int maxByteSize) {
		return AlignedMpIntHandler.subHandler(endian, vn, parts, byteShift, byteOffset,
			maxByteSize);
	}
}
