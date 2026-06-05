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

import ghidra.pcode.emu.jit.analysis.JitType.*;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.gen.opnd.Opnd;
import ghidra.pcode.emu.jit.gen.opnd.Opnd.*;
import ghidra.pcode.emu.jit.gen.util.*;
import ghidra.pcode.emu.jit.gen.util.Emitter.Ent;
import ghidra.pcode.emu.jit.gen.util.Emitter.Next;
import ghidra.pcode.emu.jit.gen.util.Types.*;
import ghidra.program.model.pcode.Varnode;

/**
 * A handler for p-code variables composed of a single JVM local variable.
 * 
 * @param <T> the JVM type of the variable
 * @param <JT> the p-code type of the variable
 */
public interface SimpleVarHandler<T extends BPrim<?>, JT extends SimpleJitType<T, JT>>
		extends VarHandler {
	/**
	 * Get the local variable into which this p-code variable is allocated
	 * 
	 * @return the local
	 */
	JvmLocal<T, JT> local();

	@Override
	default Varnode vn() {
		return local().vn();
	}

	@Override
	JT type();

	@Override
	default <TT extends BPrim<?>, TJT extends SimpleJitType<TT, TJT>, N extends Next>
			Emitter<Ent<N, TT>>
			genLoadToStack(Emitter<N> em, JitCodeGenerator<?> gen, TJT type, Ext ext) {
		return local().genLoadToStack(em, gen, type, ext);
	}

	@Override
	default <N extends Next> OpndEm<MpIntJitType, N> genLoadToOpnd(Emitter<N> em,
			JitCodeGenerator<?> gen, MpIntJitType type, Ext ext, Scope scope) {
		return em
				.emit(this::genLoadToStack, gen, type(), ext)
				.emit(Opnd::convertToOpnd, type(), local().name(), type, ext, scope);
	}

	/**
	 * This provides the implementation of
	 * {@link #genLoadLegToStack(Emitter, JitCodeGenerator, MpIntJitType, int, Ext)} for category-1
	 * primitives, i.e., {@code int} and {@code float}.
	 * <p>
	 * Only leg 0 is meaningful for a category-1 primitive. Any other leg is just the extension of
	 * the one leg.
	 * 
	 * @param <N> the incoming stack
	 * @param em the emitter typed with the incoming stack
	 * @param gen the code generator
	 * @param type the p-code type of the complete multi-precision value
	 * @param leg the index of the leg to load, 0 being least significant
	 * @param ext the kind of extension to apply
	 * @return the emitter typed with the resulting stack, i.e., having the int leg pushed onto it
	 */
	default <N extends Next> Emitter<Ent<N, TInt>> genLoadLegToStackC1(Emitter<N> em,
			JitCodeGenerator<?> gen, MpIntJitType type, int leg, Ext ext) {
		if (leg == 0) {
			return em
					.emit(this::genLoadToStack, gen, type.legTypesLE().get(leg), ext);
		}
		return switch (ext) {
			case ZERO -> em
					.emit(Op::ldc__i, 0);
			case SIGN -> {
				IntJitType intType = IntJitType.forSize(type().size());
				yield em
						.emit(this::genLoadToStack, gen, intType, ext)
						.emit(Op::ldc__i, Integer.SIZE - intType.size() * Byte.SIZE)
						.emit(Op::ishl)
						.emit(Op::ldc__i, Integer.SIZE - 1)
						.emit(Op::ishr);
			}
		};
	}

	/**
	 * This provides the implementation of
	 * {@link #genLoadLegToStack(Emitter, JitCodeGenerator, MpIntJitType, int, Ext)} for category-2
	 * primitives, i.e., {@code long} and {@code double}.
	 * <p>
	 * Only legs 0 and 1 are meaningful for a category-2 primitive. Any other leg is just the
	 * extension of the upper leg.
	 * 
	 * @param <N> the incoming stack
	 * @param em the emitter typed with the incoming stack
	 * @param gen the code generator
	 * @param type the p-code type of the complete multi-precision value
	 * @param leg the index of the leg to load, 0 being least significant
	 * @param ext the kind of extension to apply
	 * @return the emitter typed with the resulting stack, i.e., having the int leg pushed onto it
	 */
	default <N extends Next> Emitter<Ent<N, TInt>> genLoadLegToStackC2(Emitter<N> em,
			JitCodeGenerator<?> gen, MpIntJitType type, int leg, Ext ext) {
		if (leg == 0) {
			return em
					.emit(this::genLoadToStack, gen, type.legTypesLE().get(leg), ext);
		}
		if (leg == 1) {
			LongJitType longType = LongJitType.forSize(type().size());
			return em
					.emit(this::genLoadToStack, gen, longType, ext)
					.emit(Op::ldc__i, Integer.SIZE)
					.emit(Op::lshr)
					.emit(Op::l2i)
					.emit(Opnd::convertIntToInt, IntJitType.forSize(type().size() - Integer.BYTES),
						type.legTypesLE().get(leg), ext);
		}
		return switch (ext) {
			case ZERO -> em
					.emit(Op::ldc__i, 0);
			case SIGN -> {
				LongJitType longType = LongJitType.forSize(type().size());
				yield em
						.emit(this::genLoadToStack, gen, longType, ext)
						.emit(Op::ldc__i, longType.size() * Byte.SIZE - Integer.SIZE)
						.emit(Op::lshr)
						.emit(Op::l2i)
						.emit(Op::ldc__i, Integer.SIZE - 1)
						.emit(Op::ishr); // FIXME: Is size conversion required here?
			}
		};
	}

	@Override
	default <N extends Next> Emitter<Ent<N, TRef<int[]>>> genLoadToArray(Emitter<N> em,
			JitCodeGenerator<?> gen, MpIntJitType type, Ext ext, Scope scope, int slack) {
		return em
				.emit(this::genLoadToStack, gen, type(), ext)
				.emit(Opnd::convertToArray, type(), local().name(), type, ext, scope, slack);
	}

	@Override
	default <FT extends BPrim<?>, FJT extends SimpleJitType<FT, FJT>, N1 extends Next,
		N0 extends Ent<N1, FT>> Emitter<N1> genStoreFromStack(Emitter<N0> em,
				JitCodeGenerator<?> gen, FJT type, Ext ext, Scope scope) {
		return local().genStoreFromStack(em, gen, type, ext, scope);
	}

	/**
	 * Get the converter of multi-precision integers to the stack type of this handler's local.
	 * <p>
	 * Note that the converter need only extract the least 1 or 2 legs of the source multi-precision
	 * int, depending on the category of the destination's type. The converter knows how to handle
	 * both the operand (series of locals) and array forms.
	 * 
	 * @return the converter
	 */
	MpToStackConv<TInt, IntJitType, MpIntJitType, T, JT> getConvToStack();

	@Override
	default <N extends Next> Emitter<N> genStoreFromOpnd(Emitter<N> em, JitCodeGenerator<?> gen,
			Opnd<MpIntJitType> opnd, Ext ext, Scope scope) {
		return em
				.emit(getConvToStack()::convertOpndToStack, opnd, this.type(), ext)
				.emit(this::genStoreFromStack, gen, this.type(), ext, scope);
	}

	@Override
	default <N1 extends Next, N0 extends Ent<N1, TRef<int[]>>> Emitter<N1> genStoreFromArray(
			Emitter<N0> em, JitCodeGenerator<?> gen, MpIntJitType type, Ext ext, Scope scope) {
		return em
				.emit(getConvToStack()::convertArrayToStack, type, this.type(), ext)
				.emit(this::genStoreFromStack, gen, this.type(), ext, scope);
	}
}
