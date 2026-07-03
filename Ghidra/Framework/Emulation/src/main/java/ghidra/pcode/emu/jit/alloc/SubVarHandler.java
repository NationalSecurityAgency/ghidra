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
import ghidra.pcode.emu.jit.gen.util.Emitter;
import ghidra.pcode.emu.jit.gen.util.Emitter.Ent;
import ghidra.pcode.emu.jit.gen.util.Emitter.Next;
import ghidra.pcode.emu.jit.gen.util.Scope;
import ghidra.pcode.emu.jit.gen.util.Types.*;

/**
 * A handler to p-code variables stored in just a portion of a single JVM local variable.
 * 
 * @param <ST> the JVM type of the sub variable
 * @param <SJT> the p-code type of the sub variable
 * @param <WT> the JVM type of the containing variable
 * @param <WJT> the p-code type of the containing variable
 */
public interface SubVarHandler<ST extends BPrim<?>, SJT extends SimpleJitType<ST, SJT>,
	WT extends BPrim<?>, WJT extends SimpleJitType<WT, WJT>> extends VarHandler {

	/**
	 * Verify that the sub variable as shifted actually fits in the containing variable
	 * 
	 * @param byteShift the number of unused bytes in the container variable to the right of the sub
	 *            variable
	 * @param type the type of the sub variable
	 * @param local the containing local variable
	 */
	default void assertShiftFits(int byteShift, SJT type, JvmLocal<WT, WJT> local) {
		assert byteShift >= 0 && byteShift + type.size() <= local.type().size();
	}

	/**
	 * {@return the number of unused bytes in the container variable to the right of the sub
	 * variable}
	 */
	int byteShift();

	/**
	 * {@return the number of bits in the sub variable}
	 */
	default int bitSize() {
		return type().size() * Byte.SIZE;
	}

	/**
	 * {@return the number of unused bits in the container variable to the right of the sub
	 * variable}
	 */
	default int bitShift() {
		return byteShift() * Byte.SIZE;
	}

	/**
	 * {@return the mask indicating which parts of the {@code int} containing variable are within
	 * the sub variable}
	 */
	default int intMask() {
		return (-1 >>> (Integer.SIZE - bitSize())) << bitShift();
	}

	/**
	 * {@return the mask indicating which parts of the {@code long} containing variable are within
	 * the sub variable}
	 */
	default long longMask() {
		return (-1L >>> (Long.SIZE - bitSize())) << bitShift();
	}

	/**
	 * {@return The containing local variable}
	 */
	JvmLocal<WT, WJT> local();

	@Override
	SJT type();

	/**
	 * Get the converter of multi-precision integers to the type of the sub variable.
	 * <p>
	 * The converter need not worry about positioning or masking wrt. the sub variable. It should
	 * extract from the multi-precision integer the minimum number of legs needed to fill the sub
	 * variable, i.e., it need only consider the sub variable's size. This handler will then mask
	 * and position it within the containing variable for storage.
	 * 
	 * @return the converter
	 */
	MpToStackConv<TInt, IntJitType, MpIntJitType, ST, SJT> getConvToSub();

	@Override
	default <N extends Next> OpndEm<MpIntJitType, N> genLoadToOpnd(Emitter<N> em,
			JitCodeGenerator<?> gen, MpIntJitType type, Ext ext, Scope scope) {
		return em
				.emit(this::genLoadToStack, gen, this.type(), ext)
				.emit(Opnd::convertToOpnd, this.type(), name(), type, ext, scope);
	}

	@Override
	default <N extends Next> Emitter<Ent<N, TRef<int[]>>> genLoadToArray(Emitter<N> em,
			JitCodeGenerator<?> gen, MpIntJitType type, Ext ext, Scope scope, int slack) {
		return em
				.emit(this::genLoadToStack, gen, this.type(), ext)
				.emit(Opnd::convertToArray, this.type(), name(), type, ext, scope, slack);
	}

	@Override
	default <N extends Next> Emitter<N> genStoreFromOpnd(Emitter<N> em, JitCodeGenerator<?> gen,
			Opnd<MpIntJitType> opnd, Ext ext, Scope scope) {
		return em
				.emit(getConvToSub()::convertOpndToStack, opnd, this.type(), ext)
				.emit(this::genStoreFromStack, gen, this.type(), ext, scope);
	}

	@Override
	default <N1 extends Next, N0 extends Ent<N1, TRef<int[]>>> Emitter<N1> genStoreFromArray(
			Emitter<N0> em, JitCodeGenerator<?> gen, MpIntJitType type, Ext ext, Scope scope) {
		return em
				.emit(getConvToSub()::convertArrayToStack, type, this.type(), ext)
				.emit(this::genStoreFromStack, gen, this.type(), ext, scope);
	}
}
