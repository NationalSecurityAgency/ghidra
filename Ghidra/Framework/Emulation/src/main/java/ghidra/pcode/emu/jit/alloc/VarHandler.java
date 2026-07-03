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

import ghidra.pcode.emu.jit.analysis.JitType;
import ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType;
import ghidra.pcode.emu.jit.analysis.JitType.SimpleJitType;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.gen.op.SubPieceOpGen;
import ghidra.pcode.emu.jit.gen.opnd.Opnd;
import ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext;
import ghidra.pcode.emu.jit.gen.opnd.Opnd.OpndEm;
import ghidra.pcode.emu.jit.gen.util.Emitter;
import ghidra.pcode.emu.jit.gen.util.Emitter.Ent;
import ghidra.pcode.emu.jit.gen.util.Emitter.Next;
import ghidra.pcode.emu.jit.gen.util.Scope;
import ghidra.pcode.emu.jit.gen.util.Types.*;
import ghidra.program.model.lang.Endian;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

/**
 * A handler that knows how to load and store variables' values from local storage.
 * <p>
 * Some variables are hosted in a single JVM local of compatible type. Others, notably
 * multi-precision integers, are allocated among two or more JVM local integers. Each such integer
 * is called a "leg" of the multi-precision integer. Other literature may call these "digits" (whose
 * value is in [0, 0xffffffff]). Depending on the operator implementation, value may need to be
 * loaded with alternative types or in different forms. e.g., any float operator will need to
 * convert its inputs into the appropriate float type, even if the operands were allocated as an int
 * type. Similarly, some operators are implement their multi-precision computations by invoking
 * static methods whose parameters are {@code int[]}, and so they will load and store the array
 * forms instead of accessing the legs' locals. This interface provides generators for the various
 * circumstances. Each subclass provides the implementations for various allocations.
 */
public interface VarHandler {

	/**
	 * Generate a name for the variable representing the given varnode
	 * <p>
	 * These are for debugging purposes. When dumping generating bytecode, the declared local
	 * variables and their scopes are often also dumped. This provides a human with the local
	 * variable index for various varnodes.
	 * 
	 * @param vn the varnode
	 * @return the name
	 */
	static String nameVn(Varnode vn) {
		return "var_%s_%x_%d".formatted(
			vn.getAddress().getAddressSpace().getName(),
			vn.getOffset(),
			vn.getSize());
	}

	/**
	 * Get the complete varnode accessible to this handler
	 * 
	 * @return the varnode
	 */
	Varnode vn();

	/**
	 * Get the name for this handler's local variable, named after the varnode is represents.
	 * 
	 * @return the name of the local variable
	 */
	default String name() {
		return nameVn(vn());
	}

	/**
	 * Get the p-code type of the local variable this handler uses.
	 * 
	 * @return the type
	 */
	JitType type();

	/**
	 * Emit bytecode to load the varnode's value onto the JVM stack.
	 * 
	 * @param <TT> the JVM type of the value to load onto the stack
	 * @param <TJT> the p-code type of the value to load onto the stack
	 * @param <N> the incoming stack
	 * @param em the emitter typed with the incoming stack
	 * @param gen the code generator
	 * @param type the p-code type of the value expected on the JVM stack by the proceeding bytecode
	 * @param ext the kind of extension to apply when adjusting from JVM size to varnode size
	 * @return the emitter typed with the resulting stack
	 */
	<TT extends BPrim<?>, TJT extends SimpleJitType<TT, TJT>, N extends Next> Emitter<Ent<N, TT>>
			genLoadToStack(Emitter<N> em, JitCodeGenerator<?> gen, TJT type, Ext ext);

	/**
	 * Emit bytecode to load the varnode's value into several locals.
	 * 
	 * @param <N> the incoming stack
	 * @param em the emitter typed with the incoming stack
	 * @param gen the code generator
	 * @param type the p-code type of the value expected on the JVM stack by the proceeding bytecode
	 * @param ext the kind of extension to apply
	 * @param scope a scope for generating temporary local storage
	 * @return the operand containing the locals, and the emitter typed with the incoming stack
	 */
	<N extends Next> OpndEm<MpIntJitType, N> genLoadToOpnd(Emitter<N> em, JitCodeGenerator<?> gen,
			MpIntJitType type, Ext ext, Scope scope);

	/**
	 * Emit bytecode to load one leg of a multi-precision value from the varnode onto the JVM stack.
	 * 
	 * @param <N> the incoming stack
	 * @param em the emitter typed with the incoming stack
	 * @param gen the code generator
	 * @param type the p-code type of the complete multi-precision value
	 * @param leg the index of the leg to load, 0 being least significant
	 * @param ext the kind of extension to apply
	 * @return the emitter typed with the resulting stack, i.e., having the int leg pushed onto it
	 */
	<N extends Next> Emitter<Ent<N, TInt>> genLoadLegToStack(Emitter<N> em, JitCodeGenerator<?> gen,
			MpIntJitType type, int leg, Ext ext);

	/**
	 * Emit bytecode to load the varnode's value into an integer array in little-endian order,
	 * pushing its ref onto the JVM stack.
	 * 
	 * @param <N> the incoming stack
	 * @param em the emitter typed with the incoming stack
	 * @param gen the code generator
	 * @param type the p-code type of the complete multi-precision value
	 * @param ext the kind of extension to apply
	 * @param scope a scope for generating temporary local storage
	 * @param slack the number of additional, more significant, elements to allocate in the array
	 * @return the emitter typed with the resulting stack, i.e., having the ref pushed onto it
	 */
	<N extends Next> Emitter<Ent<N, TRef<int[]>>> genLoadToArray(Emitter<N> em,
			JitCodeGenerator<?> gen, MpIntJitType type, Ext ext, Scope scope, int slack);

	/**
	 * Emit bytecode to load the varnode's value, interpreted as a boolean, as an integer onto the
	 * JVM stack.
	 * 
	 * @param <N> the incoming stack
	 * @param em the emitter typed with the incoming stack
	 * @param gen the code generator
	 * @return the emitter typed with the resulting stack, i.e., having the int boolean pushed onto
	 *         it
	 */
	<N extends Next> Emitter<Ent<N, TInt>> genLoadToBool(Emitter<N> em, JitCodeGenerator<?> gen);

	/**
	 * Emit bytecode to store a value into a variable from the JVM stack.
	 * 
	 * @param <FT> the JVM type of the value on the stack
	 * @param <FJT> the p-code type of the value on the stack
	 * @param <N1> the tail of the incoming stack
	 * @param <N0> the incoming stack having the value to store on top
	 * @param em the emitter typed with the incoming stack
	 * @param gen the code generator
	 * @param type the p-code type of the value on the stack
	 * @param ext the kind of extension to apply
	 * @param scope a scope for generating temporary local storage
	 * @return the emitter typed with the resulting stack, i.e., having popped the value
	 */
	<FT extends BPrim<?>, FJT extends SimpleJitType<FT, FJT>, N1 extends Next,
		N0 extends Ent<N1, FT>> Emitter<N1> genStoreFromStack(Emitter<N0> em,
				JitCodeGenerator<?> gen, FJT type, Ext ext, Scope scope);

	/**
	 * Emit bytecode to store a varnode's value from several locals.
	 * 
	 * @param <N> the incoming stack
	 * @param em the emitter typed with the incoming stack
	 * @param gen the code generator
	 * @param opnd the operand whose locals contain the value to be stored
	 * @param ext the kind of extension to apply
	 * @param scope a scope for generating temporary local storage
	 * @return the emitter typed with the incoming stack
	 */
	<N extends Next> Emitter<N> genStoreFromOpnd(Emitter<N> em, JitCodeGenerator<?> gen,
			Opnd<MpIntJitType> opnd, Ext ext, Scope scope);

	/**
	 * Emit bytecode to store a varnode's value from an array of integer legs, in little endian
	 * order
	 * 
	 * @param <N1> the tail of the incoming stack
	 * @param <N0> the incoming stack having the array ref on top
	 * @param em the emitter typed with the incoming stack
	 * @param gen the code generator
	 * @param type the p-code type of the value on the stack
	 * @param ext the kind of extension to apply
	 * @param scope a scope for generating temporary local storage
	 * @return the emitter typed with the resulting stack, i.e., having popped the array
	 */
	<N1 extends Next, N0 extends Ent<N1, TRef<int[]>>> Emitter<N1> genStoreFromArray(Emitter<N0> em,
			JitCodeGenerator<?> gen, MpIntJitType type, Ext ext, Scope scope);

	/**
	 * Create a handler for a {@link PcodeOp#SUBPIECE} of a value.
	 * <p>
	 * To implement {@link SubPieceOpGen subpiece}, we could load the entire varnode and then
	 * extract the designated portion. Or, we could load only the designated portion, averting any
	 * code and execution cost of loading the un-designated portions. We accomplish this by
	 * re-writing the subpiece op and a load of the sub-varnode.
	 * 
	 * @param endian the endianness of the emulation target
	 * @param byteOffset the number of least-significant bytes to remove
	 * @param maxByteSize the maximum size of the resulting variable. In general, a subpiece should
	 *            never exceed the size of the parent varnode, but if it does, this will truncate
	 *            that excess.
	 * @return the resulting subpiece handler
	 */
	VarHandler subpiece(Endian endian, int byteOffset, int maxByteSize);
}
