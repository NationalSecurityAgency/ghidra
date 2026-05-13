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
package ghidra.pcode.emu.jit.gen.access;

import ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.gen.opnd.Opnd;
import ghidra.pcode.emu.jit.gen.opnd.Opnd.Ext;
import ghidra.pcode.emu.jit.gen.opnd.Opnd.OpndEm;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage;
import ghidra.pcode.emu.jit.gen.util.*;
import ghidra.pcode.emu.jit.gen.util.Emitter.Ent;
import ghidra.pcode.emu.jit.gen.util.Emitter.Next;
import ghidra.pcode.emu.jit.gen.util.Types.TRef;
import ghidra.program.model.pcode.Varnode;

/**
 * An access generator for a multi-precision integer variable
 */
public interface MpAccessGen extends AccessGen<MpIntJitType> {

	/**
	 * Emit bytecode to load the varnode's value into several locals.
	 * 
	 * @param <THIS> the type of the generated passage
	 * @param <N> the incoming stack
	 * @param em the emitter typed with the incoming stack
	 * @param localThis a handle to the local holding the {@code this} reference
	 * @param gen the code generator
	 * @param vn the varnode
	 * @param type desired the p-code type of the value
	 * @param ext the kind of extension to apply
	 * @param scope a scope for generating temporary local storage
	 * @return the operand containing the locals, and the emitter typed with the incoming stack
	 */
	<THIS extends JitCompiledPassage, N extends Next> OpndEm<MpIntJitType, N> genReadToOpnd(
			Emitter<N> em, Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen, Varnode vn,
			MpIntJitType type, Ext ext, Scope scope);

	/**
	 * Emit bytecode to load the varnode's value into an integer array in little-endian order,
	 * pushing its ref onto the JVM stack.
	 * 
	 * @param <THIS> the type of the generated passage
	 * @param <N> the incoming stack
	 * @param em the emitter typed with the incoming stack
	 * @param localThis a handle to the local holding the {@code this} reference
	 * @param gen the code generator
	 * @param vn the varnode
	 * @param type desired the p-code type of the value
	 * @param ext the kind of extension to apply
	 * @param scope a scope for generating temporary local storage
	 * @param slack the number of additional, more significant, elements to allocate in the array
	 * @return the emitter typed with the resulting stack, i.e., having the ref pushed onto it
	 */
	<THIS extends JitCompiledPassage, N extends Next> Emitter<Ent<N, TRef<int[]>>> genReadToArray(
			Emitter<N> em, Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen, Varnode vn,
			MpIntJitType type, Ext ext, Scope scope, int slack);

	/**
	 * Emit bytecode to store a value into a variable from the JVM stack.
	 * 
	 * @param <THIS> the type of the generated passage
	 * @param <N> the incoming stack
	 * @param em the emitter typed with the incoming stack
	 * @param localThis a handle to the local holding the {@code this} reference
	 * @param gen the code generator
	 * @param opnd the operand whose locals contain the value to be stored
	 * @param vn the varnode
	 * @return the emitter typed with the incoming stack
	 */
	<THIS extends JitCompiledPassage, N extends Next> Emitter<N> genWriteFromOpnd(Emitter<N> em,
			Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen, Opnd<MpIntJitType> opnd,
			Varnode vn);

	/**
	 * Emit bytecode to store a varnode's value from an array of integer legs, in little endian
	 * order
	 * 
	 * @param <THIS> the type of the generated passage
	 * @param <N1> the tail of the incoming stack
	 * @param <N0> the incoming stack having the array ref on top
	 * @param em the emitter typed with the incoming stack
	 * @param localThis a handle to the local holding the {@code this} reference
	 * @param gen the code generator
	 * @param vn the varnode
	 * @param scope a scope for generating temporary local storage
	 * @return the emitter typed with the resulting stack, i.e., having popped the array
	 */
	<THIS extends JitCompiledPassage, N1 extends Next, N0 extends Ent<N1, TRef<int[]>>> Emitter<N1>
			genWriteFromArray(Emitter<N0> em, Local<TRef<THIS>> localThis,
					JitCodeGenerator<THIS> gen, Varnode vn, Scope scope);
}
