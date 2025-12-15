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

import ghidra.pcode.emu.jit.analysis.JitType.SimpleJitType;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage;
import ghidra.pcode.emu.jit.gen.util.Emitter;
import ghidra.pcode.emu.jit.gen.util.Emitter.Ent;
import ghidra.pcode.emu.jit.gen.util.Emitter.Next;
import ghidra.pcode.emu.jit.gen.util.Local;
import ghidra.pcode.emu.jit.gen.util.Types.BPrim;
import ghidra.pcode.emu.jit.gen.util.Types.TRef;
import ghidra.program.model.pcode.Varnode;

/**
 * An access generator for simple-typed variables
 * 
 * @param <T> the JVM type of the variable
 * @param <JT> the p-code type of the variable
 */
public interface SimpleAccessGen<T extends BPrim<?>, JT extends SimpleJitType<T, JT>>
		extends AccessGen<JT> {

	/**
	 * Emit code to read a varnode
	 * <p>
	 * If the varnode fits completely in the block (the common case), then this accesses the bytes
	 * from the one block, using the method chosen by size. If the varnode extends into the next
	 * block, then this will split the varnode into two portions according to machine byte order.
	 * Each portion is accessed using the method for the size of that portion. The results are
	 * reassembled into a single operand.
	 * 
	 * @param <N> the incoming stack
	 * @param em the emitter typed with the incoming stack
	 * @param localThis a handle to the local holding the {@code this} reference
	 * @param gen the code generator
	 * @param vn the varnode
	 * @return the code generator with the resulting stack, i.e., having pushed the value
	 */
	<THIS extends JitCompiledPassage, N extends Next> Emitter<Ent<N, T>> genReadToStack(
			Emitter<N> em, Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen, Varnode vn);

	/**
	 * Emit code to write a varnode
	 * <p>
	 * If the varnode fits completely in the block (the common case), then this accesses the bytes
	 * from the one block, using the method chosen by size. If the varnode extends into the next
	 * block, then this will split the varnode into two portions according to machine byte order.
	 * Each portion is accessed using the method for the size of that portion.
	 * 
	 * @param <N1> the tail of the incoming stack
	 * @param <N0> the incoming stack having the value on top
	 * @param em the emitter typed with the incoming stack
	 * @param localThis a handle to the local holding the {@code this} reference
	 * @param gen the code generator
	 * @param vn the varnode
	 * @return the code generator with the resulting stack, i.e., having popped the value
	 */
	<THIS extends JitCompiledPassage, N1 extends Next, N0 extends Ent<N1, T>> Emitter<N1>
			genWriteFromStack(Emitter<N0> em, Local<TRef<THIS>> localThis,
					JitCodeGenerator<THIS> gen, Varnode vn);
}
