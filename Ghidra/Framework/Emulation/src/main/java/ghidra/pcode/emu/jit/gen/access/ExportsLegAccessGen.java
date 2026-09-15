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

import static ghidra.pcode.emu.jit.gen.GenConsts.BLOCK_SIZE;

import ghidra.pcode.emu.jit.analysis.JitType.IntJitType;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage;
import ghidra.pcode.emu.jit.gen.util.Emitter;
import ghidra.pcode.emu.jit.gen.util.Emitter.Ent;
import ghidra.pcode.emu.jit.gen.util.Emitter.Next;
import ghidra.pcode.emu.jit.gen.util.Local;
import ghidra.pcode.emu.jit.gen.util.Types.TInt;
import ghidra.pcode.emu.jit.gen.util.Types.TRef;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.Varnode;

/**
 * A generator that exports part of its implementation for use in a {@link MpIntAccessGen}.
 * 
 * <p>
 * This really just avoids the re-creation of {@link Varnode} objects for each leg of a large
 * varnode. The method instead takes the (space,offset,size) triple as well as the offset of the
 * block containing its start.
 */
public interface ExportsLegAccessGen extends SimpleAccessGen<TInt, IntJitType> {
	/**
	 * Emit code to read one JVM int, either a whole variable or one leg of a multi-precision int
	 * variable.
	 * 
	 * <p>
	 * Legs that span blocks are handled as in
	 * {@link #genReadToStack(Emitter, Local, JitCodeGenerator, Varnode)}
	 * 
	 * @param <THIS> the type of the generated passage
	 * @param <N> the incoming stack
	 * @param em the emitter typed with the incoming stack
	 * @param localThis a handle to the local holding the {@code this} reference
	 * @param gen the code generator
	 * @param space the address space of the varnode
	 * @param block the block offset containing the varnode (or leg)
	 * @param off the offset of the varnode (or leg)
	 * @param size the size of the varnode in bytes (or leg)
	 * @return the emitter typed with the resulting stack, i.e., having pushed the value
	 */
	<THIS extends JitCompiledPassage, N extends Next> Emitter<Ent<N, TInt>> genReadLegToStack(
			Emitter<N> em, Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen,
			AddressSpace space, long block, int off, int size);

	/**
	 * Emit code to write one JVM int, either a whole variable or one leg of a multi-precision int
	 * variable.
	 * 
	 * <p>
	 * Legs that span blocks are handled as in
	 * {@link #genWriteFromStack(Emitter, Local, JitCodeGenerator, Varnode)}
	 * 
	 * @param <THIS> the type of the generated passage
	 * @param <N1> the tail of the incoming stack
	 * @param <N0> the incoming stack with the value on top
	 * @param em the emitter typed with the incoming stack
	 * @param localThis a handle to the local holding the {@code this} reference
	 * @param gen the code generator
	 * @param space the address space of the varnode
	 * @param block the block offset containing the varnode (or leg)
	 * @param off the offset of the varnode (or leg)
	 * @param size the size of the varnode in bytes (or leg)
	 * @return the emitter typed with the resulting stack, i.e., having popped the value
	 */
	<THIS extends JitCompiledPassage, N1 extends Next, N0 extends Ent<N1, TInt>> Emitter<N1>
			genWriteLegFromStack(Emitter<N0> em, Local<TRef<THIS>> localThis,
					JitCodeGenerator<THIS> gen, AddressSpace space, long block, int off, int size);

	@Override
	default <THIS extends JitCompiledPassage, N extends Next> Emitter<Ent<N, TInt>> genReadToStack(
			Emitter<N> em, Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen, Varnode vn) {
		AddressSpace space = vn.getAddress().getAddressSpace();
		long offset = vn.getOffset();
		long block = offset / BLOCK_SIZE * BLOCK_SIZE;
		int off = (int) (offset - block);
		int size = vn.getSize();
		return genReadLegToStack(em, localThis, gen, space, block, off, size);
	}

	@Override
	default <THIS extends JitCompiledPassage, N1 extends Next, N0 extends Ent<N1, TInt>> Emitter<N1>
			genWriteFromStack(Emitter<N0> em, Local<TRef<THIS>> localThis,
					JitCodeGenerator<THIS> gen, Varnode vn) {
		AddressSpace space = vn.getAddress().getAddressSpace();
		long offset = vn.getOffset();
		long block = offset / BLOCK_SIZE * BLOCK_SIZE;
		int off = (int) (offset - block);
		int size = vn.getSize();
		return genWriteLegFromStack(em, localThis, gen, space, block, off, size);
	}
}
