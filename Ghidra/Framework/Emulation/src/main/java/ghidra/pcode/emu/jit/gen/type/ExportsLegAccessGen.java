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
package ghidra.pcode.emu.jit.gen.type;

import static ghidra.pcode.emu.jit.gen.GenConsts.BLOCK_SIZE;

import org.objectweb.asm.MethodVisitor;

import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.Varnode;

/**
 * A generator that exports part of its implementation for use in a {@link MpTypedAccessGen}.
 * 
 * <p>
 * This really just avoids the re-creation of {@link Varnode} objects for each leg of a large
 * varnode. The method instead takes the (space,offset,size) triple as well as the offset of the
 * block containing its start.
 */
public interface ExportsLegAccessGen extends TypedAccessGen {
	/**
	 * Emit code to access one JVM int, either a whole variable or one leg of a multi-precision int
	 * variable.
	 * 
	 * <p>
	 * Legs that span blocks are handled as in
	 * {@link #generateCode(JitCodeGenerator, Varnode, MethodVisitor)}.
	 * 
	 * 
	 * @param gen the code generator
	 * @param space the address space of the varnode
	 * @param block the block offset containing the varnode (or leg)
	 * @param off the offset of the varnode (or leg)
	 * @param size the size of the varnode in bytes (or leg)
	 * @param rv the method visitor
	 */
	void generateMpCodeLeg(JitCodeGenerator gen, AddressSpace space, long block, int off,
			int size, MethodVisitor rv);

	@Override
	default void generateCode(JitCodeGenerator gen, Varnode vn, MethodVisitor rv) {
		AddressSpace space = vn.getAddress().getAddressSpace();
		long offset = vn.getOffset();
		long block = offset / BLOCK_SIZE * BLOCK_SIZE;
		int off = (int) (offset - block);
		int size = vn.getSize();
		generateMpCodeLeg(gen, space, block, off, size, rv);
	}
}
