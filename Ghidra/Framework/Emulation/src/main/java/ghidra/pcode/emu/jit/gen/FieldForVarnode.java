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
package ghidra.pcode.emu.jit.gen;

import static ghidra.pcode.emu.jit.gen.GenConsts.*;
import static org.objectweb.asm.Opcodes.*;

import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;

import ghidra.pcode.emu.jit.analysis.JitDataFlowUseropLibrary;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage;
import ghidra.pcode.emu.jit.gen.var.VarGen;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.pcode.Varnode;

/**
 * A field request for a pre-constructed varnode
 * 
 * <p>
 * These are used to invoke userops using the Standard strategy.
 * 
 * @param vn the varnode to pre-construct
 * @see JitDataFlowUseropLibrary
 */
public record FieldForVarnode(Varnode vn) implements StaticFieldReq {
	@Override
	public String name() {
		Address addr = vn.getAddress();
		return "VARNODE_%s_%s_%s".formatted(addr.getAddressSpace().getName().toUpperCase(),
			Long.toUnsignedString(addr.getOffset(), 16), vn.getSize());
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * Consider the varnode (ram:00400000,4). The code is equivalent to:
	 * 
	 * <pre>
	 * private static final {@link Varnode} VARNODE_ram_400000_4 = {@link JitCompiledPassage#createVarnode(AddressFactory, String, long, int) createVarnode}(ADDRESS_FACTORY, "ram", 0x400000, 4);
	 * </pre>
	 */
	@Override
	public void generateClinitCode(JitCodeGenerator gen, ClassVisitor cv, MethodVisitor sv) {
		cv.visitField(ACC_PRIVATE | ACC_STATIC | ACC_FINAL, name(), TDESC_VARNODE, null, null);

		sv.visitFieldInsn(GETSTATIC, gen.nameThis, "ADDRESS_FACTORY", TDESC_ADDRESS_FACTORY);
		sv.visitLdcInsn(vn.getAddress().getAddressSpace().getName());
		sv.visitLdcInsn(vn.getAddress().getOffset());
		sv.visitLdcInsn(vn.getSize());
		sv.visitMethodInsn(INVOKESTATIC, NAME_JIT_COMPILED_PASSAGE, "createVarnode",
			MDESC_JIT_COMPILED_PASSAGE__CREATE_VARNODE, true);
		sv.visitFieldInsn(PUTSTATIC, gen.nameThis, name(), TDESC_VARNODE);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * To clarify, this <em>does not</em> load a varnode's current value onto the JVM stack. That is
	 * done by {@link VarGen}. This loads a ref to the {@link Varnode} instance. Also, it's not
	 * precisely the same instance as given, but a re-construction of it as a plain {@link Varnode},
	 * i.e., just the (space,offset,size) triple.
	 * 
	 */
	@Override
	public void generateLoadCode(JitCodeGenerator gen, MethodVisitor rv) {
		rv.visitFieldInsn(GETSTATIC, gen.nameThis, name(), TDESC_VARNODE);
	}
}
