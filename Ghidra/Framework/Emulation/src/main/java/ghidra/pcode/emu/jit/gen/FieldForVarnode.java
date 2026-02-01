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

import ghidra.pcode.emu.jit.analysis.JitDataFlowUseropLibrary;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage;
import ghidra.pcode.emu.jit.gen.util.*;
import ghidra.pcode.emu.jit.gen.util.Emitter.Ent;
import ghidra.pcode.emu.jit.gen.util.Emitter.Next;
import ghidra.pcode.emu.jit.gen.util.Methods.Inv;
import ghidra.pcode.emu.jit.gen.util.Types.TRef;
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
public record FieldForVarnode(Varnode vn) implements StaticFieldReq<TRef<Varnode>> {
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
	public <N extends Next> Emitter<N> genClInitCode(Emitter<N> em, JitCodeGenerator<?> gen,
			ClassVisitor cv) {
		Fld.decl(cv, ACC_PRIVATE | ACC_STATIC | ACC_FINAL, T_VARNODE, name());
		return em
				.emit(Op::getstatic, gen.typeThis, "ADDRESS_FACTORY", T_ADDRESS_FACTORY)
				.emit(Op::ldc__a, vn.getAddress().getAddressSpace().getName())
				.emit(Op::ldc__l, vn.getAddress().getOffset())
				.emit(Op::ldc__i, vn.getSize())
				.emit(Op::invokestatic, T_JIT_COMPILED_PASSAGE, "createVarnode",
					MDESC_JIT_COMPILED_PASSAGE__CREATE_VARNODE, true)
				.step(Inv::takeArg)
				.step(Inv::takeArg)
				.step(Inv::takeArg)
				.step(Inv::takeArg)
				.step(Inv::ret)
				.emit(Op::putstatic, gen.typeThis, name(), T_VARNODE);
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
	public <N extends Next> Emitter<Ent<N, TRef<Varnode>>> genLoad(Emitter<N> em,
			JitCodeGenerator<?> gen) {
		return em
				.emit(Op::getstatic, gen.typeThis, name(), T_VARNODE);
	}
}
