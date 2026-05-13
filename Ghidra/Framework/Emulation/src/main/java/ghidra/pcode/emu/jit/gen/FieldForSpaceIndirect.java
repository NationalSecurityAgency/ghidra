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

import static ghidra.pcode.emu.jit.gen.GenConsts.T_JIT_BYTES_PCODE_EXECUTOR_STATE_SPACE;
import static org.objectweb.asm.Opcodes.ACC_FINAL;
import static org.objectweb.asm.Opcodes.ACC_PRIVATE;

import org.objectweb.asm.ClassVisitor;

import ghidra.pcode.emu.jit.JitBytesPcodeExecutorStatePiece.JitBytesPcodeExecutorStateSpace;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage;
import ghidra.pcode.emu.jit.gen.util.*;
import ghidra.pcode.emu.jit.gen.util.Emitter.Ent;
import ghidra.pcode.emu.jit.gen.util.Emitter.Next;
import ghidra.pcode.emu.jit.gen.util.Types.TRef;
import ghidra.program.model.address.AddressSpace;

/**
 * A field request for a pre-fetched {@link JitBytesPcodeExecutorStateSpace}
 * 
 * <p>
 * The field is used for indirect memory accesses. For those, the address space is given in the
 * p-code, but the offset must be computed at run time. Thus, we can pre-fetch the state space, but
 * not any particular page.
 * 
 * @param space the address space of the state space to pre-fetch
 */
public record FieldForSpaceIndirect(AddressSpace space)
		implements InstanceFieldReq<TRef<JitBytesPcodeExecutorStateSpace>> {
	@Override
	public String name() {
		return "spaceInd_" + space.getName();
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * Consider the "ram" space. The declaration is equivalent to:
	 * 
	 * <pre>
	 * private final {@link JitBytesPcodeExecutorStateSpace} spaceInd_ram;
	 * </pre>
	 * 
	 * <p>
	 * And the initialization is equivalent to:
	 * 
	 * <pre>
	 * spaceInd_ram = state.getForSpace(ADDRESS_FACTORY.getAddressSpace(ramId));
	 * </pre>
	 */
	@Override
	public <THIS extends JitCompiledPassage, N extends Next> Emitter<N> genInit(Emitter<N> em,
			Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen, ClassVisitor cv) {
		Fld.decl(cv, ACC_PRIVATE | ACC_FINAL, T_JIT_BYTES_PCODE_EXECUTOR_STATE_SPACE, name());
		return em
				.emit(Op::aload, localThis)
				.emit(gen::genLoadJitStateSpace, localThis, space)
				.emit(Op::putfield, gen.typeThis, name(), T_JIT_BYTES_PCODE_EXECUTOR_STATE_SPACE);
	}

	@Override
	public <THIS extends JitCompiledPassage, N extends Next>
			Emitter<Ent<N, TRef<JitBytesPcodeExecutorStateSpace>>>
			genLoad(Emitter<N> em, Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen) {
		return em
				.emit(Op::aload, localThis)
				.emit(Op::getfield, gen.typeThis, name(), T_JIT_BYTES_PCODE_EXECUTOR_STATE_SPACE);
	}
}
