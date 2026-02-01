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
import static org.objectweb.asm.Opcodes.ACC_FINAL;
import static org.objectweb.asm.Opcodes.ACC_PRIVATE;

import org.objectweb.asm.ClassVisitor;

import ghidra.pcode.emu.jit.analysis.JitDataFlowUseropLibrary;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage;
import ghidra.pcode.emu.jit.gen.util.*;
import ghidra.pcode.emu.jit.gen.util.Emitter.Ent;
import ghidra.pcode.emu.jit.gen.util.Emitter.Next;
import ghidra.pcode.emu.jit.gen.util.Methods.Inv;
import ghidra.pcode.emu.jit.gen.util.Types.TRef;
import ghidra.pcode.exec.PcodeUseropLibrary.PcodeUseropDefinition;

/**
 * A field request for a pre-fetched userop definition
 * 
 * <p>
 * These are used to invoke userops using the Standard or Direct strategies.
 * 
 * @param userop the definition to pre-fetch
 * @see JitDataFlowUseropLibrary
 */
public record FieldForUserop(PcodeUseropDefinition<byte[]> userop)
		implements InstanceFieldReq<TRef<PcodeUseropDefinition<byte[]>>> {
	@Override
	public String name() {
		return "userop_" + userop.getName();
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * Consider the userop {@code syscall()}. The declaration is equivalent to:
	 * 
	 * <pre>
	 * private final {@link PcodeUseropDefinition} userop_syscall;
	 * </pre>
	 * 
	 * <p>
	 * And the initialization is equivalent to:
	 * 
	 * <pre>
	 * userop_syscall = {@link JitCompiledPassage#getUseropDefinition(String) getUseropdDefinition}("syscall");
	 * </pre>
	 */
	@Override
	public <THIS extends JitCompiledPassage, N extends Next> Emitter<N> genInit(Emitter<N> em,
			Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen, ClassVisitor cv) {
		Fld.decl(cv, ACC_PRIVATE | ACC_FINAL, T_PCODE_USEROP_DEFINITION, name());
		return em
				.emit(Op::aload, localThis)
				.emit(Op::dup)
				.emit(Op::ldc__a, userop.getName())
				.emit(Op::invokeinterface, T_JIT_COMPILED_PASSAGE, "getUseropDefinition",
					MDESC_JIT_COMPILED_PASSAGE__GET_USEROP_DEFINITION)
				.step(Inv::takeArg)
				.step(Inv::takeObjRef)
				.step(Inv::ret)
				.emit(Op::putfield, gen.typeThis, name(), T_PCODE_USEROP_DEFINITION);
	}

	@Override
	public <THIS extends JitCompiledPassage, N extends Next>
			Emitter<Ent<N, TRef<PcodeUseropDefinition<byte[]>>>>
			genLoad(Emitter<N> em, Local<TRef<THIS>> localThis, JitCodeGenerator<THIS> gen) {
		return em
				.emit(Op::aload, localThis)
				.emit(Op::getfield, gen.typeThis, name(), T_PCODE_USEROP_DEFINITION__BYTEARR);
	}
}
