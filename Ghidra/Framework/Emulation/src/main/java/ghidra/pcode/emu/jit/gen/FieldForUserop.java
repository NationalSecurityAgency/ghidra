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
public record FieldForUserop(PcodeUseropDefinition<?> userop) implements InstanceFieldReq {
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
	public void generateInitCode(JitCodeGenerator gen, ClassVisitor cv, MethodVisitor iv) {
		cv.visitField(ACC_PRIVATE | ACC_FINAL, name(), TDESC_PCODE_USEROP_DEFINITION, null,
			null);

		// []
		iv.visitVarInsn(ALOAD, 0);
		// [this]
		iv.visitInsn(DUP);
		// [this,this]
		iv.visitLdcInsn(userop.getName());
		// [this,this,name]
		iv.visitMethodInsn(INVOKEINTERFACE, NAME_JIT_COMPILED_PASSAGE, "getUseropDefinition",
			MDESC_JIT_COMPILED_PASSAGE__GET_USEROP_DEFINITION, true);
		// [this,userop]
		iv.visitFieldInsn(PUTFIELD, gen.nameThis, name(), TDESC_PCODE_USEROP_DEFINITION);
		// []
	}

	@Override
	public void generateLoadCode(JitCodeGenerator gen, MethodVisitor rv) {
		// []
		rv.visitVarInsn(ALOAD, 0);
		// [this]
		rv.visitFieldInsn(GETFIELD, gen.nameThis, name(), TDESC_PCODE_USEROP_DEFINITION);
		// [userop]
	}
}
