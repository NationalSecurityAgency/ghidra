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

import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.RegisterValue;

/**
 * A field request for pre-constructed contextreg value
 */
record FieldForContext(RegisterValue ctx) implements StaticFieldReq {
	@Override
	public String name() {
		return "CTX_%s".formatted(ctx.getUnsignedValue().toString(16));
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * Consider the context value 0x80000000. The code is equivalent to:
	 * 
	 * <pre>
	 * private static final {@link RegisterValue} CTX_80000000 = {@link JitCompiledPassage#createContext(Language, String) createContext}(LANGUAGE, "80000000");
	 * </pre>
	 */
	@Override
	public void generateClinitCode(JitCodeGenerator gen, ClassVisitor cv, MethodVisitor sv) {
		if (ctx == null) {
			return;
		}
		cv.visitField(ACC_PRIVATE | ACC_STATIC | ACC_FINAL, name(), TDESC_REGISTER_VALUE, null,
			null);

		// []
		sv.visitFieldInsn(GETSTATIC, gen.nameThis, "LANGUAGE", TDESC_LANGUAGE);
		// [language]
		sv.visitLdcInsn(ctx.getUnsignedValue().toString(16));
		// [language,ctx:STR]
		sv.visitMethodInsn(INVOKESTATIC, NAME_JIT_COMPILED_PASSAGE, "createContext",
			MDESC_JIT_COMPILED_PASSAGE__CREATE_CONTEXT, true);
		// [ctx:RV]
		sv.visitFieldInsn(PUTSTATIC, gen.nameThis, name(), TDESC_REGISTER_VALUE);
	}

	@Override
	public void generateLoadCode(JitCodeGenerator gen, MethodVisitor rv) {
		// [...]
		if (ctx == null) {
			rv.visitInsn(ACONST_NULL);
		}
		else {
			rv.visitFieldInsn(GETSTATIC, gen.nameThis, name(), TDESC_REGISTER_VALUE);
		}
		// [...,ctx]
	}
}
