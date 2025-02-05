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
package ghidra.pcode.emu.jit.gen.var;

import static ghidra.pcode.emu.jit.gen.GenConsts.MDESC_ASSERTION_ERROR__$INIT;
import static ghidra.pcode.emu.jit.gen.GenConsts.NAME_ASSERTION_ERROR;
import static org.objectweb.asm.Opcodes.*;

import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import ghidra.pcode.emu.jit.analysis.JitType;
import ghidra.pcode.emu.jit.analysis.JitTypeBehavior;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.op.JitPhiOp;
import ghidra.pcode.emu.jit.var.JitMissingVar;

/**
 * The generator for a missing (local) variable.
 * 
 * <p>
 * In principle, a {@link JitMissingVar} should never show up in the use-def graph, since they
 * should all be replaced by {@link JitPhiOp phi} outputs. We can be certain these should never show
 * up as an output, so we prohibit any attempt to generate code that writes to a missing variable.
 * However, we wait until run time to make that assertion about reads. In theory, it's possible the
 * generator will generate unreachable code that reads from a variable; however, that code is
 * unreachable. First how does this happen? Second, what if it does?
 * 
 * <p>
 * To answer the first question, we note that the passage decoder should never decode any statically
 * unreachable instructions. However, the p-code emitted by those instructions may technically
 * contain unreachable ops.
 * 
 * <p>
 * To answer the second, we note that the ASM library has a built-in control-flow analyzer, and it
 * ought to detect the unreachable code. In my observation, it replaces that code with
 * {@link Opcodes#NOP nop} and/or {@link Opcodes#ATHROW athrow}. Still, in case it doesn't, or in
 * case something changes in a later version (or if/when we port this to the JDK's upcoming
 * classfile API), we emit our own bytecode to throw an {@link AssertionError}.
 */
public enum MissingVarGen implements VarGen<JitMissingVar> {
	/** Singleton */
	GEN;

	@Override
	public void generateValInitCode(JitCodeGenerator gen, JitMissingVar v, MethodVisitor iv) {
	}

	@Override
	public JitType generateValReadCode(JitCodeGenerator gen, JitMissingVar v,
			JitTypeBehavior typeReq, MethodVisitor rv) {
		// [...]
		rv.visitTypeInsn(NEW, NAME_ASSERTION_ERROR);
		// [...,error:NEW]
		rv.visitInsn(DUP);
		// [...,error:NEW,error:NEW]
		rv.visitLdcInsn("Tried to read " + v);
		// [...,error:NEW,error:NEW,message]
		rv.visitMethodInsn(INVOKESPECIAL, NAME_ASSERTION_ERROR, "<init>",
			MDESC_ASSERTION_ERROR__$INIT, false);
		// [...,error]
		rv.visitInsn(ATHROW);
		// [...]
		JitType type = typeReq.resolve(gen.getTypeModel().typeOf(v));
		return type;
	}

	@Override
	public void generateVarWriteCode(JitCodeGenerator gen, JitMissingVar v, JitType type,
			MethodVisitor rv) {
		throw new AssertionError();
	}
}
