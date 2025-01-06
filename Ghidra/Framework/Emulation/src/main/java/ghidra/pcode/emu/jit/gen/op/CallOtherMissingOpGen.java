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
package ghidra.pcode.emu.jit.gen.op;

import static ghidra.pcode.emu.jit.gen.GenConsts.MDESC_SLEIGH_LINK_EXCEPTION__$INIT;
import static ghidra.pcode.emu.jit.gen.GenConsts.NAME_SLEIGH_LINK_EXCEPTION;

import org.objectweb.asm.MethodVisitor;

import ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.op.JitCallOtherMissingOp;
import ghidra.pcode.exec.SleighLinkException;

/**
 * The generator for a {@link JitCallOtherMissingOp callother-missing}.
 * 
 * <p>
 * This emits code to retire the program counter, context, and live variables, then throw a
 * {@link SleighLinkException}.
 */
public enum CallOtherMissingOpGen implements OpGen<JitCallOtherMissingOp> {
	/** The generator singleton */
	GEN;

	@Override
	public void generateRunCode(JitCodeGenerator gen, JitCallOtherMissingOp op, JitBlock block,
			MethodVisitor rv) {
		gen.generatePassageExit(block, () -> {
			rv.visitLdcInsn(gen.getAddressForOp(op.op()).getOffset());
		}, gen.getExitContext(op.op()), rv);

		String message = gen.getErrorMessage(op.op());
		// [...]
		rv.visitTypeInsn(NEW, NAME_SLEIGH_LINK_EXCEPTION);
		// [...,error:NEW]
		rv.visitInsn(DUP);
		// [...,error:NEW,error:NEW]
		rv.visitLdcInsn(message);
		// [...,error:NEW,error:NEW,message]
		rv.visitMethodInsn(INVOKESPECIAL, NAME_SLEIGH_LINK_EXCEPTION, "<init>",
			MDESC_SLEIGH_LINK_EXCEPTION__$INIT, false);
		// [...,error]
		rv.visitInsn(ATHROW);
	}
}
