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

import static ghidra.pcode.emu.jit.gen.GenConsts.*;

import org.objectweb.asm.MethodVisitor;

import ghidra.pcode.emu.jit.JitPassage.DecodeErrorPcodeOp;
import ghidra.pcode.emu.jit.analysis.JitAllocationModel.RunFixedLocal;
import ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage;
import ghidra.pcode.emu.jit.op.JitUnimplementedOp;
import ghidra.pcode.error.LowlevelError;
import ghidra.pcode.exec.DecodePcodeExecutionException;

/**
 * The generator for a {@link JitUnimplementedOp unimplemented}.
 * 
 * <p>
 * This emits code to retire the program counter, context, and live variables, then throw a
 * {@link DecodePcodeExecutionException} or {@link LowlevelError}. The former case is constructed by
 * {@link JitCompiledPassage#createDecodeError(String, long)}.
 */
public enum UnimplementedOpGen implements OpGen<JitUnimplementedOp> {
	/** The generator singleton */
	GEN;

	@Override
	public void generateRunCode(JitCodeGenerator gen, JitUnimplementedOp op, JitBlock block,
			MethodVisitor rv) {
		long counter = gen.getAddressForOp(op.op()).getOffset();

		gen.generatePassageExit(block, () -> {
			rv.visitLdcInsn(counter);
		}, gen.getExitContext(op.op()), rv);

		String message = gen.getErrorMessage(op.op());
		if (op.op() instanceof DecodeErrorPcodeOp) {
			RunFixedLocal.THIS.generateLoadCode(rv);
			rv.visitLdcInsn(message);
			rv.visitLdcInsn(counter);
			rv.visitMethodInsn(INVOKEINTERFACE, NAME_JIT_COMPILED_PASSAGE, "createDecodeError",
				MDESC_JIT_COMPILED_PASSAGE__CREATE_DECODE_ERROR, true);
			rv.visitInsn(ATHROW);
		}
		else {
			// [...]
			rv.visitTypeInsn(NEW, NAME_LOW_LEVEL_ERROR);
			// [...,error:NEW]
			rv.visitInsn(DUP);
			// [...,error:NEW,error:NEW]
			rv.visitLdcInsn(message);
			// [...,error:NEW,error:NEW,message]
			rv.visitMethodInsn(INVOKESPECIAL, NAME_LOW_LEVEL_ERROR, "<init>",
				MDESC_LOW_LEVEL_ERROR__$INIT, false);
			// [...,error]
			rv.visitInsn(ATHROW);
		}
	}
}
