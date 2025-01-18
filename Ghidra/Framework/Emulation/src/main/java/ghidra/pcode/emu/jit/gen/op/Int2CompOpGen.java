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

import org.objectweb.asm.MethodVisitor;

import ghidra.lifecycle.Unfinished;
import ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock;
import ghidra.pcode.emu.jit.analysis.JitType;
import ghidra.pcode.emu.jit.analysis.JitType.*;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.op.JitInt2CompOp;

/**
 * The generator for a {@link JitInt2CompOp int_2comp}.
 * 
 * <p>
 * This uses the unary operator generator and emits {@link #INEG} or {@link #LNEG}, depending on
 * type.
 */
public enum Int2CompOpGen implements UnOpGen<JitInt2CompOp> {
	/** The generator singleton */
	GEN;

	@Override
	public JitType generateUnOpRunCode(JitCodeGenerator gen, JitInt2CompOp op, JitBlock block,
			JitType uType, MethodVisitor rv) {
		switch (uType) {
			case IntJitType t -> rv.visitInsn(INEG);
			case LongJitType t -> rv.visitInsn(LNEG);
			case MpIntJitType t -> Unfinished.TODO("MpInt");
			default -> throw new AssertionError();
		}
		return uType;
	}
}
