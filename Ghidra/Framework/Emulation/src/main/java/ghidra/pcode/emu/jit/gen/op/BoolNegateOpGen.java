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
import ghidra.pcode.emu.jit.op.JitBoolNegateOp;
import ghidra.pcode.opbehavior.OpBehaviorBoolNegate;

/**
 * The generator for a {@link JitBoolNegateOp bool_negate}.
 * 
 * @implNote It is the responsibility of the slaspec author to ensure boolean values are 0 or 1.
 *           This allows us to use bitwise logic instead of having to check for any non-zero value,
 *           just like {@link OpBehaviorBoolNegate}.
 */
public enum BoolNegateOpGen implements UnOpGen<JitBoolNegateOp> {
	/** The generator singleton */
	GEN;

	@Override
	public JitType generateUnOpRunCode(JitCodeGenerator gen, JitBoolNegateOp op, JitBlock block,
			JitType uType, MethodVisitor rv) {
		switch (uType) {
			case IntJitType t -> {
				rv.visitLdcInsn(1);
				rv.visitInsn(IXOR);
			}
			case LongJitType t -> {
				rv.visitLdcInsn(1L);
				rv.visitInsn(LXOR);
			}
			case MpIntJitType t -> Unfinished.TODO("MpInt");
			default -> throw new AssertionError();
		}
		return uType;
	}
}
