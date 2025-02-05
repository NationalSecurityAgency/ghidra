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

import static ghidra.lifecycle.Unfinished.TODO;
import static ghidra.pcode.emu.jit.gen.GenConsts.*;

import org.objectweb.asm.MethodVisitor;

import ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock;
import ghidra.pcode.emu.jit.analysis.JitType;
import ghidra.pcode.emu.jit.analysis.JitType.*;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.op.JitFloatAbsOp;

/**
 * The generator for a {@link JitFloatAbsOp float_abs}.
 * 
 * <p>
 * This uses the unary operator generator and emits an invocation of {@link Math#abs(float)} or
 * {@link Math#abs(double)}, depending on the type.
 */
public enum FloatAbsOpGen implements UnOpGen<JitFloatAbsOp> {
	/** The generator singleton */
	GEN;

	@Override
	public JitType generateUnOpRunCode(JitCodeGenerator gen, JitFloatAbsOp op, JitBlock block,
			JitType uType, MethodVisitor rv) {
		switch (uType) {
			case FloatJitType t -> rv.visitMethodInsn(INVOKESTATIC, NAME_MATH, "abs",
				MDESC_$FLOAT_UNOP, false);
			case DoubleJitType t -> rv.visitMethodInsn(INVOKESTATIC, NAME_MATH, "abs",
				MDESC_$DOUBLE_UNOP, false);
			case MpFloatJitType t -> TODO("MpFloat");
			default -> throw new AssertionError();
		}
		return uType;
	}
}
