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
import ghidra.pcode.emu.jit.op.JitFloatNaNOp;

/**
 * The generator for a {@link JitFloatNaNOp float_nan}.
 * 
 * <p>
 * This uses the unary operator generator and emits an invocation of {@link Float#isNaN(float)} or
 * {@link Double#isNaN(double)}, depending on the type.
 */
public enum FloatNaNOpGen implements UnOpGen<JitFloatNaNOp> {
	/** The generator singleton */
	GEN;

	@Override
	public JitType generateUnOpRunCode(JitCodeGenerator gen, JitFloatNaNOp op, JitBlock block,
			JitType uType, MethodVisitor rv) {
		switch (uType) {
			case FloatJitType t -> rv.visitMethodInsn(INVOKESTATIC, NAME_FLOAT, "isNaN",
				MDESC_FLOAT__IS_NAN, false);
			case DoubleJitType t -> rv.visitMethodInsn(INVOKESTATIC, NAME_DOUBLE, "isNaN",
				MDESC_DOUBLE__IS_NAN, false);
			case MpFloatJitType t -> TODO("MpFloat");
			default -> throw new AssertionError();
		}
		return IntJitType.I4;
	}
}
