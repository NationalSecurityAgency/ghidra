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
import static ghidra.pcode.emu.jit.gen.GenConsts.MDESC_$DOUBLE_UNOP;
import static ghidra.pcode.emu.jit.gen.GenConsts.NAME_MATH;

import org.objectweb.asm.MethodVisitor;

import ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock;
import ghidra.pcode.emu.jit.analysis.JitType;
import ghidra.pcode.emu.jit.analysis.JitType.*;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.op.JitFloatFloorOp;

/**
 * The generator for a {@link JitFloatFloorOp float_floor}.
 * 
 * <p>
 * This uses the unary operator generator and emits an invocation of {@link Math#floor(double)},
 * possibly surrounding it with conversions from and to float.
 */
public enum FloatFloorOpGen implements UnOpGen<JitFloatFloorOp> {
	/** The generator singleton */
	GEN;

	@Override
	public JitType generateUnOpRunCode(JitCodeGenerator gen, JitFloatFloorOp op, JitBlock block,
			JitType uType, MethodVisitor rv) {
		switch (uType) {
			case FloatJitType t -> {
				// There apparently is no Math.floor(float)???
				rv.visitInsn(F2D);
				rv.visitMethodInsn(INVOKESTATIC, NAME_MATH, "floor", MDESC_$DOUBLE_UNOP, false);
				rv.visitInsn(D2F);
			}
			case DoubleJitType t -> rv.visitMethodInsn(INVOKESTATIC, NAME_MATH, "floor",
				MDESC_$DOUBLE_UNOP, false);
			case MpFloatJitType t -> TODO("MpFloat");
			default -> throw new AssertionError();
		}
		return uType;
	}
}
