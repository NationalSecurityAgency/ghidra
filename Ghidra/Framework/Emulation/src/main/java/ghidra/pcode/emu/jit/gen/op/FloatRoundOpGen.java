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
import ghidra.pcode.emu.jit.op.JitFloatRoundOp;

/**
 * The generator for a {@link JitFloatRoundOp float_round}.
 * 
 * <p>
 * The JVM does provide a {@link Math#round(float)} method, however it returns an int. (It has
 * similar for doubles with the same problem.) That would be suitable if a type conversion were also
 * desired, but that is not the case. Thus, we construct a rounding function without conversion:
 * {@code round(x) = floor(x + 0.5)}. This uses the unary operator generator and emits the bytecode
 * to implement that definition, applying type conversions as needed.
 */
public enum FloatRoundOpGen implements UnOpGen<JitFloatRoundOp> {
	/** The generator singleton */
	GEN;

	@Override
	public JitType generateUnOpRunCode(JitCodeGenerator gen, JitFloatRoundOp op, JitBlock block,
			JitType uType, MethodVisitor rv) {
		switch (uType) {
			// Math.round also converts to int/long
			case FloatJitType t -> {
				rv.visitLdcInsn(0.5f);
				rv.visitInsn(FADD);
				rv.visitInsn(F2D);
				rv.visitMethodInsn(INVOKESTATIC, NAME_MATH, "floor", MDESC_$DOUBLE_UNOP, false);
				rv.visitInsn(D2F);
			}
			case DoubleJitType t -> {
				rv.visitLdcInsn(0.5d);
				rv.visitInsn(DADD);
				rv.visitMethodInsn(INVOKESTATIC, NAME_MATH, "floor", MDESC_$DOUBLE_UNOP, false);
			}
			case MpFloatJitType t -> TODO("MpFloat");
			default -> throw new AssertionError();
		}
		return uType;
	}
}
