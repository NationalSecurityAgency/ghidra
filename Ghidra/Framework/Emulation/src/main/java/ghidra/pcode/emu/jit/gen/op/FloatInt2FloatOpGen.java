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

import org.objectweb.asm.MethodVisitor;

import ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock;
import ghidra.pcode.emu.jit.analysis.JitType;
import ghidra.pcode.emu.jit.analysis.JitType.*;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.op.JitFloatInt2FloatOp;

/**
 * The generator for a {@link JitFloatInt2FloatOp float_int2float}.
 * 
 * <p>
 * This uses the unary operator generator and emits {@link #I2F}, {@link #I2D}, {@link #L2F}, or
 * {@link #L2D}.
 */
public enum FloatInt2FloatOpGen implements UnOpGen<JitFloatInt2FloatOp> {
	/** The generator singleton */
	GEN;

	private JitType gen(MethodVisitor rv, int opcode, JitType type) {
		rv.visitInsn(opcode);
		return type;
	}

	@Override
	public JitType generateUnOpRunCode(JitCodeGenerator gen, JitFloatInt2FloatOp op, JitBlock block,
			JitType uType, MethodVisitor rv) {
		JitType outType = op.type().resolve(gen.getTypeModel().typeOf(op.out()));
		return switch (uType) {
			case IntJitType ut -> switch (outType) {
				case FloatJitType ot -> gen(rv, I2F, ot);
				case DoubleJitType ot -> gen(rv, I2D, ot);
				case MpFloatJitType ot -> TODO("MpInt/Float");
				default -> throw new AssertionError();
			};
			case LongJitType ut -> switch (outType) {
				case FloatJitType ot -> gen(rv, L2F, ot);
				case DoubleJitType ot -> gen(rv, L2D, ot);
				case MpFloatJitType ot -> TODO("MpInt/Float");
				default -> throw new AssertionError();
			};
			case MpIntJitType ut -> TODO("MpInt/Float");
			default -> throw new AssertionError();
		};
	}
}
