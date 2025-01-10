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
import ghidra.pcode.emu.jit.gen.type.TypeConversions;
import ghidra.pcode.emu.jit.op.JitIntSExtOp;

/**
 * The generator for a {@link JitIntSExtOp int_sext}.
 * 
 * <p>
 * We implement this using a left then signed-right shift. This uses the unary operator generator
 * and emits {@link #ISHL} and {@link #ISHR} or {@link #LSHL} and {@link #LSHR}, depending on type.
 * Additional type conversions may be emitted first. As a special case, sign extension from
 * {@link IntJitType#I4 int4} to {@link LongJitType#I8 int8} is implemented with by emitting only
 * {@link #I2L}.
 */
public enum IntSExtOpGen implements UnOpGen<JitIntSExtOp> {
	/** The generator singleton */
	GEN;

	@Override
	public JitType generateUnOpRunCode(JitCodeGenerator gen, JitIntSExtOp op, JitBlock block,
			JitType uType, MethodVisitor rv) {
		JitType outType = op.type().resolve(gen.getTypeModel().typeOf(op.out()));

		if (uType == IntJitType.I4 && outType == LongJitType.I8) {
			rv.visitInsn(I2L);
			return outType;
		}

		TypeConversions.generate(gen, uType, outType, rv);
		switch (outType) {
			case IntJitType t -> {
				int shamt = Integer.SIZE - op.u().size() * Byte.SIZE;
				if (shamt != 0) {
					rv.visitLdcInsn(shamt);
					rv.visitInsn(ISHL);
					rv.visitLdcInsn(shamt);
					rv.visitInsn(ISHR);
				}
			}
			case LongJitType t -> {
				int shamt = Long.SIZE - op.u().size() * Byte.SIZE;
				if (shamt != 0) {
					rv.visitLdcInsn(shamt);
					rv.visitInsn(LSHL);
					rv.visitLdcInsn(shamt);
					rv.visitInsn(LSHR);
				}
			}
			case MpIntJitType t -> Unfinished.TODO("MpInt");
			default -> throw new AssertionError();
		}
		return outType;
	}
}
