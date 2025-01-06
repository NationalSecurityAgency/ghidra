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
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage;
import ghidra.pcode.emu.jit.gen.type.TypeConversions;
import ghidra.pcode.emu.jit.op.JitIntSCarryOp;

/**
 * The generator for a {@link JitIntSCarryOp int_scarry}.
 * 
 * <p>
 * This uses the binary operator generator and emits {@link #INVOKESTATIC} on
 * {@link JitCompiledPassage#sCarryIntRaw(int, int)} or
 * {@link JitCompiledPassage#sCarryLongRaw(long, long)} depending on the type. We must then emit a
 * shift and mask to extract the correct bit.
 */
public enum IntSCarryOpGen implements BinOpGen<JitIntSCarryOp> {
	/** The generator singleton */
	GEN;

	@Override
	public JitType afterLeft(JitCodeGenerator gen, JitIntSCarryOp op, JitType lType, JitType rType,
			MethodVisitor rv) {
		return TypeConversions.forceUniformSExt(lType, rType, rv);
	}

	@Override
	public JitType generateBinOpRunCode(JitCodeGenerator gen, JitIntSCarryOp op, JitBlock block,
			JitType lType, JitType rType, MethodVisitor rv) {
		rType = TypeConversions.forceUniformSExt(rType, lType, rv);
		switch (rType) {
			case IntJitType(int size) -> {
				rv.visitMethodInsn(INVOKESTATIC, NAME_JIT_COMPILED_PASSAGE, "sCarryIntRaw",
					MDESC_JIT_COMPILED_PASSAGE__S_CARRY_INT_RAW, true);
				rv.visitLdcInsn(size * Byte.SIZE - 1);
				rv.visitInsn(ISHR);
				// TODO: This mask may not be necessary
				rv.visitLdcInsn(1);
				rv.visitInsn(IAND);
				return IntJitType.I1;
			}
			case LongJitType(int size) -> {
				rv.visitMethodInsn(INVOKESTATIC, NAME_JIT_COMPILED_PASSAGE, "sCarryLongRaw",
					MDESC_JIT_COMPILED_PASSAGE__S_CARRY_LONG_RAW, true);
				rv.visitLdcInsn(size * Byte.SIZE - 1);
				rv.visitInsn(LSHR);
				rv.visitInsn(L2I);
				// TODO: This mask may not be necessary
				rv.visitLdcInsn(1);
				rv.visitInsn(IAND);
				return IntJitType.I1;
			}
			case MpIntJitType t -> {
				return TODO("MpInt");
			}
			default -> throw new AssertionError();
		}
	}
}
