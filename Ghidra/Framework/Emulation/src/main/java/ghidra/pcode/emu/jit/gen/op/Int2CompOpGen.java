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

import java.util.List;

import org.objectweb.asm.MethodVisitor;

import ghidra.pcode.emu.jit.analysis.JitAllocationModel.JvmTempAlloc;
import ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock;
import ghidra.pcode.emu.jit.analysis.JitType;
import ghidra.pcode.emu.jit.analysis.JitType.*;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.gen.type.TypeConversions;
import ghidra.pcode.emu.jit.gen.type.TypeConversions.Ext;
import ghidra.pcode.emu.jit.op.JitInt2CompOp;

/**
 * The generator for a {@link JitInt2CompOp int_2comp}.
 * 
 * <p>
 * This uses the unary operator generator and emits {@link #INEG} or {@link #LNEG}, depending on
 * type.
 */
public enum Int2CompOpGen implements IntUnOpGen<JitInt2CompOp> {
	/** The generator singleton */
	GEN;

	@Override
	public boolean isSigned() {
		return false; // TODO: Is it? Test with 3-byte operands to figure it out.
	}

	private void generateMpIntLeg2Cmp(int idx, IntJitType type, boolean givesCarry,
			MethodVisitor mv) {
		// [carryN-1:LONG]
		mv.visitVarInsn(ILOAD, idx);
		// [legN:INT,carry:LONG]
		mv.visitLdcInsn(-1 >>> (Integer.SIZE - type.size() * Byte.SIZE));
		// [ff:INT,legN:INT,carry:LONG]
		mv.visitInsn(IXOR);
		// [invN:INT,carry:LONG]
		TypeConversions.generateIntToLong(type, LongJitType.I8, Ext.ZERO, mv);
		// [invN:LONG,carry:LONG]
		mv.visitInsn(LADD);
		// [carry|2cmpN:LONG]
		if (givesCarry) {
			mv.visitInsn(DUP2);
			// [carry|2cmpN:LONG,carry|2cmpN:LONG]
			TypeConversions.generateLongToInt(LongJitType.I8, type, Ext.ZERO, mv);
			// [2cmpN:INT,carry|2cmpN:LONG]
			mv.visitVarInsn(ISTORE, idx);
			// [carry|2cmpN:LONG]
			mv.visitLdcInsn(Integer.SIZE);
			// [32:INT, carry:LONG]
			mv.visitInsn(LUSHR);
			// [carryN:LONG]
		}
		else {
			TypeConversions.generateLongToInt(LongJitType.I8, type, Ext.ZERO, mv);
			// [2cmpN:INT]
			mv.visitVarInsn(ISTORE, idx);
			// []
		}
	}

	private void generateMpInt2Comp(JitCodeGenerator gen, MpIntJitType type, MethodVisitor mv) {
		int legCount = type.legsAlloc();
		try (JvmTempAlloc result = gen.getAllocationModel().allocateTemp(mv, "result", legCount)) {
			OpGen.generateMpLegsIntoTemp(result, legCount, mv);
			List<IntJitType> types = type.legTypes().reversed();
			mv.visitLdcInsn(1L); // Seed the "carry in" with the 1 to add
			for (int i = 0; i < legCount; i++) {
				boolean isLast = i == legCount - 1;
				generateMpIntLeg2Cmp(result.idx(i), types.get(i), !isLast, mv);
			}
			OpGen.generateMpLegsFromTemp(result, legCount, mv);
		}
	}

	@Override
	public JitType generateUnOpRunCode(JitCodeGenerator gen, JitInt2CompOp op, JitBlock block,
			JitType uType, MethodVisitor rv) {
		switch (uType) {
			case IntJitType t -> rv.visitInsn(INEG);
			case LongJitType t -> rv.visitInsn(LNEG);
			case MpIntJitType t -> generateMpInt2Comp(gen, t, rv);
			default -> throw new AssertionError();
		}
		return uType;
	}
}
