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

import static ghidra.pcode.emu.jit.gen.GenConsts.*;

import org.bouncycastle.util.Bytes;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;

import ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock;
import ghidra.pcode.emu.jit.analysis.JitType;
import ghidra.pcode.emu.jit.analysis.JitType.*;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.op.JitLzCountOp;

/**
 * The generator for a {@link JitLzCountOp lzcount}.
 * 
 * <p>
 * This uses the unary operator generator and emits an invocation of
 * {@link Integer#numberOfLeadingZeros(int)} or {@link Long#numberOfLeadingZeros(long)}, depending
 * on the type.
 */
public enum LzCountOpGen implements IntUnOpGen<JitLzCountOp> {
	/** The generator singleton */
	GEN;

	@Override
	public boolean isSigned() {
		/**
		 * We use zero extension and then, when there is slack, we subtract off the zero bits that
		 * came from the extension.
		 */
		return false;
	}

	private void generateMpIntLzCount(JitCodeGenerator gen, MpIntJitType type, MethodVisitor mv) {
		// [leg1:INT,...,legN:INT]
		mv.visitMethodInsn(INVOKESTATIC, NAME_INTEGER, "numberOfLeadingZeros",
			MDESC_INTEGER__NUMBER_OF_LEADING_ZEROS, false);
		// [lzc1:INT,leg2:INT,...,legN:INT]
		for (int i = 1; i < type.legsAlloc(); i++) {
			mv.visitInsn(SWAP);
			// [leg2:INT,lzc1:INT,...,legN:INT]
			mv.visitMethodInsn(INVOKESTATIC, NAME_INTEGER, "numberOfLeadingZeros",
				MDESC_INTEGER__NUMBER_OF_LEADING_ZEROS, false);
			// [lzc2:INT,lzc1:INT,...,legN:INT]

			Label lblAdd = new Label();
			Label lblNext = new Label();
			mv.visitInsn(DUP);
			mv.visitLdcInsn(Integer.SIZE);
			mv.visitJumpInsn(IF_ICMPEQ, lblAdd);
			// [lzc2:INT,lzc1:INT,...,legN:INT]
			mv.visitInsn(SWAP);
			mv.visitInsn(POP);
			// [lzc2:INT,...,legN:INT]
			mv.visitJumpInsn(GOTO, lblNext);
			mv.visitLabel(lblAdd);
			// [lzc2:INT,lzc1:INT,...,legN:INT]
			mv.visitInsn(IADD);
			// [lzc2+lzc1:INT,...,legN:INT]
			mv.visitLabel(lblNext);
			// [lzcT:INT,...,legN:INT]
		}

		SimpleJitType mslType = type.legTypes().get(0);
		if (mslType.size() < Integer.BYTES) {
			mv.visitLdcInsn(Integer.SIZE - mslType.size() * Byte.SIZE);
			mv.visitInsn(ISUB);
		}
	}

	@Override
	public JitType generateUnOpRunCode(JitCodeGenerator gen, JitLzCountOp op, JitBlock block,
			JitType uType, MethodVisitor rv) {
		switch (uType) {
			case IntJitType t -> {
				rv.visitMethodInsn(INVOKESTATIC, NAME_INTEGER, "numberOfLeadingZeros",
					MDESC_INTEGER__NUMBER_OF_LEADING_ZEROS, false);
				if (t.size() < Integer.BYTES) {
					rv.visitLdcInsn(Integer.SIZE - t.size() * Byte.SIZE);
					rv.visitInsn(ISUB);
				}
			}
			case LongJitType t -> {
				rv.visitMethodInsn(INVOKESTATIC, NAME_LONG, "numberOfLeadingZeros",
					MDESC_LONG__NUMBER_OF_LEADING_ZEROS, false);
				if (t.size() < Long.BYTES) {
					rv.visitLdcInsn(Long.SIZE - t.size() * Bytes.SIZE);
					rv.visitInsn(ISUB);
				}
			}
			case MpIntJitType t -> generateMpIntLzCount(gen, t, rv);
			default -> throw new AssertionError();
		}
		return IntJitType.I4;
	}
}
