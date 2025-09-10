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

import ghidra.pcode.emu.jit.analysis.JitAllocationModel;
import ghidra.pcode.emu.jit.analysis.JitAllocationModel.JvmTempAlloc;
import ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock;
import ghidra.pcode.emu.jit.analysis.JitType;
import ghidra.pcode.emu.jit.analysis.JitType.*;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.gen.type.TypeConversions.Ext;
import ghidra.pcode.emu.jit.op.JitSubPieceOp;

/**
 * The generator for a {@link JitSubPieceOp subpiece}.
 * 
 * <p>
 * NOTE: The multi-precision int parts of this are a work in progress.
 * 
 * <p>
 * This is not quite like a normal binary operator, because the second operand is always a constant.
 * It behaves more like a class of unary operators, if you ask me. Thus, we do not extend
 * {@link BinOpGen}. We first emit code to load the operand. Then, because the shift amount is
 * constant, we can deal with it at <em>generation time</em>. We emit code to shift right by that
 * constant amount, accounting for bits and bytes. The masking, if required, is taken care of by the
 * variable writing code, given the resulting type.
 */
public enum SubPieceOpGen implements OpGen<JitSubPieceOp> {
	/** The generator singleton */
	GEN;

	/**
	 * <b>Assumes the next-more-significant leg (i.e., the one from the previous iteration) is on
	 * the stack and the current (unshifted) leg is in the given variable. Computes the resulting
	 * output leg and puts in into the given local variable, but leaves a copy of the current
	 * unshifted leg on the stack.
	 * 
	 * @param rv the method visitor
	 * @param bitShift the number of <em>bits</em> to shift
	 * @param index the index of the local variable for the current leg
	 * @implNote This <em>cannot</em> yet be factored with the shifting operators, because those
	 *           take a variable for the shift amount. The subpiece offset is always constant.
	 *           If/when we optimize shift operators with constant shift amounts, then we can
	 *           consider factoring the common parts with this.
	 */
	private static void generateShiftWithPrevLeg(MethodVisitor rv, int bitShift, int index) {
		// [...,prevLegIn]
		rv.visitLdcInsn(Integer.SIZE - bitShift);
		rv.visitInsn(ISHL);
		// [...,prevLegIn:SLACK]
		rv.visitVarInsn(ILOAD, index);
		// [...,prevLegIn:SLACK,legIn]
		rv.visitInsn(DUP_X1);
		// [...,legIn,prevLegIn:SLACK,legIn]
		rv.visitLdcInsn(bitShift);
		rv.visitInsn(IUSHR);
		// [...,legIn,prevLegIn:SLACK,legIn:SHIFT]
		rv.visitInsn(IOR);
		// [...,legIn,legOut]
		rv.visitVarInsn(ISTORE, index);
		// [...,legIn]
	}

	private static MpIntJitType generateMpIntSubPiece(JitCodeGenerator gen, JitSubPieceOp op,
			MpIntJitType type, MethodVisitor mv) {
		MpIntJitType outMpType = MpIntJitType.forSize(op.out().size());
		int outLegCount = outMpType.legsAlloc();
		int legsLeft = type.legsAlloc();
		int popCount = op.offset() / Integer.BYTES;
		int byteShift = op.offset() % Integer.BYTES;
		for (int i = 0; i < popCount; i++) {
			mv.visitInsn(POP);
			legsLeft--;
		}

		JitAllocationModel am = gen.getAllocationModel();
		try (JvmTempAlloc subpieces = am.allocateTemp(mv, "subpiece", outLegCount)) {
			for (int i = 0; i < outLegCount; i++) {
				mv.visitVarInsn(ISTORE, subpieces.idx(i));
				// NOTE: More significant legs have higher indices (reverse of stack)
				legsLeft--;
			}

			if (byteShift > 0) {
				int curLeg = outLegCount - 1;
				if (legsLeft > 0) {
					// [...,prevLegIn]
					generateShiftWithPrevLeg(mv, byteShift * Byte.SIZE, subpieces.idx(curLeg));
					// [...,legIn]
					legsLeft--;
					curLeg--;
				}
				else {
					// [...]
					mv.visitVarInsn(ILOAD, subpieces.idx(curLeg));
					// [...,legIn]
					mv.visitInsn(DUP);
					// [...,legIn,legIn]
					mv.visitLdcInsn(byteShift * Byte.SIZE);
					mv.visitInsn(IUSHR);
					// [...,legIn,legOut]
					mv.visitVarInsn(ISTORE, subpieces.idx(curLeg));
					// [...,legIn]
					curLeg--;
				}
				while (curLeg >= 0) {
					generateShiftWithPrevLeg(mv, byteShift * Byte.SIZE, subpieces.idx(curLeg));
					legsLeft--;
					curLeg--;
				}
			}
			while (legsLeft > 0) {
				mv.visitInsn(POP);
				legsLeft--;
			}
			// NOTE: More significant legs have higher indices
			for (int i = outLegCount - 1; i >= 0; i--) {
				mv.visitVarInsn(ILOAD, subpieces.idx(i));
			}
		}
		return outMpType;
	}

	@Override
	public void generateRunCode(JitCodeGenerator gen, JitSubPieceOp op, JitBlock block,
			MethodVisitor rv) {
		JitType vType = gen.generateValReadCode(op.u(), op.uType(), Ext.ZERO);
		JitType outType = switch (vType) {
			case IntJitType vIType -> {
				rv.visitLdcInsn(op.offset() * Byte.SIZE);
				rv.visitInsn(IUSHR);
				yield vIType;
			}
			case LongJitType vLType -> {
				rv.visitLdcInsn(op.offset() * Byte.SIZE);
				rv.visitInsn(LUSHR);
				yield vLType;
			}
			case MpIntJitType vMpType -> generateMpIntSubPiece(gen, op, vMpType, rv);
			default -> throw new AssertionError();
		};
		gen.generateVarWriteCode(op.out(), outType, Ext.ZERO);
	}

}
