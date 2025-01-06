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

import org.objectweb.asm.*;

import ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock;
import ghidra.pcode.emu.jit.analysis.JitType;
import ghidra.pcode.emu.jit.analysis.JitType.*;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
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
	 * <b>WIP</b>: Assumes the previous (next more significant) leg is on the stack and the current
	 * (unshifted) leg is in the given variable. Computes the resulting output leg and puts in into
	 * the given local variable, but leaves a copy of the current unshifted leg on the stack.
	 * 
	 * @param rv the method visitor
	 * @param bitShift the number of <em>bits</em> to shift
	 * @param index the index of the local variable for the current leg
	 */
	private void generateShiftWithPrevLeg(MethodVisitor rv, int bitShift, int index) {
		// [...,prevLegIn]
		rv.visitLdcInsn(Integer.SIZE - bitShift);
		rv.visitInsn(ISHR);
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

	@Override
	public void generateRunCode(JitCodeGenerator gen, JitSubPieceOp op, JitBlock block,
			MethodVisitor rv) {
		JitType vType = gen.generateValReadCode(op.u(), op.uType());
		JitType outType;
		switch (vType) {
			case IntJitType vIType -> {
				rv.visitLdcInsn(op.offset() * Byte.SIZE);
				rv.visitInsn(IUSHR);
				outType = vIType;
			}
			case LongJitType vLType -> {
				rv.visitLdcInsn(op.offset() * Byte.SIZE);
				rv.visitInsn(LUSHR);
				outType = vLType;
			}
			case MpIntJitType vMpType -> {
				// WIP
				MpIntJitType outMpType = MpIntJitType.forSize(op.out().size());
				int outLegCount = outMpType.legsAlloc();
				int legsLeft = vMpType.legsAlloc();
				int popCount = op.offset() / Integer.BYTES;
				int byteShift = op.offset() % Integer.BYTES;
				for (int i = 0; i < popCount; i++) {
					rv.visitInsn(POP);
				}
				int firstIndex = gen.getAllocationModel().nextFreeLocal();
				Label start = new Label();
				Label end = new Label();
				rv.visitLabel(start);
				for (int i = 0; i < outLegCount; i++) {
					rv.visitLocalVariable("subpiece" + i, Type.getDescriptor(int.class), null,
						start, end, firstIndex + i);
					rv.visitVarInsn(ISTORE, firstIndex + i);
					// NOTE: More significant legs have higher indices (reverse of stack)
					legsLeft--;
				}

				if (byteShift > 0) {
					int curLeg = outLegCount - 1;
					if (legsLeft > 0) {
						// [...,prevLegIn]
						generateShiftWithPrevLeg(rv, byteShift * Byte.SIZE, firstIndex + curLeg);
						// [...,legIn]
						legsLeft--;
						curLeg--;
					}
					else {
						// [...]
						rv.visitVarInsn(ILOAD, firstIndex + curLeg);
						// [...,legIn]
						rv.visitInsn(DUP);
						// [...,legIn,legIn]
						rv.visitLdcInsn(byteShift * Byte.SIZE);
						rv.visitInsn(IUSHR);
						// [...,legIn,legOut]
						rv.visitVarInsn(ISTORE, firstIndex + curLeg);
						// [...,legIn]
						curLeg--;
					}
					while (curLeg >= 0) {
						generateShiftWithPrevLeg(rv, byteShift * Byte.SIZE, firstIndex + curLeg);
						legsLeft--;
						curLeg--;
					}
				}
				while (legsLeft > 0) {
					rv.visitInsn(POP);
					legsLeft--;
				}
				// NOTE: More significant legs have higher indices
				for (int i = outLegCount - 1; i >= 0; i--) {
					rv.visitVarInsn(ILOAD, firstIndex + i);
				}
				rv.visitLabel(end);
				outType = outMpType;
			}
			default -> throw new AssertionError();
		}
		gen.generateVarWriteCode(op.out(), outType);
	}

}
