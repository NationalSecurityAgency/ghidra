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

import org.objectweb.asm.*;

import ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock;
import ghidra.pcode.emu.jit.analysis.JitType;
import ghidra.pcode.emu.jit.analysis.JitType.*;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.gen.type.TypeConversions;
import ghidra.pcode.emu.jit.op.JitIntSubOp;

/**
 * The generator for a {@link JitIntSubOp int_sub}.
 * 
 * <p>
 * This uses the binary operator generator and simply emits {@link #ISUB} or {@link #LSUB} depending
 * on the type.
 * 
 * <p>
 * NOTE: The multi-precision integer parts of this are a work in progress.
 */
public enum IntSubOpGen implements BinOpGen<JitIntSubOp> {
	/** The generator singleton */
	GEN;

	private void generateMpIntLegSub(JitCodeGenerator gen, int idx, boolean takesBorrow,
			boolean givesBorrow, MethodVisitor mv) {
		if (takesBorrow) {
			// [...,llegN:INT,olegN+1:LONG]
			mv.visitLdcInsn(32);
			mv.visitInsn(LSHR); // signed so that ADD effects subtraction
			// [...,lleg1...,borrowinN:LONG]
			mv.visitInsn(DUP2_X1);
			mv.visitInsn(POP2);
			// [...,borrowinN:LONG,llegN:INT]
			mv.visitInsn(I2L); // yes, signed
			// [...,borrowinN:LONG,llegN:LONG]
			mv.visitInsn(LADD); // Yes, add, because borrow is 0 or -1
			// [...,diffpartN:LONG]
		}
		else {
			// [...,legN:INT]
			TypeConversions.generateIntToLong(IntJitType.I4, LongJitType.I8, mv);
			// [...,diffpartN:LONG] (legN + 0)
		}
		mv.visitVarInsn(ILOAD, idx);
		// [...,diffpartN:LONG,rlegN:INT]
		TypeConversions.generateIntToLong(IntJitType.I4, LongJitType.I8, mv);
		// [...,diffpartN:LONG,rlegN:LONG]
		mv.visitInsn(LSUB);
		// [...,olegN:LONG]
		if (givesBorrow) {
			mv.visitInsn(DUP2);
		}
		// [...,(olegN:LONG),olegN:LONG]
		TypeConversions.generateLongToInt(LongJitType.I8, IntJitType.I4, mv);
		// [...,(olegN:LONG),olegN:INT]
		/** NB. The store will perform the masking */
		mv.visitVarInsn(ISTORE, idx);
		// [...,(olegN:LONG)]
	}

	private void generateMpIntSub(JitCodeGenerator gen, MpIntJitType type, MethodVisitor mv) {
		/**
		 * The strategy is to allocate a temp local for each leg of the result. First, we'll pop the
		 * right operand into the temp. Then, as we work with each leg of the left operand, we'll
		 * execute the algorithm. Convert both right and left legs to a long and add them (along
		 * with a possible carry in). Store the result back into the temp locals. Shift the leg
		 * right 32 to get the carry out, then continue to the next leg up. The final carry out can
		 * be dropped (overflow). The result legs are then pushed back to the stack.
		 */
		// [lleg1,...,llegN,rleg1,rlegN] (N is least-significant leg)
		int legCount = type.legsAlloc(); // include partial
		int firstIndex = gen.getAllocationModel().nextFreeLocal();
		Label start = new Label();
		Label end = new Label();
		mv.visitLabel(start);
		for (int i = 0; i < legCount; i++) {
			mv.visitLocalVariable("result" + i, Type.getDescriptor(int.class), null, start, end,
				firstIndex + i);
			mv.visitVarInsn(ISTORE, firstIndex + i);
			// NOTE: More significant legs have higher indices (reverse of stack)
		}
		// [lleg1,...,llegN:INT]
		for (int i = 0; i < legCount; i++) {
			boolean isLast = i == legCount - 1;
			boolean takesCarry = i != 0; // not first
			generateMpIntLegSub(gen, firstIndex + i, takesCarry, !isLast, mv);
		}

		// Push it all back, in reverse order
		for (int i = 0; i < legCount; i++) {
			mv.visitVarInsn(ILOAD, firstIndex + legCount - i - 1);
		}
		mv.visitLabel(end);
	}

	@Override
	public JitType afterLeft(JitCodeGenerator gen, JitIntSubOp op, JitType lType, JitType rType,
			MethodVisitor rv) {
		return TypeConversions.forceUniformZExt(lType, rType, rv);
	}

	@Override
	public JitType generateBinOpRunCode(JitCodeGenerator gen, JitIntSubOp op, JitBlock block,
			JitType lType, JitType rType, MethodVisitor rv) {
		rType = TypeConversions.forceUniformZExt(rType, lType, rv);
		switch (rType) {
			case IntJitType t -> rv.visitInsn(ISUB);
			case LongJitType t -> rv.visitInsn(LSUB);
			case MpIntJitType t when t.size() == lType.size() -> generateMpIntSub(gen, t, rv);
			case MpIntJitType t -> TODO("MpInt of differing sizes");
			default -> throw new AssertionError();
		}
		return lType;
	}
}
