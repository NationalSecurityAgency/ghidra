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
import ghidra.pcode.emu.jit.op.JitIntAddOp;

/**
 * The generator for a {@link JitIntAddOp int_add}.
 * 
 * <p>
 * This uses the binary operator generator and simply emits {@link #IADD} or {@link #LADD} depending
 * on the type.
 * 
 * <p>
 * NOTE: The multi-precision integer parts of this are a work in progress.
 */
public enum IntAddOpGen implements BinOpGen<JitIntAddOp> {
	/** The generator singleton */
	GEN;

	static void generateMpIntLegAdd(JitCodeGenerator gen, int idx, boolean takesCarry,
			boolean givesCarry, MethodVisitor mv) {
		if (takesCarry) {
			// [...,llegN:INT,olegN+1:LONG]
			mv.visitLdcInsn(32);
			mv.visitInsn(LUSHR);
			// [...,lleg1...,carryinN:LONG]
			mv.visitInsn(DUP2_X1);
			mv.visitInsn(POP2);
			// [...,carryinN:LONG,llegN:INT]
			TypeConversions.generateIntToLong(IntJitType.I4, LongJitType.I8, mv);
			// [...,carryinN:LONG,llegN:LONG]
			mv.visitInsn(LADD);
			// [...,sumpartN:LONG]
		}
		else {
			// [...,legN:INT]
			TypeConversions.generateIntToLong(IntJitType.I4, LongJitType.I8, mv);
			// [...,sumpartN:LONG] (legN + 0)
		}
		mv.visitVarInsn(ILOAD, idx);
		// [...,sumpartN:LONG,rlegN:INT]
		TypeConversions.generateIntToLong(IntJitType.I4, LongJitType.I8, mv);
		// [...,sumpartN:LONG,rlegN:LONG]
		mv.visitInsn(LADD);
		// [...,olegN:LONG]
		if (givesCarry) {
			mv.visitInsn(DUP2);
		}
		// [...,(olegN:LONG),olegN:LONG]
		TypeConversions.generateLongToInt(LongJitType.I8, IntJitType.I4, mv);
		// [...,(olegN:LONG),olegN:INT]
		/** NB. The store will perform the masking */
		mv.visitVarInsn(ISTORE, idx);
		// [...,(olegN:LONG)]
	}

	private void generateMpIntAdd(JitCodeGenerator gen, MpIntJitType type, MethodVisitor mv) {
		/**
		 * The strategy is to allocate a temp local for each leg of the result. First, we'll pop the
		 * right operand into the temp. Then, as we work with each leg of the left operand, we'll
		 * execute the algorithm. Convert both right and left legs to a long and add them (along
		 * with a possible carry in). Store the result back into the temp locals. Shift the leg
		 * right 32 to get the carry out, then continue to the next leg up. The final carry out can
		 * be dropped (overflow). The result legs are then pushed back to the stack.
		 */
		// [lleg1,...,llegN,rleg1,rlegN] (N is least-significant leg)
		int legCount = type.legsAlloc();
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
			generateMpIntLegAdd(gen, firstIndex + i, takesCarry, !isLast, mv);
		}

		// Push it all back, in reverse order
		for (int i = 0; i < legCount; i++) {
			mv.visitVarInsn(ILOAD, firstIndex + legCount - i - 1);
		}
		mv.visitLabel(end);
	}

	@Override
	public JitType afterLeft(JitCodeGenerator gen, JitIntAddOp op, JitType lType, JitType rType,
			MethodVisitor rv) {
		return TypeConversions.forceUniformZExt(lType, rType, rv);
	}

	@Override
	public JitType generateBinOpRunCode(JitCodeGenerator gen, JitIntAddOp op, JitBlock block,
			JitType lType, JitType rType, MethodVisitor rv) {
		rType = TypeConversions.forceUniformZExt(rType, lType, rv);
		switch (rType) {
			case IntJitType t -> rv.visitInsn(IADD);
			case LongJitType t -> rv.visitInsn(LADD);
			case MpIntJitType t when t.size() == lType.size() -> generateMpIntAdd(gen, t, rv);
			case MpIntJitType t -> TODO("MpInt of differing sizes");
			default -> throw new AssertionError();
		}
		return lType;
	}
}
