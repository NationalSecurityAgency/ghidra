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

import org.objectweb.asm.*;

import ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock;
import ghidra.pcode.emu.jit.analysis.JitType;
import ghidra.pcode.emu.jit.analysis.JitType.*;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.gen.type.TypeConversions;
import ghidra.pcode.emu.jit.op.JitIntCarryOp;

/**
 * The generator for a {@link JitIntCarryOp int_carry}.
 * 
 * <p>
 * This uses the binary operator generator. First we have to consider which strategy we are going to
 * use. If the p-code type is strictly smaller than its host JVM type, we can simply add the two
 * operands and examine the next bit up. This is accomplished by emitting {@link #IADD} or
 * {@link #LADD}, depending on the type, followed by a shift right and a mask.
 * 
 * <p>
 * If the p-code type exactly fits its host JVM type, we still add, but we will need to compare the
 * result to one of the operands. Thus, we override
 * {@link #afterLeft(JitCodeGenerator, JitIntCarryOp, JitType, JitType, MethodVisitor) afterLeft}
 * and emit code to duplicate the left operand. We can then add and invoke
 * {@link Integer#compareUnsigned(int, int)} to determine whether there was overflow. If there was,
 * then we know the carry bit would have been set. We can spare the conditional flow by just
 * shifting the sign bit into the 1's place.
 * 
 * <p>
 * NOTE: The multi-precision integer parts of this are a work in progress.
 */
public enum IntCarryOpGen implements BinOpGen<JitIntCarryOp> {
	/** The generator singleton */
	GEN;

	private void generateMpIntCarry(JitCodeGenerator gen, MpIntJitType type, MethodVisitor mv) {
		/**
		 * Similar strategy as for INT_ADD. In fact, we call its per-leg logic.
		 */
		// [lleg1,...,llegN,rleg1,rlegN] (N is least-significant leg)
		int legCount = type.legsAlloc();
		int remSize = type.partialSize();
		int firstIndex = gen.getAllocationModel().nextFreeLocal();
		Label start = new Label();
		Label end = new Label();
		mv.visitLabel(start);
		for (int i = 0; i < legCount; i++) {
			mv.visitLocalVariable("temp" + i, Type.getDescriptor(int.class), null, start, end,
				firstIndex + i);
			mv.visitVarInsn(ISTORE, firstIndex + i);
			// NOTE: More significant legs have higher indices (reverse of stack)
		}
		// [lleg1,...,llegN:INT]
		for (int i = 0; i < legCount; i++) {
			boolean takesCarry = i != 0; // not first
			IntAddOpGen.generateMpIntLegAdd(gen, firstIndex + i, takesCarry, true, mv);
		}
		// [olegN:LONG]
		if (remSize == 0) {
			// The last leg was full, so extract bit 32
			mv.visitLdcInsn(32);
		}
		else {
			// The last leg was partial, so get the next more significant bit
			mv.visitLdcInsn(remSize * Byte.SIZE);
		}
		mv.visitInsn(LUSHR);
		TypeConversions.generateLongToInt(LongJitType.I8, IntJitType.I4, mv);
		mv.visitLdcInsn(1);
		mv.visitInsn(IAND);
		mv.visitLabel(end);
	}

	@Override
	public JitType afterLeft(JitCodeGenerator gen, JitIntCarryOp op, JitType lType, JitType rType,
			MethodVisitor rv) {
		/**
		 * There are two strategies to use here depending on whether or not there's room to capture
		 * the carry bit. If there's not room, we have to compare the sum to one of the input
		 * operands. If the sum is less, then we can conclude there was a carry. For that strategy,
		 * we will need to keep a copy of the left operand, so duplicate it.
		 * 
		 * On the other hand, if there is room to capture the carry, we can just add the two
		 * operands and extract the carry bit. There is no need to duplicate the left operand.
		 */
		lType = TypeConversions.forceUniformZExt(lType, rType, rv);
		switch (lType) {
			case IntJitType(int size) when size == Integer.BYTES -> rv.visitInsn(DUP);
			case IntJitType lt -> {
			}
			case LongJitType(int size) when size == Long.BYTES -> rv.visitInsn(DUP2);
			case LongJitType lt -> {
			}
			case MpIntJitType lt -> TODO("MpInt");
			default -> throw new AssertionError();
		}
		return lType;
	}

	@Override
	public JitType generateBinOpRunCode(JitCodeGenerator gen, JitIntCarryOp op, JitBlock block,
			JitType lType, JitType rType, MethodVisitor rv) {
		rType = TypeConversions.forceUniformZExt(rType, lType, rv);
		switch (rType) {
			case IntJitType(int size) when size == Integer.BYTES -> {
				// [l,l,r]
				rv.visitInsn(IADD);
				// [l,sum]
				rv.visitInsn(SWAP); // spare an LDC,XOR
				// [sum,l]
				rv.visitMethodInsn(INVOKESTATIC, NAME_INTEGER, "compareUnsigned",
					MDESC_INTEGER__COMPARE_UNSIGNED, false);
				// [cmpU(sum,l)] sum < l iff sign bit is 1
				rv.visitLdcInsn(31);
				rv.visitInsn(IUSHR);
				return IntJitType.I1;
			}
			case IntJitType(int size) -> {
				// Just add and extract the carry bit
				rv.visitInsn(IADD);
				rv.visitLdcInsn(size * Byte.SIZE);
				rv.visitInsn(ISHR);
				rv.visitLdcInsn(1);
				rv.visitInsn(IAND);
				return IntJitType.I1;
			}
			case LongJitType(int size) when size == Long.BYTES -> {
				// [l:LONG,l:LONG,r:LONG]
				rv.visitInsn(LADD);
				// [l:LONG,sum:LONG]
				rv.visitInsn(DUP2_X2);
				rv.visitInsn(POP2);
				// [sum:LONG,l:LONG]
				rv.visitMethodInsn(INVOKESTATIC, NAME_LONG, "compareUnsigned",
					MDESC_LONG__COMPARE_UNSIGNED, false);
				// [cmpU(sum,l):INT] sum < l iff sign bit is 1
				rv.visitLdcInsn(31);
				rv.visitInsn(IUSHR);
				return IntJitType.I1;
			}
			case LongJitType(int size) -> {
				// Just add and extract the carry bit
				rv.visitInsn(LADD);
				rv.visitLdcInsn(size * Byte.SIZE);
				rv.visitInsn(LSHR);
				rv.visitInsn(L2I);
				// TODO: This mask may not be necessary
				rv.visitLdcInsn(1);
				rv.visitInsn(IAND);
				return IntJitType.I1;
			}
			case MpIntJitType t when t.size() == lType.size() -> {
				generateMpIntCarry(gen, t, rv);
				return IntJitType.I1;
			}
			case MpIntJitType t -> {
				return TODO("MpInt of differing sizes");
			}
			default -> throw new AssertionError();
		}
	}
}
