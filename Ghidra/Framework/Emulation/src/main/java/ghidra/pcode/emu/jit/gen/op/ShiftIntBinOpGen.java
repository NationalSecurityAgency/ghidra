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

import org.objectweb.asm.MethodVisitor;

import ghidra.pcode.emu.jit.analysis.JitAllocationModel;
import ghidra.pcode.emu.jit.analysis.JitAllocationModel.JvmTempAlloc;
import ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock;
import ghidra.pcode.emu.jit.analysis.JitType;
import ghidra.pcode.emu.jit.analysis.JitType.*;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage;
import ghidra.pcode.emu.jit.gen.type.TypeConversions.Ext;
import ghidra.pcode.emu.jit.op.JitIntBinOp;

/**
 * An extension for integer shift operators
 * 
 * <p>
 * This is just going to invoke one of the {@link JitCompiledPassage#intLeft(int, int)},
 * {@link JitCompiledPassage#intRight(int, int)}, {@link JitCompiledPassage#intSRight(int, int)},
 * etc. methods, depending on the operand types.
 * 
 * @param <T> the class of p-code op node in the use-def graph
 */
public interface ShiftIntBinOpGen<T extends JitIntBinOp> extends IntBinOpGen<T> {
	/**
	 * {@inheritDoc}
	 * <p>
	 * The shift amount is always treated unsigned.
	 */
	@Override
	default Ext rExt() {
		return Ext.ZERO;
	}

	/**
	 * The name of the static method in {@link JitCompiledPassage} to invoke
	 * 
	 * @return the name
	 */
	String methodName();

	default MpIntJitType generateShiftMpPrimitive(JitAllocationModel am, int legCount,
			SimpleJitType rType, MpIntJitType outType, String mdesc, MethodVisitor mv) {
		try (
				JvmTempAlloc tmpL = am.allocateTemp(mv, "tmpL", legCount);
				JvmTempAlloc tmpR = am.allocateTemp(mv, "tmpR", rType.javaType(), 1)) {
			// [amt:INT, lleg1:INT,...,llegN:INT]
			mv.visitVarInsn(rType.opcodeStore(), tmpR.idx(0));
			// [lleg1,...,llegN]
			OpGen.generateMpLegsIntoTemp(tmpL, legCount, mv);
			// []
			/**
			 * FIXME: We could avoid this array allocation by shifting in place, but then we'd still
			 * need to communicate the actual out size. Things are easy if the out size is smaller
			 * than the left-in size, but not so easy if larger. Or, maybe over-provision if
			 * larger....
			 */
			mv.visitLdcInsn(outType.legsAlloc());
			// [outLegCount:INT]
			mv.visitIntInsn(NEWARRAY, T_INT);
			// [out:ARR]
			mv.visitInsn(DUP);
			// [out,out]
			mv.visitLdcInsn(outType.size());
			// [outBytes:INT,out,out]
			OpGen.generateMpLegsIntoArray(tmpL, legCount, legCount, mv);
			// [inL:ARR,outBytes:INT,out,out]
			mv.visitVarInsn(rType.opcodeLoad(), tmpR.idx(0));
			// [inR:SIMPLE,inL:ARR,outBytes,out,out]
			mv.visitMethodInsn(INVOKESTATIC, NAME_JIT_COMPILED_PASSAGE, methodName(), mdesc, true);
			// [out]
			OpGen.generateMpLegsFromArray(outType.legsAlloc(), mv);
			// [oleg1,...,olegN]
		}
		return outType.ext();
	}

	default SimpleJitType generateShiftPrimitiveMp(JitAllocationModel am, SimpleJitType lType,
			int legCount, String mdesc, MethodVisitor mv) {
		try (JvmTempAlloc tmpR = am.allocateTemp(mv, "tmpR", legCount)) {
			// [rleg1:INT,...,rlegN:INT,val:INT]
			OpGen.generateMpLegsIntoTemp(tmpR, legCount, mv);
			// [val:INT]
			OpGen.generateMpLegsIntoArray(tmpR, legCount, legCount, mv);
			// [inR:ARR,val:INT]
			mv.visitMethodInsn(INVOKESTATIC, NAME_JIT_COMPILED_PASSAGE, methodName(), mdesc, true);
			// [out:INT]
		}
		return lType.ext();
	}

	default MpIntJitType generateShiftMpMp(JitAllocationModel am, int leftLegCount,
			int rightLegCount, MpIntJitType outType, MethodVisitor mv) {
		try (
				JvmTempAlloc tmpL = am.allocateTemp(mv, "tmpL", leftLegCount);
				JvmTempAlloc tmpR = am.allocateTemp(mv, "tmpR", rightLegCount)) {
			// [rleg1:INT,...,rlegN:INT,lleg1:INT,...,llegN:INT]
			OpGen.generateMpLegsIntoTemp(tmpR, rightLegCount, mv);
			// [lleg1,...,llegN]
			OpGen.generateMpLegsIntoTemp(tmpL, leftLegCount, mv);
			// []
			// FIXME: Same as in shiftPrimitiveMp
			int outLegCount = outType.legsAlloc();
			mv.visitLdcInsn(outLegCount);
			// [outLegCount:INT]
			mv.visitIntInsn(NEWARRAY, T_INT);
			// [out:ARR]
			mv.visitInsn(DUP);
			// [out,out]
			mv.visitLdcInsn(outType.size());
			// [outBytes:INT,out,out]
			OpGen.generateMpLegsIntoArray(tmpL, leftLegCount, leftLegCount, mv);
			// [inL:ARR,outBytes,out,out]
			OpGen.generateMpLegsIntoArray(tmpR, rightLegCount, rightLegCount, mv);
			// [inR,inL,outBytes,out,out]
			mv.visitMethodInsn(INVOKESTATIC, NAME_JIT_COMPILED_PASSAGE, methodName(),
				MDESC_$SHIFT_AA, true);
			// [out]
			OpGen.generateMpLegsFromArray(outLegCount, mv);
			// [oleg1,...,olegN]
		}
		return outType;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * This reduces the implementation to just the name of the method to invoke. This will select
	 * the JVM signature of the method based on the p-code operand types.
	 */
	@Override
	default JitType generateBinOpRunCode(JitCodeGenerator gen, T op, JitBlock block, JitType lType,
			JitType rType, MethodVisitor rv) {
		JitAllocationModel am = gen.getAllocationModel();
		return switch (lType) {
			case IntJitType lt -> switch (rType) {
				case IntJitType rt -> {
					rv.visitMethodInsn(INVOKESTATIC, NAME_JIT_COMPILED_PASSAGE, methodName(),
						MDESC_$SHIFT_II, true);
					yield lType.ext();
				}
				case LongJitType rt -> {
					rv.visitMethodInsn(INVOKESTATIC, NAME_JIT_COMPILED_PASSAGE, methodName(),
						MDESC_$SHIFT_IJ, true);
					yield lType.ext();
				}
				case MpIntJitType rt -> generateShiftPrimitiveMp(am, lt, rt.legsAlloc(),
					MDESC_$SHIFT_IA, rv);
				default -> throw new AssertionError();
			};

			case LongJitType lt -> switch (rType) {
				case IntJitType rt -> {
					rv.visitMethodInsn(INVOKESTATIC, NAME_JIT_COMPILED_PASSAGE, methodName(),
						MDESC_$SHIFT_JI, true);
					yield lType.ext();
				}
				case LongJitType rt -> {
					rv.visitMethodInsn(INVOKESTATIC, NAME_JIT_COMPILED_PASSAGE, methodName(),
						MDESC_$SHIFT_JJ, true);
					yield lType.ext();
				}
				case MpIntJitType rt -> generateShiftPrimitiveMp(am, lt, rt.legsAlloc(),
					MDESC_$SHIFT_JA, rv);
				default -> throw new AssertionError();
			};
			case MpIntJitType lt -> switch (rType) {
				case IntJitType rt -> generateShiftMpPrimitive(am, lt.legsAlloc(), rt,
					MpIntJitType.forSize(op.out().size()), MDESC_$SHIFT_AI, rv);
				case LongJitType rt -> generateShiftMpPrimitive(am, lt.legsAlloc(), rt,
					MpIntJitType.forSize(op.out().size()), MDESC_$SHIFT_AJ, rv);
				case MpIntJitType rt -> generateShiftMpMp(am, lt.legsAlloc(), rt.legsAlloc(),
					MpIntJitType.forSize(op.out().size()), rv);
				default -> throw new AssertionError();
			};
			default -> throw new AssertionError();
		};
	}
}
