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
import org.objectweb.asm.Opcodes;

import ghidra.pcode.emu.jit.JitBytesPcodeExecutorStatePiece.JitBytesPcodeExecutorStateSpace;
import ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock;
import ghidra.pcode.emu.jit.analysis.JitType;
import ghidra.pcode.emu.jit.analysis.JitType.*;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.gen.type.*;
import ghidra.pcode.emu.jit.op.JitLoadOp;
import ghidra.program.model.lang.Endian;

/**
 * The generator for a {@link JitLoadOp load}.
 * 
 * <p>
 * These ops are currently presumed to be indirect memory accesses. <b>TODO</b>: If we fold
 * constants, we could convert some of these to direct.
 * 
 * <p>
 * We request a field to pre-fetch the {@link JitBytesPcodeExecutorStateSpace space} and emit code
 * to load it onto the stack. We then emit code to load the offset onto the stack and convert it to
 * a JVM long, if necessary. The varnode size is loaded by emitting an {@link Opcodes#LDC ldc}, and
 * finally we emit an invocation of {@link JitBytesPcodeExecutorStateSpace#read(long, int)}. The
 * result is a byte array, so we finish by emitting the appropriate conversion and write the result
 * to the output operand.
 */
public enum LoadOpGen implements OpGen<JitLoadOp> {
	/** The generator singleton */
	GEN;

	@Override
	public void generateInitCode(JitCodeGenerator gen, JitLoadOp op, MethodVisitor iv) {
		gen.requestFieldForSpaceIndirect(op.space());
	}

	private void generateConvMpIntRunCodeLegBE(int off, int size, MethodVisitor rv,
			boolean keepByteArr) {
		// [...,bytearr]
		if (keepByteArr) {
			rv.visitInsn(DUP);
			// [...,(bytearr),bytearr]
		}
		rv.visitLdcInsn(off);
		rv.visitMethodInsn(INVOKESTATIC, NAME_JIT_COMPILED_PASSAGE,
			IntReadGen.BE.chooseName(size), MDESC_JIT_COMPILED_PASSAGE__READ_INTX, true);
		// [...,(bytearr),legN]
		if (keepByteArr) {
			rv.visitInsn(SWAP);
			// [...,legN,(bytearr)]
		}
	}

	private void generateConvMpIntRunCodeLegLE(int off, int size, MethodVisitor rv,
			boolean keepByteArr) {
		// [...,bytearr]
		if (keepByteArr) {
			rv.visitInsn(DUP);
			// [...,(bytearr),bytearr]
		}
		rv.visitLdcInsn(off);
		rv.visitMethodInsn(INVOKESTATIC, NAME_JIT_COMPILED_PASSAGE,
			IntReadGen.LE.chooseName(size), MDESC_JIT_COMPILED_PASSAGE__READ_INTX, true);
		// [...,(bytearr),legN]
		if (keepByteArr) {
			rv.visitInsn(SWAP);
			// [...,legN,(bytearr)]
		}
	}

	private void generateConvIntRunCode(Endian endian, IntJitType type, MethodVisitor rv) {
		switch (endian) {
			case BIG -> generateConvMpIntRunCodeLegBE(0, type.size(), rv, false);
			case LITTLE -> generateConvMpIntRunCodeLegLE(0, type.size(), rv, false);
		}
	}

	static String chooseReadLongName(Endian endian, int size) {
		return switch (endian) {
			case BIG -> LongReadGen.BE.chooseName(size);
			case LITTLE -> LongReadGen.LE.chooseName(size);
		};
	}

	private void generateConvLongRunCode(Endian endian, LongJitType type, MethodVisitor rv) {
		// [...,bytearr]
		rv.visitLdcInsn(0);
		// [...,bytearr, offset=0]
		rv.visitMethodInsn(INVOKESTATIC, NAME_JIT_COMPILED_PASSAGE,
			chooseReadLongName(endian, type.size()), MDESC_JIT_COMPILED_PASSAGE__READ_LONGX, true);
		// [...,value]
	}

	private void generateConvFloatRunCode(Endian endian, FloatJitType type, MethodVisitor rv) {
		// [...,bytearr]
		generateConvIntRunCode(endian, IntJitType.I4, rv);
		// [...,value:INT]
		TypeConversions.generateIntToFloat(IntJitType.I4, type, rv);
		// [...,value:FLOAT]
	}

	private void generateConvDoubleRunCode(Endian endian, DoubleJitType type, MethodVisitor rv) {
		// [...,bytearr]
		generateConvLongRunCode(endian, LongJitType.I8, rv);
		// [...,value:LONG]
		TypeConversions.generateLongToDouble(LongJitType.I8, type, rv);
		// [...,value:DOUBLE]
	}

	private void generateConvMpIntRunCodeBE(MpIntJitType type, MethodVisitor rv) {
		int countFull = type.legsWhole();
		int remSize = type.partialSize();

		int off = 0;
		if (remSize > 0) {
			// [...,bytearr]
			generateConvMpIntRunCodeLegBE(off, remSize, rv, true);
			// [...,legN,bytearr]
			off += remSize;
		}
		for (int i = 0; i < countFull; i++) {
			// [...,legN-1,bytearr]
			generateConvMpIntRunCodeLegBE(off, Integer.BYTES, rv, true);
			// [...,legN-1,legN,bytearr]
			off += Integer.BYTES;
		}
		// [...,leg1,...,legN,bytearr]
		rv.visitInsn(POP);
		// [...,leg1,...,legN]
	}

	private void generateConvMpIntRunCodeLE(MpIntJitType type, MethodVisitor rv) {
		int countFull = type.legsWhole();
		int remSize = type.partialSize();

		int off = type.size();
		if (remSize > 0) {
			off -= remSize;
			// [...,bytearr]
			generateConvMpIntRunCodeLegLE(off, remSize, rv, true);
			// [...,legN,bytearr]
		}
		for (int i = 0; i < countFull; i++) {
			off -= Integer.BYTES;
			// [...,legN-1,bytearr]
			generateConvMpIntRunCodeLegLE(off, Integer.BYTES, rv, true);
			// [...,legN-1,legN,bytearr]
		}
		// [...,leg1,...,legN,bytearr]
		rv.visitInsn(POP);
		// [...,leg1,...,legN]
	}

	private void generateConvMpIntRunCode(Endian endian, MpIntJitType type,
			MethodVisitor rv) {
		switch (endian) {
			case BIG -> generateConvMpIntRunCodeBE(type, rv);
			case LITTLE -> generateConvMpIntRunCodeLE(type, rv);
		}
	}

	@Override
	public void generateRunCode(JitCodeGenerator gen, JitLoadOp op, JitBlock block,
			MethodVisitor rv) {
		// [...]
		gen.requestFieldForSpaceIndirect(op.space()).generateLoadCode(gen, rv);
		// [...,space]
		JitType offsetType = gen.generateValReadCode(op.offset(), op.offsetType());
		// [...,space,offset:?INT/LONG]
		TypeConversions.generateToLong(offsetType, LongJitType.I8, rv);
		// [...,space,offset:LONG]
		rv.visitLdcInsn(op.out().size());
		// [...,space,offset,size]
		rv.visitMethodInsn(INVOKEVIRTUAL, NAME_JIT_BYTES_PCODE_EXECUTOR_STATE_SPACE, "read",
			MDESC_JIT_BYTES_PCODE_EXECUTOR_STATE_SPACE__READ, false);
		// [...,bytearr]
		Endian endian = gen.getAnalysisContext().getEndian();
		JitType outType = gen.getTypeModel().typeOf(op.out());
		switch (outType) {
			case IntJitType iType -> generateConvIntRunCode(endian, iType, rv);
			case LongJitType lType -> generateConvLongRunCode(endian, lType, rv);
			case FloatJitType fType -> generateConvFloatRunCode(endian, fType, rv);
			case DoubleJitType dType -> generateConvDoubleRunCode(endian, dType, rv);
			case MpIntJitType mpType -> generateConvMpIntRunCode(endian, mpType, rv);
			default -> throw new AssertionError();
		}
		// [...,value]
		gen.generateVarWriteCode(op.out(), outType);
		// [...]
	}
}
