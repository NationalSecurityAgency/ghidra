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
import ghidra.pcode.emu.jit.op.JitStoreOp;
import ghidra.program.model.lang.Endian;

/**
 * The generator for a {@link JitStoreOp store}.
 * 
 * <p>
 * These ops are currently presumed to be indirect memory accesses. <b>TODO</b>: If we fold
 * constants, we could convert some of these to direct.
 * 
 * <p>
 * We request a field to pre-fetch the {@link JitBytesPcodeExecutorStateSpace space} and emit code
 * to load it onto the stack. We then emit code to load the offset onto the stack and convert it to
 * a JVM long, if necessary. The varnode size is loaded by emitting an {@link Opcodes#LDC ldc}. We
 * must now emit code to load the value and convert it to a byte array. The conversion depends on
 * the type of the value. Finally, we emit an invocation of
 * {@link JitBytesPcodeExecutorStateSpace#write(long, byte[], int, int)}.
 */
public enum StoreOpGen implements OpGen<JitStoreOp> {
	/** The generator singleton */
	GEN;

	@Override
	public void generateInitCode(JitCodeGenerator gen, JitStoreOp op, MethodVisitor iv) {
		gen.requestFieldForSpaceIndirect(op.space());
	}

	private void generateConvMpIntRunCodeLegBE(int off, int size, MethodVisitor rv) {
		// [...,legN,bytearr]
		rv.visitInsn(DUP_X1);
		// [...,bytearr,legN,bytearr]
		rv.visitLdcInsn(off);
		// [...,bytearr,legN,bytearr,off]
		rv.visitMethodInsn(INVOKESTATIC, NAME_JIT_COMPILED_PASSAGE,
			IntWriteGen.BE.chooseName(size), MDESC_JIT_COMPILED_PASSAGE__WRITE_INTX, true);
		// [...,bytearr]
	}

	private void generateConvMpIntRunCodeLegLE(int off, int size, MethodVisitor rv) {
		// [...,legN,bytearr]
		rv.visitInsn(DUP_X1);
		// [...,bytearr,legN,bytearr]
		rv.visitLdcInsn(off);
		// [...,bytearr,legN,bytearr,off]
		rv.visitMethodInsn(INVOKESTATIC, NAME_JIT_COMPILED_PASSAGE,
			IntWriteGen.LE.chooseName(size), MDESC_JIT_COMPILED_PASSAGE__WRITE_INTX, true);
		// [...,bytearr]
	}

	private void generateConvIntRunCode(Endian endian, IntJitType type, MethodVisitor rv) {
		switch (endian) {
			case BIG -> generateConvMpIntRunCodeLegBE(0, type.size(), rv);
			case LITTLE -> generateConvMpIntRunCodeLegLE(0, type.size(), rv);
		}
	}

	private String chooseWriteLongName(Endian endian, int size) {
		return switch (endian) {
			case BIG -> LongWriteGen.BE.chooseName(size);
			case LITTLE -> LongWriteGen.LE.chooseName(size);
		};
	}

	private void generateConvLongRunCode(Endian endian, LongJitType type, MethodVisitor rv) {
		// [...,value:LONG,bytearr]
		rv.visitInsn(DUP_X2);
		// [...,bytearr,value:LONG,bytearr]
		rv.visitLdcInsn(0);
		// [...,bytearr,value:LONG,bytearr,offset=0]
		rv.visitMethodInsn(INVOKESTATIC, NAME_JIT_COMPILED_PASSAGE,
			chooseWriteLongName(endian, type.size()),
			MDESC_JIT_COMPILED_PASSAGE__WRITE_LONGX, true);
		// [...,bytearr])
	}

	private void generateConvFloatRunCode(Endian endian, FloatJitType type, MethodVisitor rv) {
		// [...,value:FLOAT,bytearr]
		rv.visitInsn(SWAP);
		// [...,bytearr,value:FLOAT]
		TypeConversions.generateFloatToInt(type, IntJitType.I4, rv);
		// [...,bytearr,value:INT]
		rv.visitInsn(SWAP);
		// [...,value:INT,bytearr]
		generateConvIntRunCode(endian, IntJitType.I4, rv);
		// [...,bytearr]
	}

	private void generateConvDoubleRunCode(Endian endian, DoubleJitType type, MethodVisitor rv) {
		// [...,value:DOUBLE,bytearr]
		rv.visitInsn(DUP_X2);
		// [...,bytearr,value:DOUBLE,bytearr]
		rv.visitInsn(POP);
		// [...,bytearr,value:DOUBLE]
		TypeConversions.generateDoubleToLong(type, LongJitType.I8, rv);
		// [...,bytearr,value:LONG]
		rv.visitInsn(DUP2_X1);
		// [...,value:LONG,bytearr,value:LONG]
		rv.visitInsn(POP2);
		// [...,value:LONG,bytearr]
		generateConvLongRunCode(endian, LongJitType.I8, rv);
		// [...,bytearr]
	}

	private void generateConvMpIntRunCodeBE(MpIntJitType type, MethodVisitor rv) {
		// [...,leg1,...,legN,bytearr]
		int countFull = type.legsWhole();
		int remSize = type.partialSize();

		int off = type.size();
		for (int i = 0; i < countFull; i++) {
			off -= Integer.BYTES;
			// [...,legN-1,legN,bytearr]
			generateConvMpIntRunCodeLegBE(off, Integer.BYTES, rv);
			// [...,legN-1,bytearr]
		}
		if (remSize > 0) {
			off -= remSize;
			// [...,leg1,bytearr]
			generateConvMpIntRunCodeLegBE(off, remSize, rv);
			// [...,bytearr]
		}
		// [...,bytearr]
	}

	private void generateConvMpIntRunCodeLE(MpIntJitType type, MethodVisitor rv) {
		// [...,leg1,...,legN,bytearr]
		int countFull = type.legsWhole();
		int remSize = type.partialSize();

		int off = 0;
		for (int i = 0; i < countFull; i++) {
			// [...,legN-1,legN,bytearr]
			generateConvMpIntRunCodeLegLE(off, Integer.BYTES, rv);
			// [...,legN-1,bytearr]
			off += Integer.BYTES;
		}
		if (remSize > 0) {
			// [...,leg1,bytearr]
			generateConvMpIntRunCodeLegLE(off, remSize, rv);
			// [...,bytearr]
			off += remSize;
		}
		// [...,bytearr]
	}

	private void generateConvMpIntRunCode(Endian endian, MpIntJitType type, MethodVisitor rv) {
		switch (endian) {
			case BIG -> generateConvMpIntRunCodeBE(type, rv);
			case LITTLE -> generateConvMpIntRunCodeLE(type, rv);
		}
	}

	@Override
	public void generateRunCode(JitCodeGenerator gen, JitStoreOp op, JitBlock block,
			MethodVisitor rv) {
		// [...]
		gen.requestFieldForSpaceIndirect(op.space()).generateLoadCode(gen, rv);
		// [...,space]
		JitType offsetType = gen.generateValReadCode(op.offset(), op.offsetType());
		// [...,space,offset:?]
		TypeConversions.generateToLong(offsetType, LongJitType.I8, rv);
		// [...,space,offset:LONG]
		JitType valueType = gen.generateValReadCode(op.value(), op.valueType());
		// [...,space,offset,value]
		rv.visitLdcInsn(op.value().size());
		// [...,space,offset,value,size]
		rv.visitIntInsn(NEWARRAY, T_BYTE);
		// [...,space,offset,value,bytearray]
		Endian endian = gen.getAnalysisContext().getEndian();
		switch (valueType) {
			case IntJitType iType -> generateConvIntRunCode(endian, iType, rv);
			case LongJitType lType -> generateConvLongRunCode(endian, lType, rv);
			case FloatJitType fType -> generateConvFloatRunCode(endian, fType, rv);
			case DoubleJitType dType -> generateConvDoubleRunCode(endian, dType, rv);
			case MpIntJitType mpType -> generateConvMpIntRunCode(endian, mpType, rv);
			default -> throw new AssertionError();
		}
		// [...,space,offset,bytearray]
		rv.visitLdcInsn(0);
		// [...,space,offset,bytearray,srcOffset=0]
		rv.visitLdcInsn(op.value().size());
		// [...,space,offset,bytearray,srcOffset=0,size]
		rv.visitMethodInsn(
			INVOKEVIRTUAL, NAME_JIT_BYTES_PCODE_EXECUTOR_STATE_SPACE, "write",
			MDESC_JIT_BYTES_PCODE_EXECUTOR_STATE_SPACE__WRITE, false);
		// [...]
	}
}
