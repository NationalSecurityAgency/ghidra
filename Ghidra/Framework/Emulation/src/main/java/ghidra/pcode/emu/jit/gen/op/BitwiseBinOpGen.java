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
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage;
import ghidra.pcode.emu.jit.gen.type.TypeConversions;
import ghidra.pcode.emu.jit.op.JitBinOp;

/**
 * An extension for bitwise binary operators
 * 
 * @param <T> the class of p-code op node in the use-def graph
 */
public interface BitwiseBinOpGen<T extends JitBinOp> extends BinOpGen<T> {

	/**
	 * The JVM opcode to implement this operator with int operands on the stack.
	 * 
	 * @return the opcode
	 */
	int intOpcode();

	/**
	 * The JVM opcode to implement this operator with long operands on the stack.
	 * 
	 * @return the opcode
	 */
	int longOpcode();

	/**
	 * <b>WIP</b>: The implementation for multi-precision ints.
	 * 
	 * @param gen the code generator
	 * @param type the type of each operand, including the reuslt
	 * @param mv the visitor for the {@link JitCompiledPassage#run(int) run} method
	 */
	default void generateMpIntBinOp(JitCodeGenerator gen, MpIntJitType type,
			MethodVisitor mv) {
		/**
		 * We need temp locals to get things in order. Read in right operand, do the op as we pop
		 * each left op. Then push it all back.
		 * 
		 * No masking of the result is required, since both operands should already be masked, and
		 * the bitwise op cannot generate bits of more significance.
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
		for (int i = 0; i < legCount; i++) {
			// [lleg1,...,llegN:INT]
			mv.visitVarInsn(ILOAD, firstIndex + i);
			// [lleg1,...,llegN:INT,rlegN:INT]
			mv.visitInsn(intOpcode());
			// [lleg1,...,olegN:INT]
			mv.visitVarInsn(ISTORE, firstIndex + i);
			// [lleg1,...]
		}

		// Push it all back, in reverse order
		for (int i = 0; i < legCount; i++) {
			mv.visitVarInsn(ILOAD, firstIndex + legCount - i - 1);
		}
		mv.visitLabel(end);
	}

	@Override
	default JitType afterLeft(JitCodeGenerator gen, T op, JitType lType, JitType rType,
			MethodVisitor rv) {
		return TypeConversions.forceUniformZExt(lType, rType, rv);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * This implementation reduces the need to just the JVM opcode. We simply ensure both operands
	 * have the same size and JVM type, select and emit the correct opcode, and return the type of
	 * the result.
	 */
	@Override
	default JitType generateBinOpRunCode(JitCodeGenerator gen, T op, JitBlock block, JitType lType,
			JitType rType, MethodVisitor rv) {
		rType = TypeConversions.forceUniformZExt(rType, lType, rv);
		switch (rType) {
			case IntJitType t -> rv.visitInsn(intOpcode());
			case LongJitType t -> rv.visitInsn(longOpcode());
			case MpIntJitType t when t.size() == lType.size() -> generateMpIntBinOp(gen, t, rv);
			case MpIntJitType t -> TODO("MpInt of differing sizes");
			default -> throw new AssertionError();
		}
		return lType;
	}
}
