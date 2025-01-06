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

import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;

import ghidra.lifecycle.Unfinished;
import ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock;
import ghidra.pcode.emu.jit.analysis.JitType;
import ghidra.pcode.emu.jit.analysis.JitType.*;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage;
import ghidra.pcode.emu.jit.gen.type.TypeConversions;
import ghidra.pcode.emu.jit.op.JitIntTestOp;

/**
 * An extension for integer comparison operators
 * 
 * @param <T> the class of p-code op node in the use-def graph
 */
public interface CompareIntBinOpGen<T extends JitIntTestOp> extends BinOpGen<T> {

	/**
	 * Whether the comparison of p-code integers is signed
	 * 
	 * <p>
	 * If the comparison is unsigned, we will emit invocations of
	 * {@link Integer#compareUnsigned(int, int)} or {@link Long#compareUnsigned(long, long)},
	 * followed by a conditional jump corresponding to this p-code comparison op. If the comparison
	 * is signed, and the type fits in a JVM int, we emit the conditional jump of ints directly
	 * implementing this p-code comparison op. If the type requires a JVM long, we first emit an
	 * {@link #LCMP lcmp}, followed by the same opcode that would be used in the unsigned case.
	 * 
	 * @return true if signed, false if not
	 */
	boolean isSigned();

	/**
	 * The JVM opcode to perform the conditional jump for signed integers.
	 * 
	 * @return the opcode
	 */
	int icmpOpcode();

	/**
	 * Emits bytecode for the JVM int case
	 * 
	 * @param lblTrue the target bytecode label for the true case
	 * @param rv the visitor for the {@link JitCompiledPassage#run(int) run} method
	 */
	default void generateIntJump(Label lblTrue, MethodVisitor rv) {
		if (isSigned()) {
			rv.visitJumpInsn(icmpOpcode(), lblTrue);
		}
		else {
			rv.visitMethodInsn(INVOKESTATIC, NAME_INTEGER, "compareUnsigned",
				MDESC_INTEGER__COMPARE_UNSIGNED, false);
			rv.visitJumpInsn(ifOpcode(), lblTrue);
		}
	}

	/**
	 * Emits bytecode for the JVM long case
	 * 
	 * @param lblTrue the target bytecode label for the true case
	 * @param rv the visitor for the {@link JitCompiledPassage#run(int) run} method
	 */
	default void generateLongJump(Label lblTrue, MethodVisitor rv) {
		if (isSigned()) {
			rv.visitInsn(LCMP);
		}
		else {
			rv.visitMethodInsn(INVOKESTATIC, NAME_LONG, "compareUnsigned",
				MDESC_LONG__COMPARE_UNSIGNED, false);
		}
		rv.visitJumpInsn(ifOpcode(), lblTrue);
	}

	/**
	 * The JVM opcode to perform the conditional jump for unsigned or long integers.
	 * 
	 * This is emitted <em>after</em> the application of {@link #LCMP} or the comparator method.
	 * 
	 * @return the opcode
	 */
	int ifOpcode();

	@Override
	default JitType afterLeft(JitCodeGenerator gen, T op, JitType lType, JitType rType,
			MethodVisitor rv) {
		return TypeConversions.forceUniformZExt(lType, rType, rv);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * This reduces the implementation to a flag for signedness, the opcode for the conditional jump
	 * on integer operands, and the opcode for a conditional jump after the comparison of longs. The
	 * JVM, does not provide conditional jumps on long operands, so we must first compare the longs,
	 * pushing an int onto the stack, and then conditionally jumping on that. This pattern is
	 * similar for unsigned comparison of integers.
	 */
	@Override
	default JitType generateBinOpRunCode(JitCodeGenerator gen, T op, JitBlock block, JitType lType,
			JitType rType, MethodVisitor rv) {
		Label lblTrue = new Label();
		Label lblDone = new Label();

		rType = TypeConversions.forceUniformZExt(rType, lType, rv);
		switch (rType) {
			case IntJitType t -> generateIntJump(lblTrue, rv);
			case LongJitType t -> generateLongJump(lblTrue, rv);
			case MpIntJitType t -> Unfinished.TODO("MpInt");
			default -> throw new AssertionError();
		}
		JitType outType = op.type().resolve(gen.getTypeModel().typeOf(op.out()));
		TypeConversions.generateLdcFalse(outType, rv);
		rv.visitJumpInsn(GOTO, lblDone);
		rv.visitLabel(lblTrue);
		TypeConversions.generateLdcTrue(outType, rv);
		rv.visitLabel(lblDone);

		return outType;
	}
}
