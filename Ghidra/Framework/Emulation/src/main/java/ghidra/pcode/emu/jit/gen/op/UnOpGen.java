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

import ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock;
import ghidra.pcode.emu.jit.analysis.JitType;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.op.JitUnOp;

/**
 * An extension that provides conveniences and common implementations for unary p-code operators
 * 
 * @param <T> the class of p-code op node in the use-def graph
 */
public interface UnOpGen<T extends JitUnOp> extends OpGen<T> {

	/**
	 * Emit code for the unary operator
	 * 
	 * <p>
	 * At this point the operand is on the stack. After this returns, code to write the result from
	 * the stack into the destination operand will be emitted.
	 * 
	 * @param gen the code generator
	 * @param op the operator
	 * @param block the block containing the operator
	 * @param uType the actual type of the operand
	 * @param rv the method visitor
	 * @return the actual type of the result
	 */
	JitType generateUnOpRunCode(JitCodeGenerator gen, T op, JitBlock block, JitType uType,
			MethodVisitor rv);

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * This default implementation emits code to load the operand, invokes
	 * {@link #generateUnOpRunCode(JitCodeGenerator, JitUnOp, JitBlock, JitType, MethodVisitor)
	 * gen-unop}, and finally emits code to write the destination operand.
	 */
	@Override
	default void generateRunCode(JitCodeGenerator gen, T op, JitBlock block, MethodVisitor rv) {
		JitType uType = gen.generateValReadCode(op.u(), op.uType());
		JitType outType = generateUnOpRunCode(gen, op, block, uType, rv);
		gen.generateVarWriteCode(op.out(), outType);
	}
}
