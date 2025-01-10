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
import ghidra.pcode.emu.jit.op.JitBinOp;

/**
 * An extension that provides conveniences and common implementations for binary p-code operators
 * 
 * @param <T> the class of p-code op node in the use-def graph
 */
public interface BinOpGen<T extends JitBinOp> extends OpGen<T> {

	/**
	 * Emit code between reading the left and right operands
	 * 
	 * <p>
	 * This is invoked immediately after emitting code to push the left operand onto the stack,
	 * giving the implementation an opportunity to perform any manipulations of that operand
	 * necessary to set up the operation, before code to push the right operand is emitted.
	 * 
	 * @param gen the code generator
	 * @param op the operator
	 * @param lType the actual type of the left operand
	 * @param rType the actual type of the right operand
	 * @param rv the method visitor
	 * @return the new actual type of the left operand
	 */
	default JitType afterLeft(JitCodeGenerator gen, T op, JitType lType, JitType rType,
			MethodVisitor rv) {
		return lType;
	}

	/**
	 * Emit code for the binary operator
	 * 
	 * <p>
	 * At this point both operands are on the stack. After this returns, code to write the result
	 * from the stack into the destination operand will be emitted.
	 * 
	 * @param gen the code generator
	 * @param op the operator
	 * @param block the block containing the operator
	 * @param lType the actual type of the left operand
	 * @param rType the actual type of the right operand
	 * @param rv the method visitor
	 * @return the actual type of the result
	 */
	JitType generateBinOpRunCode(JitCodeGenerator gen, T op, JitBlock block, JitType lType,
			JitType rType, MethodVisitor rv);

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * This default implementation emits code to load the left operand, invokes the
	 * {@link #afterLeft(JitCodeGenerator, JitBinOp, JitType, JitType, MethodVisitor) after-left}
	 * hook point, emits code to load the right operand, invokes
	 * {@link #generateBinOpRunCode(JitCodeGenerator, JitBinOp, JitBlock, JitType, JitType, MethodVisitor)
	 * generate-binop}, and finally emits code to write the destination operand.
	 */
	@Override
	default void generateRunCode(JitCodeGenerator gen, T op, JitBlock block, MethodVisitor rv) {
		JitType lType = gen.generateValReadCode(op.l(), op.lType());
		JitType rType = op.rType().resolve(gen.getTypeModel().typeOf(op.r()));
		lType = afterLeft(gen, op, lType, rType, rv);
		JitType checkRType = gen.generateValReadCode(op.r(), op.rType());
		assert checkRType == rType;
		JitType outType = generateBinOpRunCode(gen, op, block, lType, rType, rv);
		gen.generateVarWriteCode(op.out(), outType);
	}
}
