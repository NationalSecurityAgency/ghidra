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

import static ghidra.pcode.emu.jit.gen.GenConsts.MDESC_JIT_COMPILED_PASSAGE__MP_INT_BINOP;
import static ghidra.pcode.emu.jit.gen.GenConsts.NAME_JIT_COMPILED_PASSAGE;

import org.objectweb.asm.MethodVisitor;

import ghidra.pcode.emu.jit.analysis.JitAllocationModel;
import ghidra.pcode.emu.jit.analysis.JitAllocationModel.JvmTempAlloc;
import ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock;
import ghidra.pcode.emu.jit.analysis.JitType;
import ghidra.pcode.emu.jit.analysis.JitType.MpIntJitType;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage;
import ghidra.pcode.emu.jit.gen.type.TypeConversions.Ext;
import ghidra.pcode.emu.jit.op.JitBinOp;

/**
 * An extension that provides conveniences and common implementations for binary p-code operators
 * 
 * @param <T> the class of p-code op node in the use-def graph
 */
public interface BinOpGen<T extends JitBinOp> extends OpGen<T> {

	/**
	 * A choice of static method parameter to take as operator output
	 */
	enum TakeOut {
		/**
		 * The out (first) parameter
		 */
		OUT,
		/**
		 * The left (second) parameter
		 */
		LEFT;
	}

	/**
	 * Emit bytecode that implements an mp-int binary operator via delegation to a static method on
	 * {@link JitCompiledPassage}. The method must have the signature:
	 * 
	 * <pre>
	 * void method(int[] out, int[] inL, int[] inR);
	 * </pre>
	 * 
	 * <p>
	 * This method presumes that the left operand's legs are at the top of the stack,
	 * least-significant leg on top, followed by the right operand legs, also least-significant leg
	 * on top. This will allocate the output array, move the operands into their respective input
	 * arrays, invoke the method, and then place the result legs on the stack, least-significant leg
	 * on top.
	 * 
	 * @param gen the code generator
	 * @param type the type of the operands
	 * @param methodName the name of the method in {@link JitCompiledPassage} to invoke
	 * @param mv the method visitor
	 * @param overProvisionLeft the number of extra ints to allocate for the left operand's array.
	 *            This is to facilitate Knuth's division algorithm, which may require an extra
	 *            leading leg in the dividend after normalization.
	 * @param takeOut indicates which operand of the static method to actually take for the output.
	 *            This is to facilitate the remainder operator, because Knuth's algorithm leaves the
	 *            remainder where there dividend was.
	 */
	static void generateMpDelegationToStaticMethod(JitCodeGenerator gen, MpIntJitType type,
			String methodName, MethodVisitor mv, int overProvisionLeft, TakeOut takeOut) {
		/**
		 * The strategy here will be to allocate an array for each of the operands (output and 2
		 * inputs) and then invoke a static method to do the actual operation. It might be nice to
		 * generate inline code for small multiplications, but we're going to leave that for later.
		 */
		// [lleg1,...,llegN,rleg1,...,rlegN]
		JitAllocationModel am = gen.getAllocationModel();
		int legCount = type.legsAlloc();
		try (
				JvmTempAlloc tmpL = am.allocateTemp(mv, "tmpL", legCount);
				JvmTempAlloc tmpR = am.allocateTemp(mv, "tmpR", legCount)) {
			// [rleg1,...,rlegN,lleg1,...,llegN]
			OpGen.generateMpLegsIntoTemp(tmpR, legCount, mv);
			// [lleg1,...,llegN]
			OpGen.generateMpLegsIntoTemp(tmpL, legCount, mv);
			// []

			switch (takeOut) {
				case OUT -> {
					// []
					mv.visitLdcInsn(legCount);
					// [count:INT]
					mv.visitIntInsn(NEWARRAY, T_INT);
					// [out:INT[count]]
					mv.visitInsn(DUP);
					// [out,out]

					OpGen.generateMpLegsIntoArray(tmpL, legCount + overProvisionLeft, legCount, mv);
					// [inL,out,out]
					OpGen.generateMpLegsIntoArray(tmpR, legCount, legCount, mv);
					// [inR,inL,out,out]
				}
				case LEFT -> {
					// []
					mv.visitLdcInsn(legCount);
					// [count:INT]
					mv.visitIntInsn(NEWARRAY, T_INT);
					// [out]
					OpGen.generateMpLegsIntoArray(tmpL, legCount + overProvisionLeft, legCount, mv);
					// [inL,out]
					mv.visitInsn(DUP_X1);
					// [inL,out,inL]
					OpGen.generateMpLegsIntoArray(tmpR, legCount, legCount, mv);
					// [inR,inL,out,inL]
				}
				default -> throw new AssertionError();
			}
		}

		mv.visitMethodInsn(INVOKESTATIC, NAME_JIT_COMPILED_PASSAGE, methodName,
			MDESC_JIT_COMPILED_PASSAGE__MP_INT_BINOP, true);
		// [out||inL:INT[count]]

		// Push the result back, in reverse order
		OpGen.generateMpLegsFromArray(legCount, mv);
	}

	/**
	 * Whether this operator is signed
	 * <p>
	 * In many cases, the operator itself is not affected by the signedness of the operands;
	 * however, if size adjustments to the operands are needed, this can determine how those
	 * operands are extended.
	 * 
	 * @return true for signed, false if not
	 */
	boolean isSigned();

	/**
	 * When loading and storing variables, the kind of extension to apply
	 * 
	 * @return the extension kind
	 */
	default Ext ext() {
		return Ext.forSigned(isSigned());
	}

	/**
	 * When loading the right operand, the kind of extension to apply
	 * 
	 * @return the extension kind
	 */
	default Ext rExt() {
		return ext();
	}

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
		JitType lType = gen.generateValReadCode(op.l(), op.lType(), ext());
		JitType rType = op.rType().resolve(gen.getTypeModel().typeOf(op.r()));
		lType = afterLeft(gen, op, lType, rType, rv);
		JitType checkRType = gen.generateValReadCode(op.r(), op.rType(), rExt());
		assert checkRType == rType;
		JitType outType = generateBinOpRunCode(gen, op, block, lType, rType, rv);
		gen.generateVarWriteCode(op.out(), outType, Ext.ZERO);
	}
}
