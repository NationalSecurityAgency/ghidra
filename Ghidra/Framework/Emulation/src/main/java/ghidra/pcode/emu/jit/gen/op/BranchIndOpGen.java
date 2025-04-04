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

import ghidra.pcode.emu.jit.JitPassage.RIndBranch;
import ghidra.pcode.emu.jit.JitPcodeThread;
import ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock;
import ghidra.pcode.emu.jit.analysis.JitType;
import ghidra.pcode.emu.jit.analysis.JitType.LongJitType;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.gen.op.BranchOpGen.BranchGen;
import ghidra.pcode.emu.jit.gen.type.TypeConversions;
import ghidra.pcode.emu.jit.op.JitBranchIndOp;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.RegisterValue;

/**
 * The generator for a {@link JitBranchIndOp branchind}.
 * 
 * <p>
 * This emits code to load the target from the operand and then retire it to the program counter,
 * along with the current flow context and live variables. It then emits code to return null so that
 * the {@link JitPcodeThread thread} knows to loop to the <b>Fetch</b> step for the new counter.
 */
public enum BranchIndOpGen implements OpGen<JitBranchIndOp> {
	/** The generator singleton */
	GEN;

	/**
	 * Generate code to retire the variables, write the dynamic pc value, and return from the
	 * passage
	 * 
	 * @param gen the code generator
	 * @param op the op
	 * @param ctx the context to write at exit, or null to not write the context
	 * @param block the block containing the op
	 * @param rv the run method visitor
	 */
	static void generateExitCode(JitCodeGenerator gen, JitBranchIndOp op, RegisterValue ctx,
			JitBlock block, MethodVisitor rv) {
		gen.generatePassageExit(block, () -> {
			// [...]
			JitType targetType = gen.generateValReadCode(op.target(), op.targetType());
			// [...,target:?]
			TypeConversions.generateToLong(targetType, LongJitType.I8, rv);
			// [...,target:LONG]
		}, ctx, rv);

		rv.visitInsn(ACONST_NULL);
		rv.visitInsn(ARETURN);
	}

	/**
	 * A branch code generator for indirect branches
	 */
	static class IndBranchGen extends BranchGen<RIndBranch, JitBranchIndOp> {
		/** Singleton */
		static final IndBranchGen IND = new IndBranchGen();

		@Override
		Address exit(JitCodeGenerator gen, RIndBranch branch) {
			return null;
		}

		@Override
		void generateCodeWithoutCtxmod(JitCodeGenerator gen, JitBranchIndOp op, RIndBranch branch,
				JitBlock block, MethodVisitor rv) {
			generateExitCode(gen, op, branch.flowCtx(), block, rv);
		}

		@Override
		void generateCodeWithCtxmod(JitCodeGenerator gen, JitBranchIndOp op, Address exit,
				JitBlock block, MethodVisitor rv) {
			generateExitCode(gen, op, null, block, rv);
		}
	}

	@Override
	public void generateRunCode(JitCodeGenerator gen, JitBranchIndOp op, JitBlock block,
			MethodVisitor rv) {
		IndBranchGen.IND.generateCode(gen, op, op.branch(), block, rv);
	}
}
