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

import static ghidra.pcode.emu.jit.gen.GenConsts.MDESC_JIT_COMPILED_PASSAGE__GET_CHAINED;
import static ghidra.pcode.emu.jit.gen.GenConsts.NAME_JIT_COMPILED_PASSAGE;

import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;

import ghidra.pcode.emu.jit.JitPassage.*;
import ghidra.pcode.emu.jit.JitPcodeThread;
import ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock;
import ghidra.pcode.emu.jit.gen.FieldForExitSlot;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage;
import ghidra.pcode.emu.jit.gen.var.VarGen;
import ghidra.pcode.emu.jit.op.JitBranchOp;

/**
 * The generator for a {@link JitBranchOp branch}.
 * 
 * <p>
 * With an {@link IntBranch} record, this simply looks up the label for the target block and emits a
 * block transition followed by a {@link #GOTO goto}.
 * 
 * <p>
 * With an {@link ExtBranch} record, this emits code to retire the target to the program counter,
 * along with the target context and live variables. It then emits code to request the chained entry
 * point from the target's exit slot and return it. The {@link JitPcodeThread thread} can then
 * immediately execute the chained passage entry.
 */
public enum BranchOpGen implements OpGen<JitBranchOp> {
	/** The generator singleton */
	GEN;

	/**
	 * Emit code that exits via a direct branch
	 * 
	 * <p>
	 * This emits the {@link ExtBranch} record case.
	 * 
	 * @param gen the code generator
	 * @param exit the target causing us to exit
	 * @param block the block containing the op
	 * @param rv the visitor for the {@link JitCompiledPassage#run(int) run} method
	 */
	static void generateExtBranchCode(JitCodeGenerator gen, AddrCtx exit, JitBlock block,
			MethodVisitor rv) {
		FieldForExitSlot slotField = gen.requestFieldForExitSlot(exit);

		gen.generatePassageExit(block, () -> {
			// [...]
			rv.visitLdcInsn(exit.address.getOffset());
			// [...,target:LONG]
		}, exit.rvCtx, rv);

		// []
		slotField.generateLoadCode(gen, rv);
		// [slot]
		rv.visitMethodInsn(INVOKESTATIC, NAME_JIT_COMPILED_PASSAGE, "getChained",
			MDESC_JIT_COMPILED_PASSAGE__GET_CHAINED, true);
		// [chained:ENTRY]
		rv.visitInsn(ARETURN);
	}

	@Override
	public void generateRunCode(JitCodeGenerator gen, JitBranchOp op, JitBlock block,
			MethodVisitor rv) {

		switch (op.branch()) {
			case IntBranch ib -> {
				JitBlock target = block.getTargetBlock(ib);
				Label label = gen.labelForBlock(target);
				VarGen.computeBlockTransition(gen, block, target).generate(rv);
				rv.visitJumpInsn(GOTO, label);
			}
			case ExtBranch eb -> {
				generateExtBranchCode(gen, eb.to(), block, rv);
			}
			default -> throw new AssertionError("Branch type confusion");
		}
	}
}
