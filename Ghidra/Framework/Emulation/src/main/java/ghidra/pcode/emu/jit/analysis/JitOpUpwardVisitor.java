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
package ghidra.pcode.emu.jit.analysis;

import ghidra.pcode.emu.jit.op.*;
import ghidra.pcode.emu.jit.var.JitOutVar;
import ghidra.pcode.emu.jit.var.JitVal;

/**
 * A visitor that traverses the use-def graph upward, that is from uses toward definitions
 */
public interface JitOpUpwardVisitor extends JitOpVisitor {
	@Override
	default void visitUnOp(JitUnOp op) {
		visitVal(op.u());
	}

	@Override
	default void visitBinOp(JitBinOp op) {
		visitVal(op.l());
		visitVal(op.r());
	}

	@Override
	default void visitStoreOp(JitStoreOp op) {
		visitVal(op.offset());
		visitVal(op.value());
	}

	@Override
	default void visitLoadOp(JitLoadOp op) {
		visitVal(op.offset());
	}

	@Override
	default void visitCallOtherOp(JitCallOtherOp otherOp) {
		for (JitVal v : otherOp.args()) {
			visitVal(v);
		}
	}

	@Override
	default void visitCallOtherDefOp(JitCallOtherDefOp otherOp) {
		for (JitVal v : otherOp.args()) {
			visitVal(v);
		}
	}

	@Override
	default void visitCatenateOp(JitCatenateOp op) {
		for (JitVal p : op.parts()) {
			visitVal(p);
		}
	}

	@Override
	default void visitPhiOp(JitPhiOp op) {
		for (JitVal opt : op.options().values()) {
			visitVal(opt);
		}
	}

	@Override
	default void visitSubPieceOp(JitSynthSubPieceOp op) {
		visitVal(op.v());
	}

	@Override
	default void visitCBranchOp(JitCBranchOp op) {
		visitVal(op.cond());
	}

	@Override
	default void visitBranchIndOp(JitBranchIndOp op) {
		visitVal(op.target());
	}

	@Override
	default void visitOutVar(JitOutVar v) {
		visitOp(v.definition());
	}
}
