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
import ghidra.pcode.emu.jit.var.*;

/**
 * A visitor for traversing the use-def graph
 * 
 * <p>
 * The default implementations here do nothing other than discern the type of an op and variable and
 * dispatch the invocations appropriately. To traverse the graph upward, consider
 * {@link JitOpUpwardVisitor}. Note no "downward" visitor is currently provided, because it was not
 * needed.
 */
public interface JitOpVisitor {

	/**
	 * Visit an op node
	 * 
	 * <p>
	 * The default implementation dispatches this to the type-specific {@code visit} method.
	 * 
	 * @param op the op visited
	 */
	default void visitOp(JitOp op) {
		switch (op) {
			case null -> throw new NullPointerException("null op");
			case JitUnOp unOp -> visitUnOp(unOp);
			case JitBinOp binOp -> visitBinOp(binOp);
			case JitStoreOp storeOp -> visitStoreOp(storeOp);
			case JitLoadOp loadOp -> visitLoadOp(loadOp);
			case JitCallOtherOp otherOp -> visitCallOtherOp(otherOp);
			case JitCallOtherDefOp otherOp -> visitCallOtherDefOp(otherOp);
			case JitCallOtherMissingOp otherOp -> visitCallOtherMissingOp(otherOp);
			case JitCatenateOp catOp -> visitCatenateOp(catOp);
			case JitPhiOp phiOp -> visitPhiOp(phiOp);
			case JitSynthSubPieceOp pieceOp -> visitSubPieceOp(pieceOp);
			case JitBranchOp branchOp -> visitBranchOp(branchOp);
			case JitCBranchOp cBranchOp -> visitCBranchOp(cBranchOp);
			case JitBranchIndOp branchIndOp -> visitBranchIndOp(branchIndOp);
			case JitUnimplementedOp unimplOp -> visitUnimplementedOp(unimplOp);
			case JitNopOp nopOp -> visitNopOp(nopOp);
			default -> throw new AssertionError("Unrecognized op: " + op);
		}
	}

	/**
	 * Visit a {@link JitUnOp}
	 * 
	 * @param unOp the op visited
	 */
	default void visitUnOp(JitUnOp unOp) {
	}

	/**
	 * Visit a {@link JitBinOp}
	 * 
	 * @param binOp the op visited
	 */
	default void visitBinOp(JitBinOp binOp) {
	}

	/**
	 * Visit a {@link JitStoreOp}
	 * 
	 * @param storeOp the op visited
	 */
	default void visitStoreOp(JitStoreOp storeOp) {
	}

	/**
	 * Visit a {@link JitLoadOp}
	 * 
	 * @param loadOp the op visited
	 */
	default void visitLoadOp(JitLoadOp loadOp) {
	}

	/**
	 * Visit a {@link JitCallOtherOp}
	 * 
	 * @param otherOp the op visited
	 */
	default void visitCallOtherOp(JitCallOtherOp otherOp) {
	}

	/**
	 * Visit a {@link JitCallOtherDefOp}
	 * 
	 * @param otherOp the op visited
	 */
	default void visitCallOtherDefOp(JitCallOtherDefOp otherOp) {
	}

	/**
	 * Visit a {@link JitCallOtherMissingOp}
	 * 
	 * @param otherOp the op visited
	 */
	default void visitCallOtherMissingOp(JitCallOtherMissingOp otherOp) {
	}

	/**
	 * Visit a {@link JitCatenateOp}
	 * 
	 * @param catOp the op visited
	 */
	default void visitCatenateOp(JitCatenateOp catOp) {
	}

	/**
	 * Visit a {@link JitPhiOp}
	 * 
	 * @param phiOp the op visited
	 */
	default void visitPhiOp(JitPhiOp phiOp) {
	}

	/**
	 * Visit a {@link JitSynthSubPieceOp}
	 * 
	 * @param pieceOp the op visited
	 */
	default void visitSubPieceOp(JitSynthSubPieceOp pieceOp) {
	}

	/**
	 * Visit a {@link JitBranchOp}
	 * 
	 * @param branchOp the op visited
	 */
	default void visitBranchOp(JitBranchOp branchOp) {
	}

	/**
	 * Visit a {@link JitCBranchOp}
	 * 
	 * @param cBranchOp the op visited
	 */
	default void visitCBranchOp(JitCBranchOp cBranchOp) {
	}

	/**
	 * Visit a {@link JitBranchIndOp}
	 * 
	 * @param branchIndOp the op visited
	 */
	default void visitBranchIndOp(JitBranchIndOp branchIndOp) {
	}

	/**
	 * Visit a {@link JitUnimplementedOp}
	 * 
	 * @param unimplOp the op visited
	 */
	default void visitUnimplementedOp(JitUnimplementedOp unimplOp) {
	}

	/**
	 * Visit a {@link JitNopOp}
	 * 
	 * @param nopOp the op visited
	 */
	default void visitNopOp(JitNopOp nopOp) {
	}

	/**
	 * Visit a {@link JitVal}
	 * 
	 * <p>
	 * The default implementation dispatches this to the type-specific {@code visit} method.
	 * 
	 * @param v the value visited
	 */
	default void visitVal(JitVal v) {
		switch (v) {
			case JitConstVal constVal -> visitConstVal(constVal);
			case JitFailVal failVal -> visitFailVal(failVal);
			case JitVar jVar -> visitVar(jVar);
			default -> throw new AssertionError();
		}
	}

	/**
	 * Visit a {@link JitVar}
	 * 
	 * <p>
	 * The default implementation dispatches this to the type-specific {@code visit} method.
	 * 
	 * @param v the variable visited
	 */
	default void visitVar(JitVar v) {
		switch (v) {
			case JitInputVar inputVar -> visitInputVar(inputVar);
			case JitMissingVar missingVar -> visitMissingVar(missingVar);
			case JitOutVar outVar -> visitOutVar(outVar);
			case JitDirectMemoryVar dirMemVar -> visitDirectMemoryVar(dirMemVar);
			case JitIndirectMemoryVar indMemVar -> visitIndirectMemoryVar(indMemVar);
			default -> throw new AssertionError();
		}
	}

	/**
	 * Visit a {@link JitConstVal}
	 * 
	 * @param constVal the value visited
	 */
	default void visitConstVal(JitConstVal constVal) {
	}

	/**
	 * Visit a {@link JitFailVal}
	 * 
	 * @param failVal the value visited
	 */
	default void visitFailVal(JitFailVal failVal) {
	}

	/**
	 * Visit a {@link JitDirectMemoryVar}
	 * 
	 * @param dirMemVar the variable visited
	 */
	default void visitDirectMemoryVar(JitDirectMemoryVar dirMemVar) {
	}

	/**
	 * Visit a {@link JitIndirectMemoryVar}
	 * 
	 * <p>
	 * NOTE: These should not ordinarily appear in the use-def graph. There is only the one
	 * {@link JitIndirectMemoryVar#INSTANCE}, and it's used as a temporary dummy. Indirect memory
	 * access is instead modeled by the {@link JitLoadOp}.
	 * 
	 * @param indMemVar the variable visited
	 */
	default void visitIndirectMemoryVar(JitIndirectMemoryVar indMemVar) {
		throw new AssertionError();
	}

	/**
	 * Visit a {@link JitInputVar}
	 * 
	 * @param inputVar the variable visited
	 */
	default void visitInputVar(JitInputVar inputVar) {
	}

	/**
	 * Visit a {@link JitMissingVar}
	 * 
	 * @param missingVar the variable visited
	 */
	default void visitMissingVar(JitMissingVar missingVar) {
	}

	/**
	 * Visit a {@link JitOutVar}
	 * 
	 * @param outVar the variable visited
	 */
	default void visitOutVar(JitOutVar outVar) {
	}
}
