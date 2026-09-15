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
package ghidra.pcode.emu.jit.folding;

import java.util.*;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.lifecycle.Internal;
import ghidra.lifecycle.Unfinished;
import ghidra.pcode.emu.jit.JitPassage.*;
import ghidra.pcode.emu.jit.decode.CollectExecutor;
import ghidra.pcode.emu.jit.decode.DecoderForOnePassage;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.PcodeUseropLibrary.PcodeUseropDefinition;
import ghidra.program.model.pcode.PcodeOp;

/**
 * A mechanism for re-validating the folded constants discovered during decode
 * <p>
 * Because alternative flows into a block can be discovered during decode, after that block's
 * computations were already examined for folded constants, blocks must generally be re-examined
 * with all discovered flows considered. We also have to consider that a block that becomes an entry
 * point into the passage may have <em>no</em> incoming folded constants.
 * <p>
 * The algorithm is basically a forward traversal of block flows until we reach convergence. We
 * haven't performed full control-flow analysis at this point, so we just follow branches and merge
 * as we go. If the target is also an entry point, we erase all the folded constants in the "merged"
 * state. Otherwise, we merge with the state at the target and re-queue it for interpretation.
 * Merging consists of taking only those constants common to both states, and where those constants
 * have the same value. If merging produces the same state as was already there, that target is
 * <em>not</em> re-queued. Convergence occurs when the queue is empty. LATER: Prove it?
 */
@Internal
public class FoldRevalidator {
	final DecoderForOnePassage passage;
	final List<PcodeOp> code;

	final Map<PcodeOp, Integer> where = new HashMap<>(); // ick
	final Map<PcodeOp, RIntBranch> invertedBranches = new HashMap<>();
	final Map<PcodeOp, FoldedState> stateMap = new HashMap<>();
	final Deque<PcodeOp> queue = new LinkedList<>();

	/**
	 * Begin re-validating a decoded passage
	 * 
	 * @param passage the (mutable) decoded passage
	 */
	public FoldRevalidator(DecoderForOnePassage passage) {
		this.passage = passage;
		this.code = passage.strides.stream().flatMap(b -> b.ops().stream()).toList();

		PcodeOp entry = passage.strides.getFirst().ops().getFirst();
		this.stateMap.put(entry, new FoldedState(passage.decoder.thread.getLanguage()));
		this.queue.add(entry);

		for (int i = 0; i < code.size(); i++) {
			where.put(code.get(i), i);
		}

		for (RIntBranch br : passage.internalBranches.values()) {
			invertedBranches.put(br.to(), br);
		}
	}

	/**
	 * The interpreter for re-validation
	 */
	protected class RevalidateExecutor extends FoldingExecutor {
		private final PcodeOp next;

		protected RevalidateExecutor(DecoderForOnePassage passage, PcodeOp next) {
			super(passage, stateMap.get(next).fork());
			this.next = next;
		}

		void mergeAndQueue(PcodeOp to) {
			FoldedState exists = stateMap.get(to);
			if (exists == null) {
				FoldedState choice = isEntry(to) ? new FoldedState(language) : state.fork();
				stateMap.put(to, choice);
				queue.add(to);
				return;
			}
			/**
			 * Don't use .clear(). 1) It doesn't provide feedback as to whether or not the state
			 * changed. 2) We'd need logic to assure clearing out 00-masked bytes does not count as
			 * "changed." Intersecting with empty gets what we need, though at mildly greater cost.
			 */
			FoldedState choice = isEntry(to) ? new FoldedState(language) : state;
			if (exists.intersectInPlace(choice)) {
				queue.add(to);
			}
		}

		@Override
		public void stepOp(PcodeOp op, PcodeFrame frame,
				PcodeUseropLibrary<MaskedBytes> library) {
			if (op != next) {
				RIntBranch br = invertedBranches.get(op);
				if (br != null) {
					mergeAndQueue(op);
					frame.finishAsBranch();
					return;
				}
			}
			if (op.getOpcode() == PcodeOp.UNIMPLEMENTED) {
				// Ignore these
				// Don't just override badOp, because any unrecognized op goes there.
				return;
			}
			super.stepOp(op, frame, library);
		}

		@Override
		protected void doExecuteBranch(PcodeOp op, PcodeFrame frame) {
			RIntBranch branch = passage.internalBranches.get(op);
			if (branch == null) {
				// An external or other branch
				return;
			}
			PcodeOp to = branch.to();
			mergeAndQueue(to);
		}

		@Override
		public void executeBranch(PcodeOp op, PcodeFrame frame) {
			doExecuteBranch(op, frame);
			frame.finishAsBranch();
		}

		@Override
		public void executeCall(PcodeOp op, PcodeFrame frame,
				PcodeUseropLibrary<MaskedBytes> library) {
			doExecuteBranch(op, frame);
			frame.finishAsBranch();
		}

		@Override
		public void executeConditionalBranch(PcodeOp op, PcodeFrame frame) {
			super.executeConditionalBranch(op, frame);
			doExecuteBranch(op, frame);
			int fallIndex = frame.index();
			// Could be fall to external. Ensure the op is actually in the program
			if (fallIndex < frame.getCode().size()) {
				PcodeOp to = frame.getCode().get(fallIndex);
				mergeAndQueue(to);
			}
			frame.finishAsBranch();
		}

		@Override
		protected void doExecuteIndirectBranch(PcodeOp op, PcodeFrame frame) {
			// Don't worry whether the target is still a valid constant at this point.
			// Ensure the speculative block is still covered.
			// We could encode a conditional branch to it, if the actual target matches.
			doExecuteBranch(op, frame);
			frame.finishAsBranch();
		}

		@Override
		public void executeCallother(PcodeOp op, PcodeFrame frame,
				PcodeUseropLibrary<MaskedBytes> library) {
			PcodeUseropDefinition<?> opDef = getUserop(op, frame, library);
			if (opDef != null && opDef.canInlinePcode()) {
				CollectExecutor collect = new CollectExecutor(language, state, reason, () -> {
					DecodedPcodeOp decOp = (DecodedPcodeOp) op;
					AddrCtx at = decOp.getAt();
					return passage.decoder.decodeInstruction(at.address, at.rvCtx);
				});
				collect.executeCallother(op, frame, library);

				if (!passage.checkSameInline(op, collect.ops)) {
					throw new Unfinished.TODOException();
					/**
					 * TODO: We'll need to remove old and insert new, which may involve re-executing
					 * and re-recording the same and possible additional inlines. This will also
					 * involve removing branches to or from the inlined ops.
					 * 
					 * TODO: Some attention to the branches. My inclination is to make all branches,
					 * internal or not, behave like an exit. Library authors ought never to insert
					 * new instruction branches if folding fails, no?
					 * 
					 * Another option is to just not inline it....
					 */
				}
				/**
				 * The inlined ops are already queued up, so don't actually "execute" the userop
				 * again.
				 */
				return;
			}
			super.executeCallother(op, frame, library);
		}

		@Override
		protected void onMissingUseropDef(PcodeOp op, PcodeFrame frame, String opName,
				PcodeUseropLibrary<MaskedBytes> library) {
			// The decoder has already created an ErrBranch for it.
		}
	}

	/**
	 * A portion of a p-code program
	 * <p>
	 * Because we are "extracting" from a given start to the next branch, we generally don't need to
	 * specify the end, as the interpreter will naturally end at that branch.
	 */
	class SubProgram extends PcodeProgram {
		/**
		 * Construct a sub-program
		 * 
		 * @param full the full program
		 * @param start which op to start on
		 */
		SubProgram(List<PcodeOp> full, PcodeOp start) {
			SleighLanguage language = passage.decoder.thread.getLanguage();
			super(language, full.subList(where.get(start), full.size()),
				passage.decoder.library.getSymbols(language));
		}
	}

	/**
	 * Check if a given p-code op is a passage entry
	 * 
	 * @param op the op
	 * @return true if it is an entry
	 */
	boolean isEntry(PcodeOp op) {
		if (!(op instanceof DecodedPcodeOp dec)) {
			return false;
		}
		return passage.firstOps.get(dec.getAt()) == dec;
	}

	/**
	 * Re-validate folded constants
	 * <p>
	 * I had worried this algorithm could get expensive with loops with a counter. I thought perhaps
	 * with bit-level tricks in INT_ADD/SUB, the varnode would get invalidated one bit per
	 * re-interpretation of the loop. However, INT_ADD would invalidate all higher order bits of an
	 * unknown bit all at once.
	 */
	public void revalidate() {
		while (!queue.isEmpty()) {
			PcodeOp next = queue.pollFirst();
			FoldingExecutor exec = new RevalidateExecutor(passage, next);
			exec.execute(new SubProgram(code, next));
		}
	}
}
