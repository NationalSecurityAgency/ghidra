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

import java.util.*;

import ghidra.pcode.emu.jit.*;
import ghidra.pcode.emu.jit.JitCompiler.Diag;
import ghidra.pcode.emu.jit.JitPassage.*;
import ghidra.pcode.emu.jit.decode.DecoderForOneStride;
import ghidra.pcode.emu.jit.gen.JitCodeGenerator;
import ghidra.pcode.emu.jit.gen.tgt.JitCompiledPassage;
import ghidra.pcode.exec.PcodeProgram;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.SequenceNumber;

/**
 * The control flow analysis for JIT-accelerated emulation.
 * 
 * <p>
 * This implements the Control Flow Analysis phase of the {@link JitCompiler}. Some rudimentary
 * analysis is performed during passage decoding &mdash; note the {@link BlockSplitter} is exported
 * for use in {@link DecoderForOneStride}. This is necessary to evaluate whether an instruction
 * (especially an inject-instrumented instruction) has fall-through. Without that information, the
 * decoder cannot know whether it has reached the end of its stride. Note that the decoder records
 * all the branches it encounters and includes them as metadata in the passage. Because branches
 * need to record the source and target p-code op, the decoder is well suited. Additionally, it has
 * to compute these anyway, and we'd rather avoid duplicative work by this analyzer.
 * 
 * <p>
 * The decoded passage contains a good deal of information, but the primary inputs at this point are
 * the ordered list of p-code ops and the branches. This model's primary responsibility is to break
 * the passage down into basic blocks at the p-code level. Even though the p-code ops have all been
 * concatenated together when constructing the passage, we know, by definition, that each stride
 * will end with an unconditional branch (or else a synthesized {@link ExitPcodeOp}. Note also that
 * {@link JitPassage#getBranches()} only includes the non-fall-through branches, because these are
 * all that are recorded by the decoder. Thus, it is also this model's responsibility to create the
 * fall-through branches. These will occur to represent the "false" case of any conditional
 * branches, and to represent "unconditional fall through."
 * 
 * <p>
 * The algorithm for this is fairly straightforward and has been implemented primarily in
 * {@link BlockSplitter}. Most everything else in this class is data management and the types
 * representing the model.
 * 
 * <p>
 * <b>NOTE:</b> It is technically possible for a userop to branch, but this analysis does not
 * consider that. Instead, the emulator will decide how to handle those. Conventionally, I'd rather
 * a userop <em>never</em> perform control flow. Instead, I'd rather see things like
 * <code>pc = my_control_op(); goto [pc];</code>.
 */
public class JitControlFlowModel {

	/**
	 * An exception thrown when control flow might run off the edge of the passage.
	 * 
	 * <p>
	 * By definition a passage is a collection of strides, and each stride is terminated by some op
	 * without fall through (or else a synthesized {@link ExitPcodeOp}. In particular, the last
	 * stride cannot end in fall through. If it did, there would be no op for it to fall through to.
	 * While this should never happen, it is easy in the course of development to allow it by
	 * accident. The control flow analysis can detect this as it finished splitting the passage into
	 * blocks. If the final block has fall through, the passage is said to have "unterminated flow,"
	 * and this exception is thrown. We do not wait until execution of the passage to throw this. It
	 * is thrown during translation, as it represents an assertion failure in the translation
	 * process. That is, the decoder produced an unsound passage.
	 */
	public static class UnterminatedFlowException extends IllegalArgumentException {
		/**
		 * Construct the exception
		 */
		public UnterminatedFlowException() {
			super("Final block cannot fall through");
		}
	}

	/**
	 * A flow from one block to another
	 * 
	 * <p>
	 * This is just a wrapper around an {@link IntBranch} that allows us to quickly identify what
	 * two blocks it connects. Note that to connect two blocks in the passage, the branch must by
	 * definition be an {@link IntBranch}.
	 * 
	 * <p>
	 * If this flow represents entry into the passage, then {@link #from()} and {@link #branch()}
	 * may be null
	 * 
	 * @param from the block from which execution flows. In the case of a non-fall-through branch,
	 *            the block should end with the branching p-code op. For conditional fall-through,
	 *            it should end with the {@link PcodeOp#CBRANCH} op. For unconditional fall-through,
	 *            it could end with any op having fall through.
	 * @param to the block to which execution flows. The block must start with the
	 *            {@link IntBranch#to() target op} of the branch.
	 * @param branch the branch effecting the flow of execution
	 */
	public record BlockFlow(JitBlock from, JitBlock to, IntBranch branch) {
		/**
		 * Create an entry flow to the given block
		 * 
		 * @param to the block to which execution flows
		 * @return the flow
		 */
		public static BlockFlow entry(JitBlock to) {
			return new BlockFlow(null, to, null);
		}
	}

	/**
	 * A basic block of p-code
	 * 
	 * <p>
	 * This follows the formal definition of a basic block, but at the p-code level. All flows into
	 * the block enter at its first op, and all flows out of the block exit at its last op. The
	 * block also contains information about these flows as well as branches out of the passage via
	 * this block.
	 */
	public static class JitBlock extends PcodeProgram {
		private Map<IntBranch, BlockFlow> flowsFrom = new HashMap<>();
		private Map<IntBranch, BlockFlow> flowsTo = new HashMap<>();
		private List<IntBranch> branchesFrom = new ArrayList<>();
		private List<IntBranch> branchesTo = new ArrayList<>();
		private List<Branch> branchesOut = new ArrayList<>();

		private final int instructions;
		private final int trailingOps;

		/**
		 * Construct a new block
		 * 
		 * @param program the program (i.e., passage) from which this block is derived
		 * @param code the subset of ops, in execution order, comprising this block
		 */
		public JitBlock(PcodeProgram program, List<PcodeOp> code) {
			super(program, List.copyOf(code));

			int instructions = 0;
			int trailingOps = 0;
			for (PcodeOp op : code) {
				if (op instanceof DecodedPcodeOp dec && dec.isInstructionStart()) {
					instructions++;
					trailingOps = 0;
				}
				else if (op instanceof DecodedPcodeOp) {
					trailingOps++;
				}
			}
			this.instructions = instructions;
			this.trailingOps = trailingOps;
		}

		@Override
		protected String getHead() {
			return super.getHead() + "[start=" + start() + "]";
		}

		@Override
		public String toString() {
			return getHead();
		}

		/**
		 * Get the first p-code op in this block
		 * 
		 * @return the first p-code op
		 */
		public PcodeOp first() {
			return code.getFirst();
		}

		/**
		 * Get the sequence number of the first op
		 * 
		 * <p>
		 * This is used for display and testing purposes only.
		 * 
		 * @return the sequence number
		 */
		public SequenceNumber start() {
			return code.getFirst().getSeqnum();
		}

		/**
		 * Get the sequence number of the last op
		 * 
		 * <p>
		 * This is used for display and testing purposes only.
		 * 
		 * @return the sequence number
		 */
		public SequenceNumber end() {
			return code.getLast().getSeqnum();
		}

		/**
		 * Convert our collections to immutable ones
		 */
		private void cook() {
			flowsFrom = Collections.unmodifiableMap(flowsFrom);
			flowsTo = Collections.unmodifiableMap(flowsTo);
			branchesFrom = Collections.unmodifiableList(branchesFrom);
			branchesTo = Collections.unmodifiableList(branchesTo);
			branchesOut = Collections.unmodifiableList(branchesOut);
		}

		/**
		 * Get (internal) flows leaving this block
		 * 
		 * @return the flows, keyed by branch
		 */
		public Map<IntBranch, BlockFlow> flowsFrom() {
			return flowsFrom;
		}

		/**
		 * Get (internal) flows entering this block
		 * 
		 * @return the flows, keyed by branch
		 */
		public Map<IntBranch, BlockFlow> flowsTo() {
			return flowsTo;
		}

		/**
		 * Get internal branches leaving this block
		 * 
		 * @return the list of branches
		 */
		public List<IntBranch> branchesFrom() {
			return branchesFrom;
		}

		/**
		 * Get internal branches entering this block
		 * 
		 * @return the list of branches
		 */
		public List<IntBranch> branchesTo() {
			return branchesTo;
		}

		/**
		 * Get branches leaving the passage from this block
		 * 
		 * @return the list of branches
		 */
		public List<Branch> branchesOut() {
			return branchesOut;
		}

		/**
		 * If this block has fall through, find the block into which it falls
		 * 
		 * @return the block, or {@code null}
		 */
		public JitBlock getFallFrom() {
			return flowsFrom.values()
					.stream()
					.filter(f -> f.branch.isFall())
					.findAny()
					.map(f -> f.to)
					.orElse(null);
		}

		/**
		 * Check if there is an internal non-fall-through branch to this block
		 * 
		 * <p>
		 * This is used by the {@link JitCodeGenerator} to determine whether or not a block's
		 * bytecode needs to be labeled.
		 * 
		 * @return true if this block is targeted by a branch
		 */
		public boolean hasJumpTo() {
			return flowsTo.values().stream().anyMatch(f -> !f.branch.isFall());
		}

		/**
		 * Get the target block for the given internal branch, assuming it's from this block
		 * 
		 * @param branch the branch
		 * @return the target block or null
		 */
		public JitBlock getTargetBlock(IntBranch branch) {
			return flowsFrom.get(branch).to;
		}

		/**
		 * Get the number of instructions represented in this block
		 * 
		 * <p>
		 * This may get dicey as blocks are not necessarily split on instruction boundaries.
		 * Nevertheless, we seek to count the number of instructions executed at runtime, so that we
		 * can replay an execution, step in reverse, etc. What we actually do here is count the
		 * number of ops which are the first op produced by a decoded instruction.
		 * 
		 * @see JitCompiledPassage#count(int, int)
		 * @see JitPcodeThread#count(int, int)
		 * @return the instruction count
		 */
		public int instructionCount() {
			return instructions;
		}

		/**
		 * Get the number of trailing ops in this block
		 * 
		 * <p>
		 * It is possible a block represents only partial execution of an instruction. Though
		 * {@link #instructionCount()} will count this partial instruction, we can tell how far we
		 * got into it by examining this value. With this, we should be able to replay an execution
		 * to exactly the same p-code op step.
		 * 
		 * @return the trailing op count
		 */
		public int trailingOpCount() {
			return trailingOps;
		}
	}

	/**
	 * A class that splits a sequence of ops and associated branches into basic blocks.
	 * 
	 * <p>
	 * This is the kernel of control flow analysis. It first indexes the branches by source and
	 * target op. Note that only non-fall-through branches are known at this point. Then, it
	 * traverses the list of ops. A split occurs following an op that is a branch source and/or
	 * preceding an op that is a branch target. A block is constructed when such a split point is
	 * encountered. In the case of a branch source, the branch is added to the newly constructed
	 * block. As traversal proceeds to the next op, it checks if the immediately-preceding block
	 * should have fall through (conditional or unconditional) by examining its last op. It adds a
	 * new fall-through branch if so. The end of the p-code op list is presumed a split point. If
	 * that final block "should have" fall through, an {@link UnterminatedFlowException} is thrown.
	 * 
	 * <p>
	 * Once all the splitting is done, we have the blocks and all the branches (internal or
	 * external) that leave each block. We then compute all the branches (internal) that enter each
	 * block and the associated flows in both directions.
	 */
	public static class BlockSplitter {
		private final PcodeProgram program;

		private final Map<PcodeOp, Branch> branches = new HashMap<>();
		private final Map<PcodeOp, IntBranch> branchesByTarget = new HashMap<>();
		private final SequencedMap<PcodeOp, JitBlock> blocks = new LinkedHashMap<>();

		private List<PcodeOp> partialBlock = new ArrayList<>();
		private JitBlock lastBlock = null;

		/**
		 * Construct a new block splitter to process the given program
		 * 
		 * <p>
		 * No analysis is performed in the constructor. The client must call
		 * {@link #addBranches(Collection)} and then {@link #splitBlocks()}.
		 * 
		 * @param program the program, i.e., list of p-code ops
		 */
		public BlockSplitter(PcodeProgram program) {
			this.program = program;
		}

		/**
		 * Notify the splitter of the given branches before analysis
		 * 
		 * <p>
		 * The splitter immediately indexes the given branches by source and target op.
		 * 
		 * @param branches the branches
		 */
		public void addBranches(Collection<? extends Branch> branches) {
			for (Branch b : branches) {
				this.branches.put(b.from(), b);
				if (b instanceof IntBranch ib) {
					this.branchesByTarget.put(ib.to(), ib);
				}
			}
		}

		private JitBlock makeBlock() {
			if (!partialBlock.isEmpty()) {
				lastBlock = new JitBlock(program, partialBlock);
				partialBlock = new ArrayList<>();
				blocks.put(lastBlock.first(), lastBlock);
				return lastBlock;
			}
			return null;
		}

		private boolean needsFallthrough(JitBlock block) {
			if (block.branchesFrom.isEmpty() && block.branchesOut.isEmpty()) {
				return true;
			}
			if (block.branchesFrom.size() == 1) {
				return JitPassage.hasFallthrough(block.branchesFrom.getFirst().from());
			}
			if (block.branchesOut.size() == 1) {
				return JitPassage.hasFallthrough(block.branchesOut.getFirst().from());
			}
			throw new AssertionError();
		}

		private void checkForFallthrough(PcodeOp op) {
			if (lastBlock == null) {
				return;
			}
			if (needsFallthrough(lastBlock)) {
				lastBlock.branchesFrom.add(new IntBranch(lastBlock.getCode().getLast(), op, true));
			}
			lastBlock = null;
		}

		private void fillFlows() {
			for (JitBlock from : blocks.values()) {
				for (Branch branch : from.branchesFrom) {
					if (branch instanceof IntBranch ib) {
						JitBlock to = Objects.requireNonNull(blocks.get(ib.to()));
						to.branchesTo.add(ib);
						BlockFlow flow = new BlockFlow(from, to, ib);
						from.flowsFrom.put(ib, flow);
						to.flowsTo.put(ib, flow);
					}
				}
			}
		}

		private void cook() {
			for (JitBlock block : blocks.values()) {
				block.cook();
			}
		}

		private IntBranch getBranchTo(PcodeOp to) {
			return branchesByTarget.get(to);
		}

		private Branch getBranchFrom(PcodeOp from) {
			return branches.get(from);
		}

		private void doWork() {
			if (program.getCode().isEmpty()) {
				throw new IllegalArgumentException("No code to analyze");
			}

			for (PcodeOp op : program.getCode()) {
				// This op would be after the block from the last iteration
				checkForFallthrough(op);
				IntBranch branchTo = getBranchTo(op);
				if (branchTo != null) {
					makeBlock();
					// This op would be after the block we just made
					checkForFallthrough(op);
				}
				partialBlock.add(op);
				Branch branchFrom = getBranchFrom(op);
				if (branchFrom != null) {
					makeBlock();
					// NB. lastBlock cannot be null, we just added the op
					if (branchFrom instanceof IntBranch ib) {
						lastBlock.branchesFrom.add(ib);
					}
					else {
						lastBlock.branchesOut.add(branchFrom);
					}
					/**
					 * Do not checkForFallthrough, because the current op is already in the block
					 */
				}
			}

			makeBlock();
			if (needsFallthrough(lastBlock)) {
				/**
				 * I'm making it the decoder's responsibility to provide a sane program. We can
				 * catch missing control flow at the very end, but we cannot do so at the end of
				 * other blocks. If they have fall-through, they'll (perhaps erroneously) fall
				 * through to the next block that happens to be there. Thus, it is up to the
				 * decoder, if it decodes any incomplete strides, that is must synthesize the
				 * appropriate control-flow ops.
				 */
				throw new UnterminatedFlowException();
			}

			fillFlows();
			cook();
		}

		private SequencedMap<PcodeOp, JitBlock> getBlocks() {
			return blocks;
		}

		/**
		 * Perform the actual analysis
		 * 
		 * @return the resulting split blocks, keyed by {@link JitBlock#start()}
		 */
		public SequencedMap<PcodeOp, JitBlock> splitBlocks() {
			doWork();
			return getBlocks();
		}
	}

	private final JitPassage passage;
	private final SequencedMap<PcodeOp, JitBlock> blocks;

	/**
	 * Construct the control flow model.
	 * 
	 * <p>
	 * Analysis is performed as part of constructing the model.
	 * 
	 * @param context the analysis context
	 */
	public JitControlFlowModel(JitAnalysisContext context) {
		this.passage = context.getPassage();
		this.blocks = analyze();
	}

	/**
	 * Perform the analysis.
	 * 
	 * @return the resulting blocks, keyed by {@link JitBlock#first()}
	 */
	protected SequencedMap<PcodeOp, JitBlock> analyze() {
		BlockSplitter splitter = new BlockSplitter(passage);
		splitter.addBranches(passage.getBranches().values());
		return splitter.splitBlocks();
	}

	/**
	 * Get the basic blocks
	 * 
	 * @return the collection of blocks
	 */
	public Collection<JitBlock> getBlocks() {
		return blocks.values();
	}

	/**
	 * For diagnostics: Dump the results to stderr
	 * 
	 * @see Diag#PRINT_CFM
	 */
	public void dumpResult() {
		System.err.println("STAGE: ControlFlow");
		for (JitBlock block : blocks.values()) {
			System.err.println("");
			System.err.println("Block: " + block);
			System.err.println("Branches to:");
			for (IntBranch branch : block.branchesTo) {
				System.err.println("  " + branch);
			}
			System.err.println("Flows to:");
			for (BlockFlow flow : block.flowsTo.values()) {
				System.err.println("  " + flow);
			}
			System.err.println(block.format(true));
			System.err.println("Branches from:");
			for (IntBranch branch : block.branchesFrom) {
				System.err.println("  " + branch);
			}
			System.err.println("Flows from:");
			for (BlockFlow flow : block.flowsFrom.values()) {
				System.err.println("  " + flow);
			}
			System.err.println("Branches out:");
			for (Branch branch : block.branchesOut) {
				System.err.println("  " + branch);
			}
		}
	}
}
