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
import java.util.Map.Entry;

import ghidra.pcode.emu.jit.JitBytesPcodeExecutorState;
import ghidra.pcode.emu.jit.JitCompiler;
import ghidra.pcode.emu.jit.JitCompiler.Diag;
import ghidra.pcode.emu.jit.analysis.JitControlFlowModel.BlockFlow;
import ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.MathUtilities;

/**
 * The variable scope analysis of JIT-accelerated emulation.
 * 
 * <p>
 * This implements the Variable Scope Analysis phase of the {@link JitCompiler}. The result provides
 * the set of in-scope (alive) varnodes for each basic block. The design of this analysis, and the
 * shortcuts we take, are informed by the design of downstream phases. In particular, we do not
 * intend to allocate each SSA variable. There are often many, many such variables, and attempting
 * to allocate them to as few target resources, e.g., JVM locals, as possible is <em>probably</em> a
 * complicated and expensive algorithm. I don't think we'd gain much from it either. Instead, we'll
 * just allocate by varnode. To do that, though, we still have to consider that some varnodes
 * overlap and otherwise alias others. If we are able to handle all that aliasing in place, then we
 * need not generate code for the synthetic ops. One might ask, well then why do any of the Data
 * Flow Analysis in the first place? 1) We still need data flow to inform the selection of JVM local
 * types. We have not measured the run-time cost of the bitwise casts, but we do know the bytecode
 * for each cast occupies space, counted against the 65,535-byte max. 2) We also need data flow to
 * inform operation elimination, which removes many wasted flag computations.
 * 
 * <p>
 * To handle the aliasing, we coalesce overlapping varnodes. For example, {@code EAX} will get
 * coalesced with {@code RAX}, but {@code BH} <em>will not</em> get coalesced with {@code BL},
 * assuming no other part of {@code RBX} is accessed. The {@link JitDataFlowModel} records all
 * varnodes accessed in the course of its intra-block analysis. Only those actually accessed are
 * considered. We then compute scope in terms of these coalesced varnodes. For example, if both
 * {@code RAX} and {@code EAX} are used by a passage, then an access of {@code EAX} causes
 * {@code RAX} to remain in scope.
 * 
 * <p>
 * The decision to compute scope on a block-by-block basis instead of op-by-op is for simplicity. We
 * intend to birth and retire variables along block transitions by considering what variables are
 * coming into or leaving scope on the flow edge. <em>Birthing</em> is just reading a variable's
 * value from the run-time {@link JitBytesPcodeExecutorState state} into its allocated JVM local.
 * Conversely, <em>retiring</em> is writing the value back out to the state. There's little to be
 * gained by retiring a variable midway through a block as opposed to the end of the block. Perhaps
 * if one giant block handles a series of variables in sequence, we could have used a single JVM
 * local to allocate each, but we're already committed to allocating a JVM local per (coalesced)
 * varnode. So, while that may ensure only one variable is alive at a time, the number of JVM locals
 * required remains the same. Furthermore, the amount of bytecode emitted remains the same, but at
 * different locations in the block. The case where this might be worth considering is a userop
 * invocation, because all live variables must be forcefully retired.
 *
 * <p>
 * We then consider what common cases we want to ensure are optimized, when we're limited to a
 * block-by-block analysis. One that comes to mind is a function with an early bail. Consider the
 * following C source:
 * 
 * <pre>
 * int func(my_struct* ptr) {
 *   if (ptr == NULL) {
 *     return ERR;
 *   }
 *   // Do some serious work
 *   return ptr->v;
 * }
 * </pre>
 * 
 * <p>
 * Often, the C compiler will group all the returns into one final basic block, so we might get the
 * following p-code:
 * 
 * <pre>
 *  1   RSP    = INT_SUB RSP, 0x20:8
 *  2   $U00:1 = INT_EQUAL RDI, 0:8     # RDI is ptr
 *  3            CBRANCH &lt;err&gt;, $U0:1
 *
 *  4            # Do some serious work
 *  5   $U10:8 = INT_ADD RDI, 0xc:8     # Offset to field v
 *  6   EAX    = LOAD [ram] $U10:8
 *  7            BRANCH &lt;exit&gt;
 * &lt;err&gt;
 *  8   EAX    = COPY 0xffffffff:4
 * &lt;exit&gt;
 *  9   RSP    = INT_ADD RSP, 0x20:8
 *  10  RIP    = LOAD [ram] RSP
 *  11  RSP    = INT_ADD RSP, 8:8
 *  12           RETURN RIP
 * </pre>
 * 
 * <p>
 * Note that I've elided the actual x86 machine code and all of the noise generated by C compilation
 * and p-code lifting, and I've presumed the decoded passage contains exactly the example function.
 * The result is your typical if-else diamond. We'll place the error case on the left:
 * 
 * <pre>
 *     +---------+
 *     |   1--3  |
 *     | CBRANCH |
 *     +-T-----F-+
 *      /       \
 *     /         \
 * +--------+ +--------+
 * |   8    | |  4--7  |
 * | (fall) | | BRANCH |
 * +--------+ +--------+
 *     \         /
 *      \       /
 *     +---------+
 *     |  9--12  |
 *     | RETURN  |
 *     +---------+
 * </pre>
 * 
 * <p>
 * Suppose the "serious work" on line 4 accesses several varnodes: RBX, RCX, RDX, and RSI. If
 * execution follows the error path, we'd rather not birth any of those variables. Thus, we might
 * like the result of the scope analysis to be:
 * 
 * <p>
 * <table border="1">
 * <tr>
 * <th>Block</th>
 * <th>Live Vars</th>
 * </tr>
 * <tr>
 * <td>1&ndash;3</td>
 * <td>RDI, RSP, $U00:1</td>
 * </tr>
 * <tr>
 * <td>4&ndash;7</td>
 * <td>EAX, RBX, RCX, RDI, RDX, RSI, RSP, $U10:8</td>
 * </tr>
 * <tr>
 * <td>8</td>
 * <td>EAX, RSP</td>
 * </tr>
 * <tr>
 * <td>9&ndash;12</td>
 * <td>RIP, RSP</td>
 * </tr>
 * </table>
 * 
 * <p>
 * This can be achieved rather simply: Define two sets for each block, the upward view and the
 * downward view. The first corresponds to all varnodes that could be accessed before entering this
 * block or while in it. The second corresponds to all varnodes that could be access while in this
 * block or after leaving it. The upward view is computed by initializing each set to the varnodes
 * accessed by its block. Then we "push" each set upward by adding its elements into the set for
 * each block with flows into this one, until the sets converge. The downward sets are similarly
 * computed, independently of the upward sets. The result is the intersection of these sets, per
 * block. The algorithm is somewhat intuitive in that we accrue live variables as we move toward the
 * "body" of the control flow graph, and they begin to drop off as we approach an exit. The accrual
 * is captured by the downward set, and the drop off is captured by intersection with the upward
 * set. This will also prevent retirement and rebirth of variables. Essentially, if we are between
 * two accesses of a varnode, then that varnode is alive. Consider {@code RSP} from the example
 * above. The algorithm considers it alive in blocks 4&ndash;7 and 8, despite the fact neither
 * actually accesses it. Nevertheless, we'd rather generate one birth upon entering block 1&ndash;3,
 * keep it alive in the body, and then generate one retirement upon leaving block 9&ndash;12.
 * 
 * <p>
 * One notable effect of this algorithm is that all blocks in a loop will have the same variables in
 * scope.... I think this is okay. We'll birth the relevant variables upon entering the loop, keep
 * them all alive during loop execution, and then retire them (unless they're accessed downstream)
 * upon leaving.
 * 
 * @implNote <b>TODO</b>: There's some nonsense to figure out with types. It would be nice if we
 *           could allow variables of different types to occupy the same location at different
 *           times. This can be the case, e.g., if a register is used as a temporary location for
 *           copying values around. If there are times when it's treated as an int and other times
 *           when it's treated as a float, we could avoid unnecessary Java type conversions.
 *           However, this would require us to track liveness with types, and at that granularity,
 *           it could get unwieldy. My inclination is to just consider location liveness and then
 *           have the allocator decide what type to assign the local variable for that location
 *           based on some voting system. This is not the best, because some access sites are
 *           executed more often than others, but it'll suffice.
 */
public class JitVarScopeModel {

	/**
	 * Encapsulates set movement when computing the upward and downward views.
	 */
	enum Which {
		/**
		 * Set movement for the upward view
		 */
		UP {
			@Override
			Collection<JitBlock> getFlows(ScopeInfo info) {
				return info.block.flowsTo().values().stream().map(BlockFlow::from).toList();
			}

			@Override
			Set<Varnode> getLive(ScopeInfo info) {
				return info.liveUp;
			}

			@Override
			Set<Varnode> getQueued(ScopeInfo info) {
				return info.queuedUp;
			}
		},
		/**
		 * Set movement for the downward view
		 */
		DOWN {
			@Override
			Collection<JitBlock> getFlows(ScopeInfo info) {
				return info.block.flowsFrom().values().stream().map(BlockFlow::to).toList();
			}

			@Override
			Set<Varnode> getLive(ScopeInfo info) {
				return info.liveDn;
			}

			@Override
			Set<Varnode> getQueued(ScopeInfo info) {
				return info.queuedDn;
			}
		};

		/**
		 * Get the flow toward which we will push the given block's set
		 * 
		 * @param info the intermediate analytic result for the block whose set to push
		 * @return the blocks into which our set will be unioned
		 */
		abstract Collection<JitBlock> getFlows(ScopeInfo info);

		/**
		 * Get the current set for the given block
		 * 
		 * @param info the intermediate analytic result for the block whose set to get
		 * @return the set of live varnodes
		 */
		abstract Set<Varnode> getLive(ScopeInfo info);

		/**
		 * Get the varnodes which are queued for addition into the given block's set
		 * 
		 * @param info the intermediate analytic result for the given block
		 * @return the set of queued live varnodes
		 */
		abstract Set<Varnode> getQueued(ScopeInfo info);
	}

	/**
	 * Encapsulates the (intermediate) analytic result for each block
	 */
	private class ScopeInfo {
		private final JitBlock block;
		private final Set<Varnode> liveUp = new HashSet<>();
		private final Set<Varnode> liveDn = new HashSet<>();

		private final Set<Varnode> queuedUp = new HashSet<>();
		private final Set<Varnode> queuedDn = new HashSet<>();

		private final Set<Varnode> liveVars = new LinkedHashSet<>();
		private final Set<Varnode> liveVarsImm = Collections.unmodifiableSet(liveVars);

		/**
		 * Construct the result for the given block
		 * 
		 * @param block the block
		 */
		public ScopeInfo(JitBlock block) {
			this.block = block;

			JitDataFlowBlockAnalyzer dfa = dfm.getAnalyzer(block);
			for (Varnode vn : dfa.getVarnodesRead()) {
				if (!vn.isAddress()) {
					queuedUp.add(getCoalesced(vn));
					queuedDn.add(getCoalesced(vn));
				}
			}
			for (Varnode vn : dfa.getVarnodesWritten()) {
				if (!vn.isAddress()) {
					queuedUp.add(getCoalesced(vn));
					queuedDn.add(getCoalesced(vn));
				}
			}
		}

		/**
		 * Push this block's queue for the given view
		 * 
		 * <p>
		 * Any block whose set was affected by this push is added to the queue of blocks to be
		 * processed again.
		 * 
		 * @param which which view (direction)
		 */
		private void push(Which which) {
			Set<Varnode> queued = which.getQueued(this);
			if (queued.isEmpty()) {
				return;
			}
			for (JitBlock block : which.getFlows(this)) {
				ScopeInfo that = infos.get(block);
				Set<Varnode> toQueueThat = new HashSet<>(queued);
				toQueueThat.removeAll(which.getLive(that));
				if (which.getQueued(that).addAll(toQueueThat)) {
					blockQueue.add(that);
				}
			}
			which.getLive(this).addAll(queued);
			queued.clear();
		}

		/**
		 * Finish the analytic computation for this block
		 * 
		 * <p>
		 * If a block contains an access to a variable, that variable is alive in that block. If a
		 * block is between (in terms of possible control-flow paths) two others that access a
		 * variable, that variable is alive in the block.
		 */
		private void finish() {
			List<Varnode> sortedLiveUp = new ArrayList<>(this.liveUp);
			Collections.sort(sortedLiveUp, Comparator.comparing(Varnode::getAddress));
			liveVars.addAll(sortedLiveUp);
			liveVars.retainAll(liveDn);
		}
	}

	private final JitControlFlowModel cfm;
	private final JitDataFlowModel dfm;

	private final NavigableMap<Address, Varnode> coalesced = new TreeMap<>();

	private final Map<JitBlock, ScopeInfo> infos = new HashMap<>();
	private final SequencedSet<ScopeInfo> blockQueue = new LinkedHashSet<>();

	/**
	 * Construct the model
	 * 
	 * @param cfm the control flow model
	 * @param dfm the data flow model
	 */
	public JitVarScopeModel(JitControlFlowModel cfm, JitDataFlowModel dfm) {
		this.cfm = cfm;
		this.dfm = dfm;

		analyze();
	}

	/**
	 * Get the maximum address (inclusive) in the varnode
	 * 
	 * @param varnode the node
	 * @return the max address
	 */
	static Address maxAddr(Varnode varnode) {
		return varnode.getAddress().add(varnode.getSize() - 1);
	}

	/**
	 * Check for overlap when one varnode is known to be to the left of the other.
	 * 
	 * @param left the left varnode (having lower address)
	 * @param right the right varnode (having higher address)
	 * @return true if they overlap (not counting abutting), false otherwise.
	 */
	static boolean overlapsLeft(Varnode left, Varnode right) {
		// max is inclusive, so use >=, not just >
		return maxAddr(left).compareTo(right.getAddress()) >= 0;
	}

	private void coalesceVarnode(Varnode varnode) {
		Address min = varnode.getAddress();
		Address max = maxAddr(varnode);
		Entry<Address, Varnode> leftEntry = coalesced.floorEntry(min);
		if (leftEntry != null && overlapsLeft(leftEntry.getValue(), varnode)) {
			min = leftEntry.getKey();
		}
		Entry<Address, Varnode> rightEntry = coalesced.floorEntry(max);
		if (rightEntry != null) {
			max = MathUtilities.cmax(max, maxAddr(rightEntry.getValue()));
		}
		Varnode exists = leftEntry == null ? null : leftEntry.getValue();
		Varnode existsRight = rightEntry == null ? null : rightEntry.getValue();
		if (exists == existsRight && exists != null && exists.getAddress().equals(min) &&
			maxAddr(exists).equals(max)) {
			return; // no change
		}
		coalesced.subMap(min, true, maxAddr(varnode), true).clear();
		coalesced.put(min, new Varnode(min, (int) max.subtract(min) + 1));
	}

	private void coalesceVarnodes() {
		Set<Varnode> allVarnodes = new HashSet<>();
		for (JitBlock block : cfm.getBlocks()) {
			allVarnodes.addAll(dfm.getAnalyzer(block).getVarnodesRead());
			allVarnodes.addAll(dfm.getAnalyzer(block).getVarnodesWritten());
		}
		for (Varnode varnode : allVarnodes) {
			if (!varnode.isAddress()) {
				coalesceVarnode(varnode);
			}
		}
	}

	/**
	 * Get the varnode into which the given varnode was coalesced
	 * 
	 * <p>
	 * In many cases, the result is the same varnode.
	 * 
	 * @param part the varnode
	 * @return the coalesced varnode
	 */
	public Varnode getCoalesced(Varnode part) {
		if (part.isAddress()) {
			return part;
		}
		Entry<Address, Varnode> floorEntry = coalesced.floorEntry(part.getAddress());
		assert overlapsLeft(floorEntry.getValue(), part);
		return floorEntry.getValue();
	}

	/**
	 * Perform a push for the given direction for the next block in the queue.
	 * 
	 * <p>
	 * Any block whose varnode queue was affected is added back into the block queue.
	 * 
	 * @param which which view is being computed (direction)
	 * @return true if there remains at least one block in the queue
	 */
	private boolean pushNext(Which which) {
		if (blockQueue.isEmpty()) {
			return false;
		}
		ScopeInfo info = blockQueue.removeFirst();
		info.push(which);
		return !blockQueue.isEmpty();
	}

	/**
	 * Perform the analysis.
	 * 
	 * <p>
	 * This starts with the upward set, which is computed by pushing queued block's varnodes upward
	 * until the queue is empty. All blockes are queued initially. When a block's set is affected,
	 * it's re-added to the queue, so we know we've converged when the queue is empty. The downward
	 * set is then computed in the same fashion.
	 */
	private void analyze() {
		coalesceVarnodes();
		for (JitBlock block : cfm.getBlocks()) {
			ScopeInfo info = new ScopeInfo(block);
			infos.put(block, info);
			blockQueue.add(info);
		}
		while (pushNext(Which.UP)) {
		}

		blockQueue.addAll(infos.values());
		while (pushNext(Which.DOWN)) {
		}

		for (ScopeInfo info : infos.values()) {
			info.finish();
		}
	}

	/**
	 * Get the collection of all coalesced varnodes
	 * 
	 * @return the varnodes
	 */
	public Iterable<Varnode> coalescedVarnodes() {
		return coalesced.values();
	}

	/**
	 * Get the set of live varnodes for the given block
	 * 
	 * @param block the block
	 * @return the live varnodes
	 */
	public Set<Varnode> getLiveVars(JitBlock block) {
		return infos.get(block).liveVarsImm;
	}

	/**
	 * For diagnostics: Dump the analysis result to stderr
	 * 
	 * @see Diag#PRINT_VSM
	 */
	public void dumpResult() {
		System.err.println("STAGE: VarLiveness");
		for (JitBlock block : cfm.getBlocks()) {
			System.err.println("  Block: " + block);
			Set<String> liveNames = new TreeSet<>();
			for (Varnode vn : infos.get(block).liveVarsImm) {
				Register register = block.getLanguage().getRegister(vn.getAddress(), vn.getSize());
				if (register != null) {
					liveNames.add(register.getName());
				}
				else if (vn.isUnique()) {
					liveNames.add("$U%x:%d".formatted(vn.getOffset(), vn.getSize()));
				}
				else {
					liveNames.add("%s:%x:4".formatted(vn.getAddress().getAddressSpace().getName(),
						vn.getOffset(), vn.getSize()));
				}
			}
			System.err.println("    Live: " + liveNames);
		}
	}
}
