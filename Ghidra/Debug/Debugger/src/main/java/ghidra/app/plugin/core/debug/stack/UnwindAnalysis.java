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
package ghidra.app.plugin.core.debug.stack;

import java.util.*;
import java.util.stream.Collectors;

import generic.Unique;
import ghidra.app.plugin.core.debug.stack.StackUnwindWarning.NoReturnPathStackUnwindWarning;
import ghidra.app.plugin.core.debug.stack.StackUnwindWarning.OpaqueReturnPathStackUnwindWarning;
import ghidra.graph.*;
import ghidra.graph.algo.DijkstraShortestPathsAlgorithm;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.pcode.exec.PcodeProgram;
import ghidra.pcode.exec.PcodeUseropLibrary;
import ghidra.program.model.address.*;
import ghidra.program.model.block.*;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.FlowType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A class for analyzing a given program's functions as a means of unwinding their stack frames in
 * traces, possibly for live debug sessions.
 * 
 * @see StackUnwinder
 */
public class UnwindAnalysis {

	/**
	 * A graph used for finding execution paths from function entry through the program counter to a
	 * return.
	 * 
	 * <p>
	 * This just wraps {@link UnwindAnalysis#blockModel} in a {@link GImplicitDirectedGraph}.
	 */
	class BlockGraph implements GImplicitDirectedGraph<BlockVertex, BlockEdge> {
		final TaskMonitor monitor;

		public BlockGraph(TaskMonitor monitor) {
			this.monitor = monitor;
		}

		List<BlockEdge> toEdgeList(CodeBlockReferenceIterator it) throws CancelledException {
			List<BlockEdge> result = new ArrayList<>();
			while (it.hasNext()) {
				CodeBlockReference ref = it.next();
				if (ref.getFlowType().isCall()) {
					continue;
				}
				result.add(new BlockEdge(ref));
			}
			return result;
		}

		@Override
		public Collection<BlockEdge> getInEdges(BlockVertex v) {
			try {
				return toEdgeList(blockModel.getSources(v.block, monitor));
			}
			catch (CancelledException e) {
				throw new AssertionError(e);
			}
		}

		@Override
		public Collection<BlockEdge> getOutEdges(BlockVertex v) {
			try {
				return toEdgeList(blockModel.getDestinations(v.block, monitor));
			}
			catch (CancelledException e) {
				throw new AssertionError(e);
			}
		}

		@Override
		public GDirectedGraph<BlockVertex, BlockEdge> copy() {
			throw new UnsupportedOperationException();
		}
	}

	/**
	 * Wrap a {@link CodeBlock}
	 */
	record BlockVertex(CodeBlock block) {
	}

	/**
	 * Wrap a {@link CodeBlockReference}
	 */
	record BlockEdge(CodeBlockReference ref)
			implements GEdge<BlockVertex> {
		@Override
		public BlockVertex getStart() {
			return new BlockVertex(ref.getSourceBlock());
		}

		@Override
		public BlockVertex getEnd() {
			return new BlockVertex(ref.getDestinationBlock());
		}
	}

	private final Program program;
	private final CodeBlockModel blockModel;

	/**
	 * Prepare analysis on the given program
	 * 
	 * @param program the program
	 */
	public UnwindAnalysis(Program program) {
		this.program = program;
		// PartitionCodeSubModel seems to call each subroutine a block
		this.blockModel = new BasicBlockModel(program);
	}

	/**
	 * The analysis surrounding a single frame for a given program counter, i.e., instruction
	 * address
	 */
	class AnalysisForPC {
		private final Address pc;
		private final TaskMonitor monitor;
		private final Function function;
		private final BlockGraph graph;
		private final BlockVertex pcBlock;
		private final DijkstraShortestPathsAlgorithm<BlockVertex, BlockEdge> pathFinder;
		private final Set<StackUnwindWarning> warnings = new HashSet<>();

		/**
		 * Begin analysis for unwinding a frame, knowing only the program counter for that frame
		 * 
		 * <p>
		 * This will look up the function containing the program counter. If there's isn't one, then
		 * this analysis cannot proceed.
		 * 
		 * @param pc the program counter
		 * @param monitor a monitor for progress and cancellation
		 * @throws CancelledException if the monitor cancels the analysis
		 */
		public AnalysisForPC(Address pc, TaskMonitor monitor) throws CancelledException {
			this.pc = pc;
			this.function = program.getFunctionManager().getFunctionContaining(pc);
			if (function == null) {
				throw new UnwindException("No function contains " + pc);
			}
			this.monitor = monitor;
			this.graph = new BlockGraph(monitor);
			this.pathFinder =
				new DijkstraShortestPathsAlgorithm<>(graph, GEdgeWeightMetric.unitMetric());
			this.pcBlock = new BlockVertex(
				Unique.assertAtMostOne(blockModel.getCodeBlocksContaining(pc, monitor)));
		}

		/**
		 * Compute the shortest path(s) from function entry to the program counter
		 * 
		 * @return the paths. There's usually only one
		 * @throws CancelledException if the monitor cancels the analysis
		 */
		public Collection<Deque<BlockEdge>> getEntryPaths() throws CancelledException {
			BlockVertex entryBlock = new BlockVertex(Unique.assertAtMostOne(
				blockModel.getCodeBlocksContaining(function.getEntryPoint(), monitor)));
			return pathFinder.computeOptimalPaths(entryBlock, pcBlock);
		}

		/**
		 * Find terminating blocks that return from the function
		 * 
		 * <p>
		 * If there are none, then the function is presumed non-returning. Analysis will not be
		 * complete.
		 * 
		 * <p>
		 * For non-returning functions, we can still use the entry path. From limited
		 * experimentation, it seems the extra saved-register entries are not problematic. One case
		 * is register parameters that the function saves to the stack for its own sake. While
		 * restoring those would technically be incorrect, it doesn't seem problematic to do so.
		 * This doesn't help us compute {@link UnwindInfo#adjust}, but that might just be
		 * {@link PrototypeModel#getExtrapop()}....
		 * 
		 * @return the blocks
		 * @throws CancelledException if the monitor cancels the analysis
		 */
		public Collection<BlockVertex> getReturnBlocks()
				throws CancelledException {
			// TODO: What to do if function is non-returning?
			List<BlockVertex> returns = new ArrayList<>();
			for (CodeBlock funcBlock : blockModel.getCodeBlocksContaining(function.getBody(),
				monitor)) {
				FlowType flowType = funcBlock.getFlowType();
				// Omit CALL_TERMINATORs, since those are calls to non-returning functions
				// TODO: This also omits tail calls by JMP
				if (flowType.isTerminal() && !flowType.isCall()) {
					returns.add(new BlockVertex(funcBlock));
				}
			}
			return returns;
		}

		/**
		 * Compute the shortest path(s) from the program counter to a function return
		 * 
		 * <p>
		 * Because the shortest-path API does not readily permit the searching for the shortest path
		 * from one vertex to many vertices, we instead search for the shortest path from the
		 * program counter to each of the found function returns, collect all the resulting paths,
		 * and sort. Still, usually only the first (shortest of all) is needed.
		 * 
		 * @return the paths sorted shortest first
		 * @throws CancelledException if the monitor cancels the analysis
		 */
		public Collection<Deque<BlockEdge>> getExitsPaths() throws CancelledException {
			return getReturnBlocks().stream()
					.flatMap(rb -> pathFinder.computeOptimalPaths(pcBlock, rb).stream())
					.sorted(Comparator.comparing(d -> d.size()))
					.collect(Collectors.toList());
		}

		/**
		 * Execute the instructions, ordered by address, in the given address set
		 * 
		 * @param exec the executor
		 * @param set the address set indicating the instructions to execute
		 * @throws CancelledException if the monitor cancels the analysis
		 */
		public void executeSet(SymPcodeExecutor exec, AddressSetView set)
				throws CancelledException {
			for (Instruction i : program.getListing().getInstructions(set, true)) {
				monitor.checkCancelled();
				exec.execute(PcodeProgram.fromInstruction(i, true), PcodeUseropLibrary.nil());
			}
		}

		/**
		 * Execute the instructions in the given block preceding the given address
		 * 
		 * <p>
		 * The instruction at {@code to} is omitted.
		 * 
		 * @param exec the executor
		 * @param block the block whose instructions to execute
		 * @param to the ending address, usually the program counter
		 * @throws CancelledException if the monitor cancels the analysis
		 */
		public void executeBlockTo(SymPcodeExecutor exec, CodeBlock block, Address to)
				throws CancelledException {
			AddressSet set =
				block.intersectRange(to.getAddressSpace().getMinAddress(), to.previous());
			executeSet(exec, set);
		}

		/**
		 * Execute the instructions in the given block
		 * 
		 * @param exec the executor
		 * @param block the block whose instructions to execute
		 * @throws CancelledException if the monitor cancels the analysis
		 */
		public void executeBlock(SymPcodeExecutor exec, CodeBlock block)
				throws CancelledException {
			executeSet(exec, block);
		}

		/**
		 * Execute the instructions in the given block starting at the given address
		 * 
		 * <p>
		 * Instructions preceding the given address are omitted.
		 * 
		 * @param exec the executor
		 * @param block the block whose instructions to execute
		 * @param from the starting address, usually the program counter
		 * @throws CancelledException if the monitor cancels the analysis
		 */
		public void executeBlockFrom(SymPcodeExecutor exec, CodeBlock block, Address from)
				throws CancelledException {
			AddressSet set = block.intersectRange(from, from.getAddressSpace().getMaxAddress());
			executeSet(exec, set);
		}

		/**
		 * Execute the instructions along the given path to a destination block, omitting the final
		 * destination block.
		 * 
		 * <p>
		 * The given path is usually from the function entry to the block containing the program
		 * counter. The final block is omitted, since it should only be partially executed, i.e.,
		 * using {@link #executeBlockTo(SymPcodeExecutor, CodeBlock, Address)}.
		 * 
		 * @param exec the executor
		 * @param to the path to the program counter
		 * @see #executeToPc(Deque)
		 * @throws CancelledException if the monitor cancels the analysis
		 */
		public void executePathTo(SymPcodeExecutor exec, Deque<BlockEdge> to)
				throws CancelledException {
			for (BlockEdge et : to) {
				executeBlock(exec, et.ref.getSourceBlock());
			}
		}

		/**
		 * Execute the instructions along the given path from a source block, omitting the initial
		 * source block.
		 * 
		 * <p>
		 * The given path us usually from the block containing the program counter to a function
		 * return. The initial source is omitted, since it should only be partially executed, i.e.,
		 * using {@link #executeBlockFrom(SymPcodeExecutor, CodeBlock, Address)}.
		 * 
		 * @param exec the executor
		 * @param from the path from the program counter
		 * @see #executeFromPc(SymPcodeExecutorState, Deque)
		 * @throws CancelledException if the monitor cancels the analysis
		 */
		public void executePathFrom(SymPcodeExecutor exec, Deque<BlockEdge> from)
				throws CancelledException {
			for (BlockEdge ef : from) {
				executeBlock(exec, ef.ref.getDestinationBlock());
			}
		}

		/**
		 * Execute the instructions from entry to the program counter, using the given path
		 * 
		 * <p>
		 * This constructs a new symbolic state for stack analysis, performs the execution, and
		 * returns the state. The state can then be analyzed before finishing execution to a
		 * function return and analyzing it again.
		 * 
		 * @param to the path from entry to the program counter
		 * @return the resulting state
		 * @throws CancelledException if the monitor cancels the analysis
		 */
		public SymPcodeExecutorState executeToPc(Deque<BlockEdge> to) throws CancelledException {
			SymPcodeExecutorState state = new SymPcodeExecutorState(program);
			SymPcodeExecutor exec =
				SymPcodeExecutor.forProgram(program, state, Reason.EXECUTE_READ, warnings, monitor);
			executePathTo(exec, to);
			executeBlockTo(exec, pcBlock.block, pc);
			return state;
		}

		/**
		 * Finish execution from the program counter to a function return, using the given path
		 * 
		 * <p>
		 * This returns the same (but mutated) state as passed to it. The state should be forked
		 * from the result of {@link #executeToPc(Deque)}, but resetting the stack portion.
		 * 
		 * @param state the state, whose registers are forked from the result of
		 *            {@link #executeToPc(Deque)}.
		 * @param from the path from the program counter to a return
		 * @return the resulting state
		 * @throws CancelledException if the monitor cancels the analysis
		 */
		public SymPcodeExecutorState executeFromPc(SymPcodeExecutorState state,
				Deque<BlockEdge> from) throws CancelledException {
			SymPcodeExecutor exec =
				SymPcodeExecutor.forProgram(program, state, Reason.EXECUTE_READ, warnings, monitor);
			executeBlockFrom(exec, pcBlock.block, pc);
			executePathFrom(exec, from);
			return state;
		}

		/**
		 * Compute the unwinding information for a frame presumably produced by executing the
		 * current function up to but excluding the program counter
		 * 
		 * <p>
		 * The goal is to compute a base pointer for the current frame so that the values of stack
		 * variables can be retrieved from a dynamic trace, as well as enough information to unwind
		 * and achieve the same for the next frame up on the stack. That is, the frame of the
		 * function that called the current function. We'll also need to figure out what registers
		 * were saved where on the stack so that the values of register variables can be retrieved
		 * from a dynamic trace. For architectures with a link register, register restoration is
		 * necessary to unwind the next frame, since that register holds its program counter.
		 * Ideally, this unwinding can be applied iteratively, until we reach the process' entry
		 * point.
		 * 
		 * <p>
		 * The analytic strategy is fairly straightforward and generalized, though not universally
		 * applicable. It employs a somewhat rudimentary symbolic interpretation. A symbol can be a
		 * constant, a register's initial value at function entry, a stack offset relative to the
		 * stack pointer at function entry, a dereferenced stack offset, or an opaque value. See
		 * {@link Sym}.
		 * 
		 * <ol>
		 * <li>Interpret the instructions along the shortest path from function entry to the program
		 * counter.</li>
		 * <li>Examine the symbol in the stack pointer register. It should be a stack offset. That
		 * offset is the "stack depth." See {@link UnwindInfo#depth()},
		 * {@link UnwindInfo#computeBase(Address)}, and
		 * {@link SymPcodeExecutorState#computeStackDepth()}.</li>
		 * <li>Search the stack for register symbols, creating an offset-register map. A subset of
		 * these are the saved registers on the stack. See {@link UnwindInfo#saved} and
		 * {@link SymPcodeExecutorState#computeMapUsingStack()}.</li>
		 * <li>Reset the stack state. (This implies stack dereferences from further interpretation
		 * refer to their values at the program counter rather than function entry.) See
		 * {@link SymPcodeExecutorState#forkRegs()}.</li>
		 * <li>Interpret the instructions along the shortest path from the program counter to a
		 * function return.</li>
		 * <li>Examine the symbol in the program counter register. This gives the location (register
		 * or stack offset) of the return address. This strategy should work whether or not a link
		 * register is involved. See {@link SymPcodeExecutorState#computeAddressOfReturn()}.
		 * <li>Examine the symbol in the stack pointer register, again. It should be a stack offset.
		 * That offset is the "stack adjustment." See {@link UnwindInfo#adjust()},
		 * {@link UnwindInfo#computeNextSp(Address)}, and
		 * {@link SymPcodeExecutorState#computeStackDepth()}.
		 * <li>Search the registers for stack dereference symbols, creating an offset-register map.
		 * This intersected with the same from entry to program counter is the saved registers map.
		 * See {@link UnwindInfo#saved()},
		 * {@link UnwindInfo#mapSavedRegisters(Address, SavedRegisterMap)}, and
		 * {@link SymPcodeExecutorState#computeMapUsingRegisters()}.
		 * </ol>
		 * 
		 * <p>
		 * This strategy does make some assumptions:
		 * <ul>
		 * <li>The function returns.</li>
		 * <li>For every edge in the basic block graph, the stack depth at the end of its source
		 * block is equal to the stack depth at the start of its destination block.</li>
		 * <li>The function follows a "sane" convention. While it doesn't have to be any particular
		 * convention, it does need to restore its saved registers, and those registers should be
		 * saved to the stack in a straightforward manner.</li>
		 * </ul>
		 * 
		 * @return the unwind information
		 * @throws CancelledException if the monitor cancels the analysis
		 */
		public UnwindInfo computeUnwindInfo() throws CancelledException {
			// TODO: Find out to what other pc values this applies and cache?
			Collection<Deque<BlockEdge>> entryPaths = getEntryPaths();
			if (entryPaths.isEmpty()) {
				throw new UnwindException(
					"Could not find a path from " + function + " entry to " + pc);
			}
			Collection<Deque<BlockEdge>> exitsPaths = getExitsPaths();
			// TODO: Proper exceptions for useless results
			for (Deque<BlockEdge> entryPath : entryPaths) {
				SymPcodeExecutorState entryState = executeToPc(entryPath);
				Long depth = entryState.computeStackDepth();
				if (depth == null) {
					continue;
				}
				if (exitsPaths.isEmpty()) {
					warnings.add(new NoReturnPathStackUnwindWarning(pc));
				}
				Map<Register, Address> mapByEntry = entryState.computeMapUsingStack();
				for (Deque<BlockEdge> exitPath : exitsPaths) {
					SymPcodeExecutorState exitState =
						executeFromPc(entryState.forkRegs(), exitPath);
					Address addressOfReturn = exitState.computeAddressOfReturn();
					Long adjust = exitState.computeStackDepth();
					if (addressOfReturn == null || adjust == null) {
						continue;
					}
					Map<Register, Address> mapByExit = exitState.computeMapUsingRegisters();
					mapByExit.entrySet().retainAll(mapByEntry.entrySet());
					return new UnwindInfo(function, depth, adjust, addressOfReturn, mapByExit,
						new StackUnwindWarningSet(warnings));
				}
				warnings.add(new OpaqueReturnPathStackUnwindWarning(pc));
				long adjust = SymPcodeExecutor.computeStackChange(function, warnings);
				return new UnwindInfo(function, depth, adjust, null, mapByEntry,
					new StackUnwindWarningSet(warnings));
			}
			throw new UnwindException(
				"Could not analyze any path from " + function + " entry to " + pc);
		}
	}

	/**
	 * Start analysis at the given program counter
	 * 
	 * @param pc the program counter
	 * @param monitor a monitor for all the analysis that follows
	 * @return the pc-specific analyzer
	 * @throws CancelledException if the monitor cancels the analysis
	 */
	AnalysisForPC start(Address pc, TaskMonitor monitor) throws CancelledException {
		return new AnalysisForPC(pc, monitor);
	}

	/**
	 * Compute the unwind information for the given program counter
	 * 
	 * @param pc the program counter
	 * @param monitor a monitor for progress and cancellation
	 * @return the unwind information
	 * @throws CancelledException if the monitor cancels the analysis
	 */
	public UnwindInfo computeUnwindInfo(Address pc, TaskMonitor monitor)
			throws CancelledException {
		AnalysisForPC analysis = start(pc, monitor);
		return analysis.computeUnwindInfo();
	}
}
