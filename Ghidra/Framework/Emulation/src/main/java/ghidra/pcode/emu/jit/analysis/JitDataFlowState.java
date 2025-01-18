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
import ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock;
import ghidra.pcode.emu.jit.op.*;
import ghidra.pcode.emu.jit.var.*;
import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.pcode.exec.PcodeExecutorState;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.Msg;

/**
 * An implementation of {@link PcodeExecutorState} for per-block data flow interpretation
 * 
 * <p>
 * In p-code interpretation, this interface's purpose is to store the current value of varnodes in
 * the emulation/interpretation state. Here we implement it using {@code T:=}{@link JitVal}, and
 * track the latest variable definition of vanodes in the data flow interpretation. The adaptation
 * is fairly straightforward, except when varnode accesses do not match their latest definitions
 * exactly, e.g., an access of {@code EAX} when the latest definition is for {@code RAX}. Thus, this
 * state object may synthesize {@link JitSynthSubPieceOp subpiece} and {@link JitCatenateOp
 * catenate} ops to model the "off-cut" use of one or more such definitions. Additionally, in
 * preparation for inter-block data flow analysis, when no definition is present for a varnode (or
 * part of a varnode) access, this state will synthesize {@link JitPhiOp phi} ops. See
 * {@link #setVar(AddressSpace, JitVal, int, boolean, JitVal) setVar} and
 * {@link #getVar(AddressSpace, JitVal, int, boolean, Reason) getVar} for details.
 * 
 * <p>
 * This state only serves to analyze data flow through register and unique variables. Because we
 * know these are only accessible to the thread, we stand to save much execution time by bypassing
 * the {@link JitBytesPcodeExecutorState} at run time. We can accomplish this by mapping these
 * variables to suitable JVM local variables. Thus, we have one map of entries for register space
 * and another for unique space. Accesses to other spaces do not mutate or read from either of those
 * maps, but this class may generate a suitable {@link JitVal} for the use-def graph.
 */
public class JitDataFlowState implements PcodeExecutorState<JitVal> {

	/**
	 * A minimal data flow machine state that can be captured by a {@link JitCallOtherOpIf}.
	 */
	public class MiniDFState {
		private final NavigableMap<Long, JitVal> uniqMap;
		private final NavigableMap<Long, JitVal> regMap;

		MiniDFState() {
			this(new TreeMap<>(), new TreeMap<>());
		}

		MiniDFState(NavigableMap<Long, JitVal> uniqMap, NavigableMap<Long, JitVal> regMap) {
			this.uniqMap = uniqMap;
			this.regMap = regMap;
		}

		NavigableMap<Long, JitVal> mapFor(AddressSpace space) {
			if (space.isUniqueSpace()) {
				return uniqMap;
			}
			if (space.isRegisterSpace()) {
				return regMap;
			}
			return null;
		}

		/**
		 * Compute the upper (exclusive) offset of a given definition entry
		 * 
		 * @param entry the entry
		 * @return the upper offset, exclusive
		 */
		protected static long endOf(Entry<Long, JitVal> entry) {
			return entry.getKey() + entry.getValue().size();
		}

		/**
		 * Clear all definition entries in the given per-space map for the given varnode
		 * 
		 * <p>
		 * Any entries completely covered by the given varnode (including an exact match) are
		 * removed from the map. Those partially covered will be replaced by subpieces of their
		 * former selves such that no part within the cleared varnode remains defined.
		 * 
		 * @param map the map to modify
		 * @param varnode the varnode whose definitions to remove
		 */
		protected void doClear(NavigableMap<Long, JitVal> map, Varnode varnode) {
			AddressSpace space = varnode.getAddress().getAddressSpace();
			long offset = varnode.getOffset();
			int size = varnode.getSize();

			Entry<Long, JitVal> truncLeftEntry = map.lowerEntry(offset);
			if (truncLeftEntry != null && endOf(truncLeftEntry) <= offset) {
				truncLeftEntry = null;
			}
			/**
			 * Collect entry at both ends before removal, in case the clear is cutting a hole in the
			 * middle of one entry. I.e., could be the same entry at both ends.
			 */
			long end = offset + size;
			Entry<Long, JitVal> truncRightEntry = map.lowerEntry(end);
			if (truncRightEntry != null && endOf(truncRightEntry) <= end) {
				truncRightEntry = null;
			}

			/**
			 * Replace the right entry first. If it's the same entry as the left, and we remove by
			 * key, then we might remove the replacement on the left, if it were done first.
			 */
			if (truncRightEntry != null) {
				long entStart = truncRightEntry.getKey();
				map.remove(entStart);
				int shave = (int) (endOf(truncRightEntry) - end);
				JitVal entVal = truncRightEntry.getValue();
				Varnode truncVn = new Varnode(space.getAddress(entStart), entVal.size());
				JitVal truncVal = arithmetic.truncFromLeft(truncVn, shave, entVal);
				map.put(end, truncVal);
			}

			if (truncLeftEntry != null) {
				long entStart = truncLeftEntry.getKey();
				map.remove(entStart);
				int shave = (int) (endOf(truncLeftEntry) - offset);
				JitVal entVal = truncLeftEntry.getValue();
				Varnode truncVn = new Varnode(space.getAddress(entStart), entVal.size());
				JitVal truncVal = arithmetic.truncFromRight(truncVn, shave, entVal);
				map.put(truncLeftEntry.getKey(), truncVal);
			}

			/**
			 * At this point, no part of the ends should be in the key range [start,end), so clear
			 * that submap
			 */
			map.subMap(offset, end).clear();
		}

		/**
		 * The implementation of {@link #set(Varnode, JitVal)} for a given address space
		 * 
		 * @param map the map to modify for the given space
		 * @param varnode the varnode whose value to define
		 * @param val the varnode's new definition
		 */
		protected void doSet(NavigableMap<Long, JitVal> map, Varnode varnode, JitVal val) {
			doClear(map, varnode);

			if (val instanceof JitOutVar out) {
				if (out.definition() instanceof JitCatenateOp cat) {
					int cursor = 0;
					for (JitVal part : cat.iterParts(language.isBigEndian())) {
						/**
						 * NOTE: Do not filter phi nodes here. Perhaps if we're certain its for the
						 * same varnode we could, but not sure there's any benefit to doing so.
						 * TODO: Determine whether there's any benefit. NOTE: While the phi nodes
						 * are linked after the fact, they are generated (but empty) during p-code
						 * interpretation.
						 */
						map.put(varnode.getOffset() + cursor, part);
						cursor += part.size();
					}
					/**
					 * Can't necessarily unlink cat here. Something else may use it. May need to
					 * prune afterward.
					 */
					return;
				}
			}

			map.put(varnode.getOffset(), val);
		}

		/**
		 * Set one or more definition entries in the given map for the given varnode to the given
		 * value
		 * 
		 * <p>
		 * Ordinary, this just sets the one varnode to the given value; however, if the given value
		 * is the output of a {@link JitCatenateOp catenation}, then each input part is entered into
		 * the map separately, and the synthetic catenation dropped. The behavior avoids nested
		 * catenations.
		 * 
		 * @param varnode the varnode
		 * @param val the value
		 */
		public void set(Varnode varnode, JitVal val) {
			var map = mapFor(varnode.getAddress().getAddressSpace());
			if (map == null) {
				return;
			}
			doSet(map, varnode, val);
		}

		/**
		 * The implementation of {@link #getDefinitions(AddressSpace, long, int)} for a given
		 * address space
		 * 
		 * @param map the map of values for the given space
		 * @param space the address space
		 * @param offset the offset within the space
		 * @param size the size of the varnode
		 * @return the list of values
		 */
		protected List<JitVal> doGetDefinitions(NavigableMap<Long, JitVal> map, AddressSpace space,
				long offset, int size) {
			List<JitVal> result = new ArrayList<>();
			Entry<Long, JitVal> preEntry = map.lowerEntry(offset);
			long cursor = offset;
			if (preEntry != null) {
				if (endOf(preEntry) > offset) {
					JitVal preVal = preEntry.getValue();
					Varnode preVn = new Varnode(space.getAddress(preEntry.getKey()), preVal.size());
					int shave = (int) (offset - preEntry.getKey());
					JitVal truncVal = arithmetic.truncFromLeft(preVn, shave, preVal);
					cursor = endOf(preEntry);
					result.add(truncVal);
				}
			}
			long end = offset + size;
			for (Entry<Long, JitVal> entry : map.subMap(offset, end).entrySet()) {
				if (entry.getKey() > cursor) {
					result.add(new JitMissingVar(
						new Varnode(space.getAddress(cursor), (int) (entry.getKey() - cursor))));
				}
				if (endOf(entry) > end) {
					JitVal postVal = entry.getValue();
					Varnode postVn = new Varnode(space.getAddress(entry.getKey()), postVal.size());
					int shave = (int) (endOf(entry) - end);
					JitVal truncVal = arithmetic.truncFromRight(postVn, shave, postVal);
					cursor = end;
					result.add(truncVal);
					break;
				}
				result.add(entry.getValue());
				cursor = endOf(entry);
			}
			if (end > cursor) {
				result.add(
					new JitMissingVar(new Varnode(space.getAddress(cursor), (int) (end - cursor))));
			}
			assert !result.isEmpty();
			return result;
		}

		/**
		 * Get an ordered list of all values involved in the latest definition of the given varnode.
		 * 
		 * <p>
		 * In the simplest case, the list consists of exactly one SSA variable whose varnode exactly
		 * matches that requested. In other cases, e.g., when only a subregister is defined, the
		 * list may have several entries, some of which may be {@link JitMissingVar missing}.
		 * 
		 * <p>
		 * The list is ordered according to machine endianness. That is for little endian, the
		 * values are ordered from least to most significant parts of the varnode defined. This is
		 * congruent with how {@link JitDataFlowArithmetic#catenate(Varnode, List)} expects parts to
		 * be listed.
		 * 
		 * @param space the address space of the varnode
		 * @param offset the offset of the varnode
		 * @param size the size in bytes of the varnode
		 * @return the list of values
		 */
		public List<JitVal> getDefinitions(AddressSpace space, long offset, int size) {
			var map = mapFor(space);
			if (map == null) {
				throw new AssertionError("What is this space?: " + space);
			}
			return doGetDefinitions(map, space, offset, size);
		}

		/**
		 * Get an ordered list of all values involved in the latest definition of the given varnode.
		 * 
		 * @see #getDefinitions(AddressSpace, long, int)
		 * @param varnode the varnode whose definitions to retrieve
		 * @return the list of values
		 */
		public List<JitVal> getDefinitions(Varnode varnode) {
			AddressSpace space = varnode.getAddress().getAddressSpace();
			return getDefinitions(space, varnode.getOffset(), varnode.getSize());
		}

		/**
		 * Get an ordered list of all values involved in the latest definition of the given varnode.
		 * 
		 * @see #getDefinitions(AddressSpace, long, int)
		 * @param register the register whose definitions to retrieve
		 * @return the list of values
		 */
		public List<JitVal> getDefinitions(Register register) {
			return getDefinitions(register.getAddressSpace(), register.getOffset(),
				register.getNumBytes());
		}

		/**
		 * Replace missing variables with phi nodes, mutating the given list in place
		 * 
		 * @param defs the definitions
		 * @return the same list, modified
		 */
		protected List<JitVal> generatePhis(List<JitVal> defs, Collection<JitPhiOp> phiQueue) {
			int n = defs.size();
			for (int i = 0; i < n; i++) {
				JitVal v = defs.get(i);
				if (v instanceof JitMissingVar missing) {
					JitPhiOp phi = missing.generatePhi(dfm, block);
					if (phiQueue != null) {
						phiQueue.add(phi);
					}
					defs.set(i, phi.out());
					set(missing.varnode(), phi.out());
				}
			}
			return defs;
		}

		/**
		 * Get the value of the given varnode
		 * 
		 * <p>
		 * This is the implementation of
		 * {@link JitDataFlowState#getVar(AddressSpace, JitVal, int, boolean, Reason)}, but only for
		 * uniques and registers.
		 * 
		 * @param varnode the varnode
		 * @return the value
		 */
		public JitVal getVar(Varnode varnode) {
			List<JitVal> defs = generatePhis(getDefinitions(varnode), null);
			if (defs.size() == 1) {
				return defs.get(0);
			}
			return arithmetic.catenate(varnode, defs);
		}

		/**
		 * Copy this mini state
		 * 
		 * @return the copy
		 */
		public MiniDFState copy() {
			return new MiniDFState(new TreeMap<>(uniqMap), new TreeMap<>(regMap));
		}
	}

	private final JitDataFlowModel dfm;
	private final JitBlock block;
	private final Language language;
	private final JitDataFlowArithmetic arithmetic;

	private final MiniDFState mini = new MiniDFState();

	private final Set<Varnode> varnodesRead = new HashSet<>();
	private final Set<Varnode> varnodesWritten = new HashSet<>();

	/**
	 * Construct a state
	 * 
	 * @param context the analysis context
	 * @param dfm the data flow model whose use-def graph to populate
	 * @param block the block being analyzed (to which generated phi ops belong)
	 */
	JitDataFlowState(JitAnalysisContext context, JitDataFlowModel dfm, JitBlock block) {
		this.dfm = dfm;
		this.block = block;

		this.language = context.getLanguage();
		this.arithmetic = dfm.getArithmetic();
	}

	@Override
	public Language getLanguage() {
		return language;
	}

	@Override
	public JitDataFlowArithmetic getArithmetic() {
		return arithmetic;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * This and {@link #getVar(AddressSpace, JitVal, int, boolean, Reason)} are where we connect the
	 * interpretation to the maps of definitions we keep in this state. We examine the varnode's
	 * type first. We can't write to a constant, and that shouldn't be allowed anyway, so we warn if
	 * we observe that. We'll ignore any indirect writes, because those are denoted by
	 * {@link JitStoreOp store} ops. We also don't do much here with direct writes. The writes to
	 * such variables are handled by {@link JitMemoryOutVar}. Such output variables are actually
	 * passed in as {@code val} here, but need only be stored in a map if they are register or
	 * unique variables.
	 */
	@Override
	public void setVar(AddressSpace space, JitVal offset, int size, boolean quantize,
			JitVal val) {
		/**
		 * We use this only to log possible storage bypasses. All uniques will be bypassed.
		 * Registers must be written, but it is safe to bypass subsequent loads. Actually, perhaps
		 * with a pre-load of register values and a try-finally to write them, we can optimize
		 * register access, too. Might also make sense to do that for uniques, just for debugging
		 * purposes.
		 * 
		 * Memory must be written. Unless we can determine for sure the memory is non-volatile, we
		 * must presume volatile, so no bypassing is allowed. TODO: We might consider assuming
		 * stack-based accesses are non-volatile, but I'm not sure that is appropriate either.
		 * Technically one thread may launch another, providing a ref to a stack variable it knows
		 * will live for the entire thread's life.
		 */
		if (space.isConstantSpace()) {
			Msg.warn(this, "Witnessed write to constant space! Ignoring.");
			return;
		}
		if (!(offset instanceof JitConstVal c)) {
			// Don't attempt bypass for any indirect memory access
			return;
		}

		// NB. There should never be need to quantize in regs or uniqs.
		Varnode varnode = new Varnode(space.getAddress(c.value().longValue()), size);
		varnodesWritten.add(varnode);

		mini.set(varnode, val);
	}

	/**
	 * Get an ordered list of all values involved in the latest definition of the given varnode.
	 * 
	 * @see MiniDFState#getDefinitions(AddressSpace, long, int)
	 * @param varnode the varnode whose definitions to retrieve
	 * @return the list of values
	 */
	public List<JitVal> getDefinitions(Varnode varnode) {
		return mini.getDefinitions(varnode);
	}

	/**
	 * Get an ordered list of all values involved in the latest definition of the given varnode.
	 * 
	 * @see MiniDFState#getDefinitions(AddressSpace, long, int)
	 * @param register the register whose definitions to retrieve
	 * @return the list of values
	 */
	public List<JitVal> getDefinitions(Register register) {
		return mini.getDefinitions(register);
	}

	/**
	 * Replace missing variables with phi nodes, mutating the given list in place
	 * 
	 * @param defs the definitions
	 * @return the same list, modified
	 */
	List<JitVal> generatePhis(List<JitVal> defs, SequencedSet<JitPhiOp> phiQueue) {
		return mini.generatePhis(defs, phiQueue);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * This and {@link #setVar(AddressSpace, JitVal, int, boolean, JitVal)} are where we connect the
	 * interpretation to the maps of definitions we keep in this state. We examine the varnode's
	 * type first. If it's a constant or memory variable, it just returns the appropriate
	 * {@link JitConstVal}, {@link JitDirectMemoryVar}, or {@link JitIndirectMemoryVar}. If it's a
	 * register or unique, then we retrieve the latest definition(s) as in
	 * {@link MiniDFState#getDefinitions(AddressSpace, long, int)}. In the simple case of an exact
	 * definition, we return it. Otherwise, this synthesizes the appropriate op(s), enters them into
	 * the use-def graph, and returns the final output.
	 */
	@Override
	public JitVal getVar(AddressSpace space, JitVal offset, int size, boolean quantize,
			Reason reason) {
		if (space.isConstantSpace()) {
			if (!(offset instanceof JitConstVal c)) {
				throw new AssertionError("Non-constant constant?");
			}
			if (c.size() == size) {
				return offset;
			}
			return new JitConstVal(size, c.value());
		}
		if (space.isMemorySpace()) {
			if (offset instanceof JitConstVal c) {
				Varnode vn = new Varnode(space.getAddress(c.value().longValue()), size);
				return dfm.generateDirectMemoryVar(vn);
			}
			return dfm.generateIndirectMemoryVar(space, offset, size, quantize);
		}
		if (!(offset instanceof JitConstVal c)) {
			throw new AssertionError("Indirect non-memory access?");
		}

		Varnode varnode = new Varnode(space.getAddress(c.value().longValue()), size);
		varnodesRead.add(varnode);

		return mini.getVar(varnode);
	}

	@Override
	public Map<Register, JitVal> getRegisterValues() {
		throw new UnsupportedOperationException();
	}

	@Override
	public MemBuffer getConcreteBuffer(Address address, Purpose purpose) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void clear() {
		throw new UnsupportedOperationException();
	}

	@Override
	public PcodeExecutorState<JitVal> fork() {
		throw new UnsupportedOperationException();
	}

	/**
	 * Get a complete catalog of all varnodes read, including overlapping, subregs, etc.
	 * 
	 * @return the set of varnodes
	 */
	public Set<Varnode> getVarnodesRead() {
		return varnodesRead;
	}

	/**
	 * Get a complete catalog of all varnodes written, including overlapping, subregs, etc.
	 * 
	 * @return the set of varnodes
	 */
	public Set<Varnode> getVarnodesWritten() {
		return varnodesWritten;
	}

	/**
	 * Capture the current state of intra-block analysis.
	 * 
	 * <p>
	 * This may be required for follow-up op-use analysis by a {@link JitCallOtherOpIf} invoked
	 * using the standard strategy. All live varnodes <em>at the time of the call</em> must be
	 * considered used.
	 * 
	 * @return the captured state
	 */
	public MiniDFState captureState() {
		return mini.copy();
	}
}
