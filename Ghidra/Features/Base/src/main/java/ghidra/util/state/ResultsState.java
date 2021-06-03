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
package ghidra.util.state;

import java.util.*;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.state.ContextState.FrameNode;
import ghidra.util.task.TaskMonitor;

public class ResultsState {

	private static boolean DEBUG = true;

	private static final long[] VALUE_MASK = new long[] { 0x0, 0x0ff, 0x0ffff, 0x0ffffff,
		0x0ffffffffL, 0x0ffffffffffL, 0x0ffffffffffffL, 0x0ffffffffffffffL, -1 };

	private static final long[] SIGN_BIT = new long[] { 0x0, 0x080, 0x08000, 0x0800000,
		0x080000000L, 0x08000000000L, 0x0800000000000L, 0x080000000000000L };

	private static final Iterator<ContextState> emptyContextStateIterator =
		new Iterator<ContextState>() {
			@Override
			public boolean hasNext() {
				return false;
			}

			@Override
			public ContextState next() {
				return null;
			}

			@Override
			public void remove() {
			}
		};

	//public final Varnode UNKNOWN_VALUE = new Varnode(Address.NO_ADDRESS, 0);
	private boolean busy = true;
	private final FunctionAnalyzer analyzer;
	private final Program program;
	private final Listing listing;
	private final AddressFactory addrFactory;
	//private final AddressSpace uniqueSpace;
	private final boolean maintainInstructionResults;  // maintain instruction state instead of block 

	private SequenceNumber entryPt;
	private LinkedList<SequenceNumber> flowList;

	private Varnode stackVarnode;       // varnode that represents the stack pointer
	private ContextState entryState;	// initial entry-state
	private Function currentFunction;
	private PrototypeModel currentPrototype;
	private Long paramBaseStackOffset;
	private boolean stackGrowsNegative;
	private AddressSet examinedSet;
	private LinkedList<BranchDestination> todoList = new LinkedList<BranchDestination>();

	// Map<blockEntry, Map<flowFrom, blockContext>>
	//private HashMap<SequenceNumber, HashMap<SequenceNumber, ContextState>> stateMapByEntry = new HashMap<SequenceNumber, HashMap<SequenceNumber, ContextState>>();

	// Map<blockEntry, Map<flowFrom, blockContext>>
	//private HashMap<SequenceNumber, HashMap<SequenceNumber, ContextState>> stateMapByExit = new HashMap<SequenceNumber, HashMap<SequenceNumber, ContextState>>();

	//private HashMap<SequenceRange, HashMap<SequenceNumber, ContextState>> stateMap = new HashMap<SequenceRange, HashMap<SequenceNumber, ContextState>>();

	// HashMap<terminalPcodeSeq, List of exit states>
	private HashMap<SequenceNumber, List<ContextState>> endStateMap =
		new HashMap<SequenceNumber, List<ContextState>>();

	// Maps external addresses back to the original thunk location
	private HashMap<Long, Address> externalThunkMap = new HashMap<Long, Address>();

	private ArrayList<Register> inputRegs = new ArrayList<Register>();
	private ArrayList<Register> registersModified = new ArrayList<Register>();
	private ArrayList<Register> registersPreserved;

	private HashMap<Register, FramePointerCandidate> framePointerCandidates =
		new HashMap<Register, FramePointerCandidate>();
	private HashSet<Register> framePointerCandidatesDismissed = new HashSet<Register>();

	private LinkedList<ContextStateSet> savedStates = new LinkedList<ContextStateSet>();

	/**
	 * Constructor from a function entry point.  Program context is used to establish the entry context state.
	 * Analysis is performed during construction.
	 * @param entryPt function entry point
	 * @param analyzer function analysis call-back handler
	 * @param program program containing function
	 * @param maintainInstructionResults true to maintain the instruction results
	 * @param monitor task monitor
	 * @throws CancelledException
	 */
	public ResultsState(Address entryPt, FunctionAnalyzer analyzer, Program program,
			boolean maintainInstructionResults, TaskMonitor monitor) throws CancelledException {
		this(new SequenceNumber(entryPt, 0), analyzer, new ContextState(entryPt, program),
			maintainInstructionResults);
		processFunction(monitor);
	}

	/**
	 * Constructor for replaying over a specified set of context states indicated via a flowList.
	 * Analysis is performed during construction.
	 * @param flowList ordered list of context state entry points
	 * @param analyzer function analysis call-back handler
	 * @param entryState context state which feeds into the first point within the flowList
	 * @param maintainInstructionResults
	 * @param monitor task monitor
	 * @throws CancelledException
	 */
	public ResultsState(LinkedList<SequenceNumber> flowList, FunctionAnalyzer analyzer,
			ContextState entryState, boolean maintainInstructionResults, TaskMonitor monitor)
			throws CancelledException {
		this(flowList.getFirst(), analyzer, entryState, maintainInstructionResults);
		this.flowList = new LinkedList<SequenceNumber>(flowList);
		this.flowList.removeFirst();
		processFunction(monitor);
	}

	/**
	 * Constructor for entry point and a specified entryState
	 * @param entryAddr function entry point
	 * @param analyzer function analysis call-back handler
	 * @param entryState context state which feeds into the entry point
	 * @param entryState initial ResultState
	 * @param maintainInstructionResults
	 */
	private ResultsState(SequenceNumber entryPt, FunctionAnalyzer analyzer,
			ContextState entryState, boolean maintainInstructionResults) {
		this.entryPt = entryPt;
		this.analyzer = analyzer;
		this.entryState = entryState;
		this.maintainInstructionResults = maintainInstructionResults;
		program = entryState.getProgram();
		listing = program.getListing();
		addrFactory = program.getAddressFactory();
		currentFunction = listing.getFunctionContaining(entryPt.getTarget());

		if (currentFunction != null) {
			currentPrototype = currentFunction.getCallingConvention();
		}
		if (currentPrototype == null) {
			currentPrototype = program.getCompilerSpec().getDefaultCallingConvention();
		}

		stackGrowsNegative = program.getCompilerSpec().stackGrowsNegative();
		Long stackOffset = currentPrototype.getStackParameterOffset();
		if (stackOffset != null) {
			paramBaseStackOffset = stackOffset - currentPrototype.getStackshift();
		}
		else {
			paramBaseStackOffset = null;
		}

		todoList.add(new BranchDestination(null, entryPt, entryState));
	}

	/**
	 * Returns entry point associated with this results state.
	 */
	public SequenceNumber getEntryPoint() {
		return entryPt;
	}

	/**
	 * Returns set of addresses analyzed with function.
	 * (In-line functions not included)
	 */
	public AddressSetView getExaminedSet() {
		return examinedSet;
	}

	/**
	 * Set an assumed register value immediately following construction and prior to flow.
	 * @param register (context register not permitted)
	 * @param value
	 */
	public void assume(Register register, long value) {
		if (register.isProcessorContext()) {
			throw new IllegalArgumentException("Context register not permitted");
		}
		entryState.store(new Varnode(register.getAddress(), register.getMinimumByteSize()),
			new Varnode(addrFactory.getConstantAddress(value), register.getMinimumByteSize()));
	}

//	public Map<SequenceNumber, ContextState> getContextStateStartingAt(SequenceNumber entry) {
//		return stateMapByEntry.get(entry);
//	}
//	
//	public Map<SequenceNumber, ContextState> getContextStateEndingAt(SequenceNumber exit) {
//		return stateMapByExit.get(exit);
//	}

	private void processFunction(TaskMonitor monitor) throws CancelledException {

		ContextState currentState = null;
		ContextState previousState = null;
		SequenceNumber nextSeq = null;
		SequenceNumber flowFrom = null;

		examinedSet = new AddressSet();
//int testCnt = 0;		
		try {
			while (nextSeq != null || !todoList.isEmpty()) {

				monitor.checkCanceled();

				if (nextSeq == null) {
					assert currentState == null;
					BranchDestination dest = todoList.removeFirst();
					nextSeq = dest.destination;
					previousState = dest.initialState;
					flowFrom = dest.source;
				}

				Instruction instr = listing.getInstructionAt(nextSeq.getTarget());
				if (instr == null) {
					program.getBookmarkManager().setBookmark(nextSeq.getTarget(),
						BookmarkType.ERROR, "Missing Instruction",
						"Expected instruction as result of flow from: " + flowFrom);
					nextSeq = null;
					continue;
				}

				examinedSet.addRange(instr.getMinAddress(), instr.getMaxAddress());

				// Check for reference to current instruction - start new state if reference found
				if (nextSeq.getTime() == 0 && currentState != null &&
					program.getReferenceManager().getReferencesTo(nextSeq.getTarget()).hasNext()) {
					addState(flowFrom, currentState);
					previousState = currentState;
					currentState = null;
				}

				if (DEBUG) {
					Msg.debug(this, ">>> At " + nextSeq.getTarget() + "/" + nextSeq.getTime() +
						" " + instr);
				}

				SequenceNumber lastSeq = flowFrom;

				for (PcodeOp pcodeOp : instr.getPcode(true)) {
					monitor.checkCanceled();
					if (pcodeOp.getSeqnum().getTime() < nextSeq.getTime()) {
						// skip forward to PcodeOp associated with nextSeq
						continue;
					}
					lastSeq = pcodeOp.getSeqnum();
					if (currentState == null) {
						ContextStateSet existingStates = getContextStateSet(pcodeOp.getSeqnum());
						if (existingStates != null) {
							if (existingStates.containsKey(flowFrom)) {
								// TODO: We have processed this flow before 
								// TODO: Should we compare existingState with dest.initialState ?
								if (DEBUG) {
									Msg.debug(this, "Flow ignored - already processed: " +
										flowFrom + " -> " + pcodeOp.getSeqnum());
								}
								instr = null; // signal - abort current flow
								break;
							}
							for (ContextState otherEntryState : existingStates.values()) {
								// TODO: Memory can be just as important as registers - should this be done differently
								if (!otherEntryState.hasDifferingRegisters(previousState)) {
									// Re-use existing state where register values match
									addState(flowFrom, otherEntryState);
									instr = null; // signal - abort current flow
									if (DEBUG) {
										Msg.debug(this, "Flow combined - similar state: " +
											flowFrom + " -> " + pcodeOp.getSeqnum());
									}
									break;
								}
							}
						}
						currentState = previousState.branchState(pcodeOp.getSeqnum());
						currentState.addFlowFrom(flowFrom);
						previousState.lock();
						previousState = null;
					}

					try {
						if (!processAndEmulatePCode(pcodeOp, currentState, monitor)) {
							// Terminate context following branch/call/return - end of basic block
							addState(flowFrom, currentState);
							previousState = currentState;
							currentState = null;
						}
					}
					catch (InlineCallException inlineExc) {
						// Terminate context following inline-call, perform inline call to obtain fall-through state
						addState(flowFrom, currentState);
						// TODO: inline call only handles single return state
						previousState =
							performInlineCall(inlineExc.getInlineCallAddress(), currentState,
								monitor);
						if (previousState != null) {
							currentState = null;
						}
					}
				}
				if (currentState != null) {
					currentState.clearUniqueState();
					if (maintainInstructionResults) {
						// Terminate context after every instruction if maintainInstructionResults is true
						addState(flowFrom, currentState);
						previousState = currentState;
						currentState = null;
					}
				}
				nextSeq = null;
				if (instr != null) {
					Address fallthroughAddr = instr.getFallThrough();
					if (fallthroughAddr == null) {
						// No-fallthrough
						if (currentState != null) {
							currentState.lock();
							addState(flowFrom, currentState);
						}
						currentState = null;
						previousState = null;
					}
					else {
						nextSeq = new SequenceNumber(fallthroughAddr, 0);
						if (maintainInstructionResults) {
							flowFrom = lastSeq;
						}
					}
				}
//				if (++testCnt == 20) {
//					return; // TODO: TESTING!
//				}
			}
		}
		finally {
			busy = false;
		}
	}

	private void addState(SequenceNumber flowFrom, ContextState state) {
		SequenceRange seqRange = state.getSequenceRange();
		SystemUtilities.assertTrue(seqRange != null,
			"ContextState does not have sequence range set");
		ContextStateSet existingStates = getContextStateSet(seqRange.getStart());
		if (existingStates == null) {
			existingStates = createContextStateSet(seqRange);
		}
		state.addFlowFrom(flowFrom);
		existingStates.put(flowFrom, state);
	}

	private void addEndState(SequenceNumber returnPcodeSeq, ContextState state) {
		List<ContextState> returnStates = endStateMap.get(returnPcodeSeq);
		if (returnStates == null) {
			returnStates = new ArrayList<ContextState>();
			endStateMap.put(returnPcodeSeq, returnStates);
		}
		else {
			for (ContextState otherEntryState : returnStates) {
				if (!otherEntryState.hasDifferingRegisters(state)) {
					return;
				}
			}
		}
		returnStates.add(state);
	}

	private static Comparator<Object> CONTEXT_STATE_SET_SEQUENCE_COMPARATOR =
		new Comparator<Object>() {
			@Override
			public int compare(Object o1, Object o2) {
				ContextStateSet set = (ContextStateSet) o1;
				SequenceNumber seq = (SequenceNumber) o2;
				if (set.seqRange.contains(seq)) {
					return 0;
				}
				return set.seqRange.getStart().compareTo(seq);
			}
		};

	private static class BranchDestination {
		private final SequenceNumber source; // null used for initial entry flow only
		private final SequenceNumber destination;
		private final ContextState initialState;

		BranchDestination(SequenceNumber source, Address destinationAddress,
				ContextState initialState) {
			this(source, new SequenceNumber(destinationAddress, 0), initialState);
		}

		BranchDestination(SequenceNumber source, SequenceNumber destination,
				ContextState initialState) {
			this.source = source;
			this.destination = destination;
			this.initialState = initialState;
		}
	}

	private static class ContextStateSet extends HashMap<SequenceNumber, ContextState> {

		private final SequenceRange seqRange;

		ContextStateSet(SequenceRange seqRange) {
			this.seqRange = seqRange;
		}
	}

	private static class InlineCallException extends Exception {
		private final Address destAddr;

		public InlineCallException(Address destAddr) {
			super();
			this.destAddr = destAddr;
		}

		public Address getInlineCallAddress() {
			return destAddr;
		}
	}

	public Iterator<ContextState> getContextStates(SequenceNumber seq) {
		ContextStateSet set = getContextStateSet(seq);
		if (set != null) {
			return set.values().iterator();
		}
		return emptyContextStateIterator;
	}

	private ContextStateSet getContextStateSet(SequenceNumber seq) {
		int index =
			Collections.binarySearch(savedStates, seq, CONTEXT_STATE_SET_SEQUENCE_COMPARATOR);
		if (index >= 0) {
			return savedStates.get(index);
		}
		return null;
	}

	private ContextStateSet createContextStateSet(SequenceRange seqRange) {
		int index =
			Collections.binarySearch(savedStates, seqRange.getStart(),
				CONTEXT_STATE_SET_SEQUENCE_COMPARATOR);
		if (index >= 0) {
			throw new AssertException();
		}
		index = -index - 1;
		ContextStateSet set = new ContextStateSet(seqRange);
		savedStates.add(index, set);
		return set;
	}

	private ContextState performInlineCall(Address inlineCallAddress, ContextState currentState,
			TaskMonitor monitor) throws CancelledException {

		if (DEBUG) {
			Msg.debug(this, "*** Start Inline Call to " + inlineCallAddress + " ***");
		}
		ResultsState inlineState =
			new ResultsState(new SequenceNumber(inlineCallAddress, 0), null, currentState,
				maintainInstructionResults);
		inlineState.processFunction(monitor);
		if (DEBUG) {
			Msg.debug(this, "*** End Inline Call to " + inlineCallAddress + " ***");
		}

// TODO: How should multiple return states be handled ??

		Iterator<List<ContextState>> iterator = inlineState.endStateMap.values().iterator();
		if (iterator.hasNext()) {
			return iterator.next().get(0);
		}
		return null;
	}

	/**
	 * Process an instruction pcode operation after performing simplification on the inputs and operation
	 * @param pcodeOp
	 * @param currentState
	 * @param monitor task monitor
	 * @return true if state can continue to be propagated, otherwise a new state is
	 * required due to the processing of a branch operation.
	 * @throws CancelledException
	 * @throws InlineCallException
	 */
	boolean processAndEmulatePCode(PcodeOp pcodeOp, ContextState currentState, TaskMonitor monitor)
			throws CancelledException, InlineCallException {

		SequenceNumber seq = pcodeOp.getSeqnum();
		currentState.setExitPoint(seq);

		Varnode[] inputs = pcodeOp.getInputs();
		Varnode output = pcodeOp.getOutput();
		Varnode[] values = new Varnode[inputs.length];
		for (int i = 0; i < inputs.length; i++) {
			values[i] = simplify(currentState.get(inputs[i], monitor), monitor);
			if (values[i] == null) {
				values[i] = inputs[i];
				checkInput(inputs[i]);
			}
			else if (output != null && inputs[i].isAddress() && values[i].isConstant()) {
				if (listing.getFunctionAt(inputs[i].getAddress()) != null) {
					externalThunkMap.put(values[i].getOffset(), inputs[i].getAddress());
				}
			}
		}

		if (analyzer != null) {
			for (Varnode input : inputs) {
				// TODO: Watch out for memory based registers - could produce lots of references
				// TODO: Should we ever include simplified input values which are addresses ?
				if (input.isAddress()) {
					int opIndex = findOpIndex(pcodeOp, input);
					analyzer.dataReference(pcodeOp, opIndex, input, RefType.READ, monitor);
				}
			}
			if (output != null && output.isAddress()) {
				int opIndex = findOpIndex(pcodeOp, output);
				analyzer.dataReference(pcodeOp, opIndex, output, RefType.WRITE, monitor);
			}
		}

		if (output != null && output.getSize() > 8) {
			// Can't perform constant propagation values larger than a long
			Varnode result = new VarnodeOperation(pcodeOp, values);
			checkAssignment(output, result, pcodeOp, monitor);
			currentState.store(output, result);
			return true; // flow instructions do not have output
		}

		Varnode result = null;
		if (pcodeOp.getOpcode() == PcodeOp.LOAD) {
			result = simplifyLoad(pcodeOp, values, currentState, monitor);
		}
		else {
			result = simplify(pcodeOp, values, addrFactory, monitor);
		}

		if (result instanceof VarnodeOperation) {
			if (!emulateOperation((VarnodeOperation) result, currentState, monitor)) {
				return false;
			}
		}

		if (output != null) {
			if (result == null) {
				throw new AssertException("Result should not be null");
				//result = new VarnodeOperation(pcodeOp, values);
			}
			checkAssignment(output, result, pcodeOp, monitor);
			currentState.store(output, result);
		}

		return true;
	}

	private Varnode simplify(Varnode varnode, TaskMonitor monitor) throws CancelledException {
		if (varnode == null || !(varnode instanceof VarnodeOperation)) {
			return varnode;
		}
		VarnodeOperation op = (VarnodeOperation) varnode;
		if (op.isSimplified()) {
			return op;
		}
		Varnode result = simplify(op.getPCodeOp(), op.getInputValues(), addrFactory, monitor);
		if (result instanceof VarnodeOperation) {
			((VarnodeOperation) result).setSimplified(true);
		}
		return result;
	}

	private Varnode simplifyLoad(PcodeOp pcodeOp, Varnode[] values, ContextState currentState,
			TaskMonitor monitor) throws CancelledException {

		Varnode output = pcodeOp.getOutput();
		Varnode result;
		if (!values[0].isConstant()) {
			throw new AssertException("Expected constatnt address space ID");
		}
		int spaceId = (int) values[0].getOffset();
		AddressSpace addressSpace = addrFactory.getAddressSpace(spaceId);
		if (addressSpace == null) {
			throw new IllegalArgumentException("Unknown spaceID: " + spaceId);
		}
		int size = output.getSize();
		Varnode storageOffset = values[1];
		Varnode stackOffset = getStackOffset(pcodeOp, storageOffset, monitor);
		if (stackOffset != null) {
			// stackOffset is either constant or VarnodeOperation
			if (stackOffset.isConstant()) {
				long offset = getSignedOffset(stackOffset);
				AddressSpace stackSpace = addrFactory.getStackSpace();
				Varnode stackVarnode = new Varnode(stackSpace.getAddress(offset, true), size);
				result = currentState.get(stackVarnode, monitor);
				if (result == null) {
					result = stackVarnode;
				}
				if (analyzer != null) {
					int opIndex = findOpIndex(pcodeOp, pcodeOp.getInput(1));
					analyzer.stackReference(pcodeOp, opIndex, (int) offset, size, spaceId,
						RefType.READ, monitor);
				}
			}
			else if (stackOffset instanceof VarnodeOperation) {
				result = currentState.get(spaceId, storageOffset, size, monitor);
				if (analyzer != null) {
					int opIndex = findOpIndex(pcodeOp, pcodeOp.getInput(1));
					analyzer.stackReference(pcodeOp, opIndex, (VarnodeOperation) stackOffset, size,
						spaceId, RefType.READ, monitor);
				}
			}
			else {
				// stack pointer is likely invalid
				result = null;
			}
		}
		else if (storageOffset.isConstant()) {
			Varnode v =
 new Varnode(addressSpace.getAddress(storageOffset.getOffset(), true), size);
			result = currentState.get(v, monitor);
			if (result != null && result.isConstant()) {
				if (listing.getFunctionAt(v.getAddress()) != null) {
					externalThunkMap.put(result.getOffset(), v.getAddress());
				}
			}
			if (analyzer != null) {
				int opIndex = findOpIndex(pcodeOp, pcodeOp.getInput(1));
				analyzer.dataReference(pcodeOp, opIndex, v, RefType.READ, monitor);
			}
		}
		else {
			result = currentState.get(spaceId, storageOffset, size, monitor);
			if (analyzer != null) {
				int opIndex = findOpIndex(pcodeOp, pcodeOp.getInput(1));
				analyzer.indirectDataReference(pcodeOp, opIndex, storageOffset, size, spaceId,
					RefType.READ, monitor);
			}
		}
		if (result == null) {
			result = new VarnodeOperation(pcodeOp, values);
		}
		return result;
	}

	private static long nextPrivateUnique = -1;

	/**
	 * Generate unused unique varnode
	 */
	private static synchronized Varnode getNewUnique(AddressFactory addrFactory, int size) {
		AddressSpace uniqueSpace = addrFactory.getAddressSpace("unique");
		return new Varnode(uniqueSpace.getAddress(nextPrivateUnique--), size);
	}

	/**
	 * Process an instruction pcode operation represented by a VarnodeOperation.
	 * @param op
	 * @param currentState
	 * @param monitor task monitor
	 * @return true if state can continue to be propagated, otherwise a new state is
	 * required due to the processing of a branch operation.
	 * @throws CancelledException
	 * @throws InlineCallException 
	 */
	private boolean emulateOperation(VarnodeOperation op, ContextState currentState,
			TaskMonitor monitor) throws CancelledException, InlineCallException {

		PcodeOp pcodeOp = op.getPCodeOp();
		SequenceNumber seq = pcodeOp.getSeqnum();
		Varnode[] inputs = pcodeOp.getInputs();
		Varnode[] values = op.getInputValues();

		switch (pcodeOp.getOpcode()) {

			case PcodeOp.STORE:
				if (!values[0].isConstant()) {
					throw new AssertException("Expected constatnt address space ID");
				}
				int spaceId = (int) values[0].getOffset();
				AddressSpace addressSpace = addrFactory.getAddressSpace(spaceId);
				if (addressSpace == null) {
					throw new IllegalArgumentException("Unknown spaceID: " + spaceId);
				}
				Varnode storedValue = values[2];
				int size = values[2].getSize();
				Varnode storageOffset = values[1];
				Varnode stackOffset = getStackOffset(pcodeOp, storageOffset, monitor);
				if (stackOffset != null) {
					// stackOffset is either constant or VarnodeOperation
					if (stackOffset.isConstant()) {
						long offset = getSignedOffset(stackOffset);
						AddressSpace stackSpace = addrFactory.getStackSpace();
						Varnode stackVarnode =
							new Varnode(stackSpace.getAddress(offset, true), size);
						currentState.store(stackVarnode, storedValue);
						if (analyzer != null) {
							int opIndex = findOpIndex(pcodeOp, pcodeOp.getInput(1));
							analyzer.stackReference(pcodeOp, opIndex, (int) offset, size, spaceId,
								RefType.WRITE, monitor);
						}
					}
					else if (stackOffset instanceof VarnodeOperation) {
						currentState.store(spaceId, storageOffset, storedValue, size);
						if (analyzer != null) {
							int opIndex = findOpIndex(pcodeOp, pcodeOp.getInput(1));
							analyzer.stackReference(pcodeOp, opIndex,
								(VarnodeOperation) stackOffset, size, spaceId, RefType.WRITE,
								monitor);
						}
					}
				}
				else if (storageOffset.isConstant()) {
					Varnode v =
						new Varnode(addressSpace.getAddress(storageOffset.getOffset() *
							addressSpace.getAddressableUnitSize()), size);
					currentState.store(v, storedValue);
					if (analyzer != null) {
						int opIndex = findOpIndex(pcodeOp, pcodeOp.getInput(1));
						analyzer.dataReference(pcodeOp, opIndex, v, RefType.WRITE, monitor);
					}
				}
				else {
					currentState.store(spaceId, storageOffset, storedValue, size);
					if (analyzer != null) {
						int opIndex = findOpIndex(pcodeOp, pcodeOp.getInput(1));
						analyzer.indirectDataReference(pcodeOp, opIndex, storageOffset, size,
							spaceId, RefType.WRITE, monitor);
					}
				}
				break;

			case PcodeOp.CBRANCH:			// Conditional branch, input 1 is boolean condition

				if (values[1].isConstant() && values[1].getOffset() == 0) {
// TODO: This is a problem, since branch case may never be evaluated!
					if (DEBUG) {
						Msg.debug(this, "Conditional Branch to " + inputs[0].getAddress() +
							" - Not taken due to false condition value");
					}
					break;  // Fall-through case - assume that a pre-condition is steering the execution
				}

				//TODO: Establish pre-condition on destination context state
				//TODO: Can we simplify the values[1] expression when we assume a constrained value of values[1]

				// Fall into BRANCH case below

			case PcodeOp.BRANCH:			// Always branch
				if (inputs[0].isConstant()) {
					SequenceNumber dest =
						new SequenceNumber(seq.getTarget(), seq.getTime() +
							(int) inputs[0].getOffset());
					if (DEBUG) {
						Msg.debug(this, "Internal " +
							(pcodeOp.getOpcode() == PcodeOp.CBRANCH ? "Conditional " : "") +
							"Branch to " + dest);
					}
					todoList.add(new BranchDestination(pcodeOp.getSeqnum(), dest, currentState));
				}
				else if (inputs[0].isAddress()) {
					if (DEBUG) {
						Msg.debug(this, (pcodeOp.getOpcode() == PcodeOp.CBRANCH ? "Conditional "
								: "") + "Branch to " + inputs[0].getAddress());
					}
					handleDirectFlow(pcodeOp, inputs[0].getAddress(), currentState, monitor);
				}
				else {
					// TODO: This should never occur
					throw new AssertException();
				}
				return false;

			case PcodeOp.BRANCHIND:			// An indirect branch (jumptable)
				if (values[0].isConstant()) {
					// Indirect branch was resolved, although more destinations may be possible
					AddressSpace space = currentState.getEntryPoint().getTarget().getAddressSpace();
					Address destAddr =
						space.getAddress(getUnsignedOffset(values[0], space.getPointerSize()));
					if (DEBUG) {
						Msg.debug(this, "Branch to " + destAddr);
					}
					handleDirectFlow(pcodeOp, destAddr, currentState, monitor);
				}
				else if (values[0].isAddress()) {

					Varnode brOffset = currentState.get(values[0], monitor);
					if (brOffset != null && brOffset.isConstant() && brOffset.getOffset() != 0) {
						AddressSpace space =
							currentState.getEntryPoint().getTarget().getAddressSpace();
						Address destAddr =
							space.getAddress(getUnsignedOffset(brOffset, space.getPointerSize()));
						if (DEBUG) {
							Msg.debug(this, "Indirect Branch to [" + values[0].getAddress() +
								"] -> " + destAddr);
						}
						handleDirectFlow(pcodeOp, destAddr, currentState, monitor);
					}
					else {
						if (DEBUG) {
							Msg.debug(this,
								"Indirect Branch to [" + values[0].toString(program.getLanguage()) +
									"]");
						}
						handleIndirectFlow(pcodeOp, values[0], currentState, monitor);
					}
				}
				else {
					if (DEBUG) {
						Msg.debug(this,
							"Indirect Branch to [" + values[0].toString(program.getLanguage()) +
								"]");
					}
					handleIndirectFlow(pcodeOp, values[0], currentState, monitor);
				}
				return false;

			case PcodeOp.CALL:		        // A call with absolute address	  
				if (inputs[0].isAddress()) {
					if (DEBUG) {
						Msg.debug(this, "Call to " + inputs[0].getAddress());
					}
					handleCall(pcodeOp, null, inputs[0].getAddress(), currentState, monitor);
				}
				else {
					//TODO: This should never occur
					throw new AssertException();
				}
				return false;

			case PcodeOp.CALLIND:			// An indirect call
				Address indirectPtr = inputs[0].isAddress() ? inputs[0].getAddress() : null;
// TODO: When indirect through a register we loose where the original pointer came from (indirect=null) which mean we can't find the thunk function
				if (values[0].isConstant()) {
					AddressSpace space = currentState.getEntryPoint().getTarget().getAddressSpace();
					Address destAddr =
						space.getAddress(getUnsignedOffset(values[0], space.getPointerSize()));
					if (DEBUG) {
						Msg.debug(this, "Call to " + destAddr);
					}
					handleCall(pcodeOp, indirectPtr, destAddr, currentState, monitor);
				}
				else if (values[0].isAddress()) {

					Varnode callOffset = currentState.get(values[0], monitor);
					if (callOffset != null && callOffset.isConstant() &&
						callOffset.getOffset() != 0) {
						AddressSpace space =
							currentState.getEntryPoint().getTarget().getAddressSpace();
						Address destAddr =
							space.getAddress(getUnsignedOffset(callOffset, space.getPointerSize()));
						if (DEBUG) {
							Msg.debug(this, "Indirect Call to [" + values[0].getAddress() +
								"] -> " + destAddr);
						}
						handleCall(pcodeOp, indirectPtr, destAddr, currentState, monitor);
					}
					else {
						if (DEBUG) {
							Msg.debug(this,
								"Indirect Call to [" + values[0].toString(program.getLanguage()) +
									"]");
						}
						handleIndirectCall(pcodeOp, indirectPtr, values[0], currentState, monitor);
					}
				}
				else {
					if (DEBUG) {
						Msg.debug(this,
							"Indirect Call to [" + values[0].toString(program.getLanguage()) + "]");
					}
					handleIndirectCall(pcodeOp, indirectPtr, values[0], currentState, monitor);
				}
				return false;

			case PcodeOp.CALLOTHER:    		// Other unusual subroutine calling conventions
				// TODO: Affects are ignored
				break;

			case PcodeOp.RETURN:			// A return from subroutine
				addEndState(pcodeOp.getSeqnum(), currentState);
				return false;

		}

		return true;
	}

	/**
	 * Check varnode for possible stack read/write and provide
	 * stack address varnode replacement.
	 * @param pcodeOp operation which references stack location as input
	 * @param offsetValue offset value
	 * @return a stack offset if appropriate or null.
	 */
	private Varnode getStackOffset(PcodeOp loadStoreOp, Varnode offsetValue, TaskMonitor monitor) {
		Varnode stackPtr = getStackPointerVarnode();
		if (offsetValue instanceof VarnodeOperation) {
			VarnodeOperation op = (VarnodeOperation) offsetValue;
			int opcode = op.getPCodeOp().getOpcode();
			Varnode[] inputs = op.getInputValues();
			if (opcode == PcodeOp.INT_ADD) {
				if (inputs[0].isConstant() && inputs[1].equals(stackPtr)) {
					return inputs[0];
				}
				if (inputs[1].isConstant() && inputs[0].equals(stackPtr)) {
					return inputs[1];
				}
			}
			else if (opcode == PcodeOp.INT_SUB) {
				if (inputs[1].isConstant() && inputs[0].equals(stackPtr)) {
					return new Varnode(addrFactory.getConstantAddress(-getSignedOffset(inputs[1])),
						inputs[1].getSize());
				}
			}
		}
		else if (offsetValue.equals(stackPtr)) {
			return new Varnode(addrFactory.getConstantAddress(0), stackPtr.getSize());
		}
		return null;
	}

	/**
	 * Generate simplified operation
	 * @param pcodeOp pcode operation
	 * @param values values associated with pcodeOp inputs
	 * @return operation output result or simplification of an operation.
	 */
	public static Varnode simplify(PcodeOp pcodeOp, Varnode[] values, AddressFactory addrFactory,
			TaskMonitor monitor) throws CancelledException {

		SequenceNumber seq = pcodeOp.getSeqnum();
		Varnode output = pcodeOp.getOutput();
		Varnode result = null;

		switch (pcodeOp.getOpcode()) {

			case PcodeOp.COPY:		        // Copy one operand to another
				result = values[0];
				break;

			case PcodeOp.INT_EQUAL:	        // Return TRUE if operand1 == operand2
				if (values[0].equals(values[1])) {
					result = new Varnode(addrFactory.getConstantAddress(1), 1);
				}
				else if (values[0].isConstant() && values[1].isConstant()) {
					int b =
						(getUnsignedOffset(values[0], values[0].getSize()) == getUnsignedOffset(
							values[1], values[1].getSize())) ? 1 : 0;
					result = new Varnode(addrFactory.getConstantAddress(b), 1);
				}
				break;

			case PcodeOp.INT_NOTEQUAL:	    // Return TRUE if operand1 != operand2
				if (values[0].equals(values[1])) {
					result = new Varnode(addrFactory.getConstantAddress(0), 1);
				}
				else if (values[0].isConstant() && values[1].isConstant()) {
					int b =
						(getUnsignedOffset(values[0], values[0].getSize()) != getUnsignedOffset(
							values[1], values[1].getSize())) ? 1 : 0;
					result = new Varnode(addrFactory.getConstantAddress(b), 1);
				}
				break;

			case PcodeOp.INT_SLESS:         // Return TRUE if signed op1 < signed op2
				if (values[0].isConstant() && values[1].isConstant()) {
					int b = (getSignedOffset(values[0]) < getSignedOffset(values[1])) ? 1 : 0;
					result = new Varnode(addrFactory.getConstantAddress(b), 1);
				}
				break;

			case PcodeOp.INT_SLESSEQUAL:	// Return TRUE if signed op1 <= signed op2
				if (values[0].isConstant() && values[1].isConstant()) {
					int b = (getSignedOffset(values[0]) <= getSignedOffset(values[1])) ? 1 : 0;
					result = new Varnode(addrFactory.getConstantAddress(b), 1);
				}
				break;

			case PcodeOp.INT_LESS:			// Return TRUE if unsigned op1 < unsigned op2
				// Also indicates borrow on unsigned substraction
				if (values[0].isConstant() && values[1].isConstant()) {
					int b =
						(getUnsignedOffset(values[0], values[0].getSize()) < getUnsignedOffset(
							values[1], values[1].getSize())) ? 1 : 0;
					result = new Varnode(addrFactory.getConstantAddress(b), 1);
				}
				break;

			case PcodeOp.INT_LESSEQUAL:		// Return TRUE if unsigned op1 <= unsigned op2
				if (values[0].isConstant() && values[1].isConstant()) {
					int b =
						(getUnsignedOffset(values[0], values[0].getSize()) <= getUnsignedOffset(
							values[1], values[1].getSize())) ? 1 : 0;
					result = new Varnode(addrFactory.getConstantAddress(b), 1);
				}
				break;

			case PcodeOp.INT_ZEXT:			// Zero extend operand 
				if (values[0].isConstant()) {
					result =
						new Varnode(addrFactory.getConstantAddress(getUnsignedOffset(values[0],
							values[0].getSize())), output.getSize());
				}
				break;

			case PcodeOp.INT_SEXT:			// Sign extend operand
				if (values[0].isConstant()) {
					long signedOffset = getSignedOffset(values[0]) & VALUE_MASK[output.getSize()];
					result =
						new Varnode(addrFactory.getConstantAddress(signedOffset), output.getSize());
				}
				break;

			case PcodeOp.INT_ADD:			// Unsigned addition of operands of same size
				if (values[0].isConstant()) {
					VarnodeOperation op = flipInputs(pcodeOp, values);
					pcodeOp = op.getPCodeOp();
				}
				if (values[1].isConstant()) {
					if (values[0].isConstant()) {
						long signedOffset =
							(getSignedOffset(values[1]) + getSignedOffset(values[0])) &
								VALUE_MASK[output.getSize()];
						result =
							new Varnode(addrFactory.getConstantAddress(signedOffset),
								output.getSize());
					}
					else if (values[1].getOffset() == 0) {
						result = values[0];
					}
					else if (values[0] instanceof VarnodeOperation) {
						//result = combineIntAddOffset(pcodeOp, (VarnodeOperation)values[0], getSignedOffset(values[1], output.getSize()), monitor);
						result =
							pushDownIntAddOffset((VarnodeOperation) values[0],
								getSignedOffset(values[1]), addrFactory, monitor);
					}
				}
				break;

			case PcodeOp.INT_SUB:			// Unsigned subtraction of operands of same size 
				if (values[0].equals(values[1])) {
					result = new Varnode(addrFactory.getConstantAddress(0), output.getSize());
				}
				else if (values[1].isConstant()) {
					if (values[0].isConstant()) {
						long signedOffset =
							(getSignedOffset(values[0]) - getSignedOffset(values[1])) &
								VALUE_MASK[output.getSize()];
						result =
							new Varnode(addrFactory.getConstantAddress(signedOffset),
								output.getSize());
					}
					else if (values[1].getOffset() == 0) {
						result = values[0];
					}
					else if (values[0] instanceof VarnodeOperation) {
						//result = combineIntAddOffset(pcodeOp, (VarnodeOperation)values[0], -getSignedOffset(values[1], output.getSize()), monitor);
						result =
							pushDownIntAddOffset((VarnodeOperation) values[0],
								-getSignedOffset(values[1]), addrFactory, monitor);
					}
				}
				break;

			case PcodeOp.INT_CARRY:       	// TRUE if adding two operands has overflow (carry)
				return eillimnateCarryOp(pcodeOp, values, addrFactory, monitor);

			case PcodeOp.INT_SCARRY:  		// TRUE if carry in signed addition of 2 ops 

// TODO: Implement constant case

			case PcodeOp.INT_SBORROW:  		// TRUE if borrow in signed subtraction of 2 ops 
				if ((values[1].isConstant() && values[1].getOffset() == 0) ||
					(values[0].isConstant() && values[0].getOffset() == 0)) {
					result = new Varnode(addrFactory.getConstantAddress(0), 1);
				}
				break;

			case PcodeOp.INT_2COMP:   		// Twos complement (for subtracting) of operand 
				if (values[0].isConstant()) {
					result =
						new Varnode(addrFactory.getConstantAddress(-values[0].getOffset()),
							output.getSize());
				}
				break;

			case PcodeOp.INT_NEGATE:
				if (values[0].isConstant()) {
					result =
						new Varnode(addrFactory.getConstantAddress(~values[0].getOffset()),
							output.getSize());
				}
				break;

			case PcodeOp.INT_XOR:			// Exclusive OR of two operands of same size 
				if (values[0].equals(values[1])) {
					// Anything XOR'd with itself is Zero
					result = new Varnode(addrFactory.getConstantAddress(0), output.getSize());
				}
				else if (values[1].isConstant() && values[0].isConstant()) {
					result =
						new Varnode(addrFactory.getConstantAddress(values[0].getOffset() ^
							values[1].getOffset()), output.getSize());
				}
				else if (values[0].isConstant()) {
					if (values[0].getOffset() == 0) {
						result = values[1];
					}
					else {
						VarnodeOperation op = flipInputs(pcodeOp, values);
						result = combineLogicOrOperation(op, addrFactory);
					}
				}
				else if (values[1].isConstant()) {
					if (values[1].getOffset() == 0) {
						result = values[0];
					}
					else {
						VarnodeOperation op = new VarnodeOperation(pcodeOp, values);
						result = combineLogicOrOperation(op, addrFactory);
					}
				}
				break;

			case PcodeOp.INT_AND:
				if ((values[1].isConstant() && values[1].getOffset() == 0) ||
					(values[0].isConstant() && values[0].getOffset() == 0)) {
					// Zero AND'd with anything is Zero
					result = new Varnode(addrFactory.getConstantAddress(0), output.getSize());
				}
				else if (values[1].isConstant() && values[0].isConstant()) {
					result =
						new Varnode(addrFactory.getConstantAddress(values[0].getOffset() &
							values[1].getOffset()), output.getSize());
				}
				else if (values[0].isConstant()) {
					result =
						simplifyWithIntAndMask(seq, values[1],
							getUnsignedOffset(values[0], output.getSize()), addrFactory, monitor);
				}
				else if (values[1].isConstant()) {
					result =
						simplifyWithIntAndMask(seq, values[0],
							getUnsignedOffset(values[1], output.getSize()), addrFactory, monitor);
				}
				break;

			case PcodeOp.INT_OR:
				if (values[0].equals(values[1])) {
					result = values[0];
				}
				else if (values[1].isConstant() && values[0].isConstant()) {
					result =
						new Varnode(addrFactory.getConstantAddress(values[0].getOffset() |
							values[1].getOffset()), output.getSize());
				}
				else if (values[0].isConstant()) {
					if (values[0].getOffset() == 0) {
						result = values[1];
					}
					else {
						VarnodeOperation op = flipInputs(pcodeOp, values);
						result = combineLogicOrOperation(op, addrFactory);
					}
				}
				else if (values[1].isConstant()) {
					if (values[1].getOffset() == 0) {
						result = values[0];
					}
					else {
						VarnodeOperation op = new VarnodeOperation(pcodeOp, values);
						result = combineLogicOrOperation(op, addrFactory);
					}
				}
				break;
			case PcodeOp.INT_LEFT:			// Left shift
				if (values[1].isConstant() && values[1].getOffset() < 64) {
					if (values[0].isConstant()) {
						result =
							new Varnode(
								addrFactory.getConstantAddress(values[0].getOffset() << values[1].getOffset()),
								output.getSize());
					}
					else {
						result = combineDoubleShiftOperation(pcodeOp, values, addrFactory);
					}
				}

				break;
			case PcodeOp.INT_RIGHT:	        // Right shift zero fill 
				if (values[1].isConstant() && values[1].getOffset() < 64) {
					if (values[0].isConstant()) {
						result =
							new Varnode(
								addrFactory.getConstantAddress(values[0].getOffset() >>> values[1].getOffset()),
								output.getSize());
					}
					else {
						result = combineDoubleShiftOperation(pcodeOp, values, addrFactory);
					}
				}
				break;

			case PcodeOp.INT_SRIGHT:       	// Signed right shift 
				if (values[1].isConstant() && values[0].isConstant() && values[1].getOffset() < 64) {
					result =
						new Varnode(
							addrFactory.getConstantAddress(values[0].getOffset() >> values[1].getOffset()),
							output.getSize());
				}
				break;

			case PcodeOp.INT_MULT:			// Integer multiplication 
				if (values[1].isConstant() && values[0].isConstant()) {
					result =
						new Varnode(addrFactory.getConstantAddress(values[0].getOffset() *
							values[1].getOffset()), output.getSize());
				}
				break;

			case PcodeOp.INT_DIV:			// Unsigned integer division
				if (values[1].isConstant() && values[0].isConstant()) {
					if (values[1].getOffset() == 0) {
						Msg.warn(ResultsState.class,
							"Divide by zero encounteerd during emulation at " +
								pcodeOp.getSeqnum().getTarget());
					}
					else {
						result =
							new Varnode(
								addrFactory.getConstantAddress(getUnsignedOffset(values[0],
									output.getSize()) /
									getUnsignedOffset(values[1], output.getSize())),
								output.getSize());
					}
				}
				break;

			case PcodeOp.INT_SDIV:			// Signed integer division
				if (values[1].isConstant() && values[0].isConstant()) {
					if (values[1].getOffset() == 0) {
						Msg.warn(ResultsState.class,
							"Divide by zero encounteerd during emulation at " +
								pcodeOp.getSeqnum().getTarget());
					}
					else {
						result =
							new Varnode(addrFactory.getConstantAddress(values[0].getOffset() /
								values[1].getOffset()), output.getSize());
					}
				}
				break;

			case PcodeOp.INT_REM:			// Unsigned mod (remainder)
				if (values[1].isConstant() && values[0].isConstant()) {
					if (values[1].getOffset() == 0) {
						Msg.warn(ResultsState.class,
							"Divide by zero encounteerd during emulation at " +
								pcodeOp.getSeqnum().getTarget());
					}
					else {
						result =
							new Varnode(
								addrFactory.getConstantAddress(getUnsignedOffset(values[0],
									output.getSize()) %
									getUnsignedOffset(values[1], output.getSize())),
								output.getSize());
					}
				}
				break;

			case PcodeOp.INT_SREM:			// Signed mod (remainder)
				if (values[1].isConstant() && values[0].isConstant()) {
					if (values[1].getOffset() == 0) {
						Msg.warn(ResultsState.class,
							"Divide by zero encounteerd during emulation at " +
								pcodeOp.getSeqnum().getTarget());
					}
					else {
						result =
							new Varnode(addrFactory.getConstantAddress(values[0].getOffset() %
								values[1].getOffset()), output.getSize());
					}
				}
				break;

			case PcodeOp.BOOL_NEGATE:		// Boolean negate or not
				if (values[0].isConstant()) {
					int b = values[0].getOffset() != 0 ? 0 : 1;
					result = new Varnode(addrFactory.getConstantAddress(b), 1);
				}
				else if (values[0] instanceof VarnodeOperation) {
					VarnodeOperation opVal = (VarnodeOperation) values[0];
					if (opVal.getPCodeOp().getOpcode() == PcodeOp.BOOL_NEGATE) {
						result = opVal.getInputValues()[0]; // double-negative case
					}
				}
				break;

			case PcodeOp.BOOL_XOR:			// Boolean xor
				if (values[0].equals(values[1])) {
					result = new Varnode(addrFactory.getConstantAddress(0), 1);
				}
				else if (values[1].isConstant() && values[0].isConstant()) {
					boolean v0 = (values[0].getOffset() != 0);
					boolean v1 = (values[1].getOffset() != 0);
					int b = (v0 != v1) ? 1 : 0;
					result = new Varnode(addrFactory.getConstantAddress(b), 1);
				}
				break;

			case PcodeOp.BOOL_AND:			// Boolean and (&&)
				if (values[0].isConstant()) {
					if (values[0].getOffset() == 0) {
						result = new Varnode(addrFactory.getConstantAddress(0), 1);
					}
					else if (values[1].isConstant()) {
						result =
							new Varnode(
								addrFactory.getConstantAddress(values[1].getOffset() == 0 ? 0 : 1),
								1);
					}
					else {
						result = values[1];
					}
				}
				else if (values[1].isConstant()) {
					if (values[1].getOffset() == 0) {
						result = new Varnode(addrFactory.getConstantAddress(0), 1);
					}
					else {
						result = values[0];
					}
				}
				break;

			case PcodeOp.BOOL_OR:			// Boolean or (||)
				if (values[0].isConstant() && values[0].getOffset() != 0) {
					result = new Varnode(addrFactory.getConstantAddress(1), 1);
				}
				else if (values[1].isConstant() && values[1].getOffset() != 0) {
					result = new Varnode(addrFactory.getConstantAddress(1), 1);
				}
				else if (values[1].isConstant() && values[0].isConstant()) {
					// both values are zero
					result = new Varnode(addrFactory.getConstantAddress(0), 1);
				}
				break;

			case PcodeOp.SUBPIECE:   		// Output is a subpiece of input0, input1=offset into input0
				if (values[0].isConstant()) {
					long val = getUnsignedOffset(values[0], values[0].getSize());
					val = (val >> (8 * values[1].getOffset())) & VALUE_MASK[output.getSize()];
					result = new Varnode(addrFactory.getConstantAddress(val), output.getSize());
				}
				else if (values[1].getOffset() == 0) {
					if (values[0].getSize() == output.getSize()) {
						// unnecessary SUBPIECE
						result = values[0];
					}
					else if (values[0] instanceof VarnodeOperation) {
						VarnodeOperation inputOp = (VarnodeOperation) values[0];
						PcodeOp inputPcodeOp = inputOp.getPCodeOp();
						Varnode[] subInputValues = inputOp.getInputValues();
						if (inputPcodeOp.getOpcode() == PcodeOp.INT_ZEXT &&
							subInputValues[0].getSize() == output.getSize()) {
							// Combine SUBPIECE and ZEXT
							result = subInputValues[0];
						}
					}
				}
				break;

			// floating point instructions:  No floating point data format is specified here,
			// although the exact operation of these instructions obviously depends on the
			// format.  For simulation, a "mode" variable specifying the floating point format
			// will be necessary.
			case PcodeOp.FLOAT_EQUAL:       // Return TRUE if operand1 == operand2    
			case PcodeOp.FLOAT_NOTEQUAL:	// Return TRUE if operand1 != operand2    
			case PcodeOp.FLOAT_LESS:   		// Return TRUE if op1 < op2 
			case PcodeOp.FLOAT_LESSEQUAL:	// Return TRUE if op1 <= op2
			case PcodeOp.FLOAT_NAN:			// Return TRUE if neither op1 is NaN 

			case PcodeOp.FLOAT_ADD:         // float addition
			case PcodeOp.FLOAT_DIV:         // float division
			case PcodeOp.FLOAT_MULT:        // float multiplication
			case PcodeOp.FLOAT_SUB:         // float subtraction
			case PcodeOp.FLOAT_NEG:         // float negation
			case PcodeOp.FLOAT_ABS:         // float absolute value
			case PcodeOp.FLOAT_SQRT:        // float square root

			case PcodeOp.FLOAT_INT2FLOAT:   // convert int type to float type
			case PcodeOp.FLOAT_FLOAT2FLOAT: // convert between float sizes
			case PcodeOp.FLOAT_TRUNC:       // round towards zero
			case PcodeOp.FLOAT_CEIL:        // round towards +infinity
			case PcodeOp.FLOAT_FLOOR:       // round towards -infinity
			case PcodeOp.FLOAT_ROUND:       // round towards nearest

		}

		if (result == null) {
			VarnodeOperation op = new VarnodeOperation(pcodeOp, values);
			op.setSimplified(true);
			result = op;
		}
		return result;
	}

	private static Varnode eillimnateCarryOp(PcodeOp pcodeOp, Varnode[] values,
			AddressFactory addrFactory, TaskMonitor monitor) throws CancelledException {
		if (values[0].isConstant()) {
			VarnodeOperation op = flipInputs(pcodeOp, values);
			pcodeOp = op.getPCodeOp();
		}
		PcodeOp twosCompOp =
			new PcodeOp(pcodeOp.getSeqnum(), PcodeOp.INT_2COMP,
				new Varnode[] { pcodeOp.getInput(1) }, getNewUnique(addrFactory,
					pcodeOp.getInput(1).getSize()));
		Varnode twosCompValue =
			simplify(twosCompOp, new Varnode[] { values[1] }, addrFactory, monitor);

		PcodeOp lessThanOp =
			new PcodeOp(pcodeOp.getSeqnum(), PcodeOp.INT_LESSEQUAL, new Varnode[] {
				twosCompOp.getOutput(), pcodeOp.getInput(0) }, pcodeOp.getOutput());
		return simplify(lessThanOp, new Varnode[] { twosCompValue, values[1] }, addrFactory,
			monitor);
	}

	private static Varnode combineLogicOrOperation(VarnodeOperation op, AddressFactory addrFactory) {
		Varnode[] outerInputValues = op.getInputValues();
		if (!outerInputValues[1].isConstant() || !(outerInputValues[0] instanceof VarnodeOperation)) {
			return null;
		}
		PcodeOp outerPcodeOp = op.getPCodeOp();
		VarnodeOperation innerOp = (VarnodeOperation) outerInputValues[0];
		PcodeOp innerPcodeOp = innerOp.getPCodeOp();
		Varnode[] innerInputValues = innerOp.getInputValues();
		if (outerPcodeOp.getOpcode() != innerPcodeOp.getOpcode() ||
			!innerInputValues[1].isConstant()) {
			return null;
		}
		long outerConst = getUnsignedOffset(outerInputValues[1], outerInputValues[1].getSize());
		long innerConst = getUnsignedOffset(innerInputValues[1], innerInputValues[1].getSize());
		Varnode newConst =
			new Varnode(addrFactory.getConstantAddress(outerConst | innerConst),
				outerInputValues[1].getSize());
		return new VarnodeOperation(outerPcodeOp, new Varnode[] { innerInputValues[0], newConst });
	}

	private static Varnode combineDoubleShiftOperation(PcodeOp outerPcodeOp,
			Varnode[] outerInputValues, AddressFactory addrFactory) {
		if (!outerInputValues[1].isConstant() || !(outerInputValues[0] instanceof VarnodeOperation)) {
			return null;
		}
		VarnodeOperation innerOp = (VarnodeOperation) outerInputValues[0];
		PcodeOp innerPcodeOp = innerOp.getPCodeOp();
		Varnode[] innerInputValues = innerOp.getInputValues();
		if (innerInputValues.length != 2 || !innerInputValues[1].isConstant()) {
			return null;
		}

		int outerOpcode = outerPcodeOp.getOpcode();
		long shift = getUnsignedOffset(outerInputValues[1], outerInputValues[1].getSize());
		long combinedShift = 0;
		if (outerOpcode == PcodeOp.INT_RIGHT) {
			combinedShift = -shift;
		}
		else if (outerOpcode == PcodeOp.INT_LEFT) {
			combinedShift = shift;
		}
		else {
			return null;
		}

		int innerOpcode = innerPcodeOp.getOpcode();
		shift = getUnsignedOffset(outerInputValues[1], outerInputValues[1].getSize());
		if (innerOpcode == PcodeOp.INT_RIGHT) {
			combinedShift -= shift;
		}
		else if (innerOpcode == PcodeOp.INT_LEFT) {
			combinedShift += shift;
		}
		else {
			return null;
		}

		if (combinedShift == 0) {
			return innerInputValues[0];
		}

		int newOpcode = PcodeOp.INT_LEFT;
		if (combinedShift < 0) {
			newOpcode = PcodeOp.INT_RIGHT;
			combinedShift = -combinedShift;
		}
		Varnode newShift =
			new Varnode(addrFactory.getConstantAddress(combinedShift),
				outerInputValues[1].getSize());
		PcodeOp pcodeOp =
			new PcodeOp(outerPcodeOp.getSeqnum(), newOpcode, outerInputValues,
				outerPcodeOp.getOutput());
		return new VarnodeOperation(pcodeOp, new Varnode[] { innerInputValues[0], newShift });
	}

	/**
	 * Flip values and generate new VarnodeOperation which contains new pcodeOp
	 * @param pcodeOp
	 * @param values
	 * @return new VarnodeOperation which contains new pcodeOp
	 */
	private static VarnodeOperation flipInputs(PcodeOp pcodeOp, Varnode[] values) {
		Varnode[] inputs = pcodeOp.getInputs();
		if (inputs.length != 2 || values.length != 2) {
			throw new IllegalArgumentException("flipInputs handles two inputs only");
		}
		Varnode tmp = values[0];
		values[0] = values[1];
		values[1] = tmp;
		pcodeOp =
			new PcodeOp(pcodeOp.getSeqnum(), pcodeOp.getOpcode(), values, pcodeOp.getOutput());
		return new VarnodeOperation(pcodeOp, values);
	}

	private static boolean isBooleanOutputOperation(VarnodeOperation op) {
		PcodeOp pcodeOp = op.getPCodeOp();
		int opcode = pcodeOp.getOpcode();
		return opcode == PcodeOp.BOOL_AND || opcode == PcodeOp.BOOL_NEGATE ||
			opcode == PcodeOp.BOOL_OR || opcode == PcodeOp.BOOL_XOR ||
			opcode == PcodeOp.INT_EQUAL || opcode == PcodeOp.INT_CARRY ||
			opcode == PcodeOp.INT_LESS || opcode == PcodeOp.INT_LESSEQUAL ||
			opcode == PcodeOp.INT_NOTEQUAL || opcode == PcodeOp.INT_SBORROW ||
			opcode == PcodeOp.INT_SCARRY || opcode == PcodeOp.INT_SLESS ||
			opcode == PcodeOp.INT_SLESSEQUAL;
	}

	/**
	 * Simplify specified varnode base upon specified andMask.
	 * @param seq
	 * @param varnode
	 * @param andMask
	 * @return simplified varnode or null if simplification failed
	 */
	private static Varnode simplifyWithIntAndMask(SequenceNumber seq, Varnode varnode,
			long andMask, AddressFactory addrFactory, TaskMonitor monitor)
			throws CancelledException {
		monitor.checkCanceled();
		if (!(varnode instanceof VarnodeOperation)) {
			if (varnode.isConstant()) {
				return new Varnode(addrFactory.getConstantAddress(andMask & varnode.getOffset()),
					varnode.getSize());
			}
			// Can't be simplified
			return null;
		}
		VarnodeOperation op = (VarnodeOperation) varnode;

// TODO: Check -1 andMask

		PcodeOp pcodeOp = op.getPCodeOp();
		int opcode = pcodeOp.getOpcode();

		if (isBooleanOutputOperation(op)) {
			if ((andMask & 1) == 0) {
				return new Varnode(addrFactory.getConstantAddress(0), op.getSize());
			}
		}
		else if (opcode == PcodeOp.INT_AND) {
			Varnode[] values = op.getInputValues();
			Varnode v0 = simplifyWithIntAndMask(seq, values[0], andMask, addrFactory, monitor);
			Varnode v1 = simplifyWithIntAndMask(seq, values[1], andMask, addrFactory, monitor);
			if (v0 == null && v1 == null) {
				op.setSimplified(true);
				return null;
			}
			if (v0 != null) {
				values[0] = v0;
			}
			if (v1 != null) {
				values[1] = v1;
			}

// TODO: Handle double-AND with constants !!

			return simplify(pcodeOp, values, addrFactory, monitor);
		}
		else if (opcode == PcodeOp.INT_OR || opcode == PcodeOp.INT_XOR) {
			Varnode[] values = op.getInputValues();
			Varnode v0 = simplifyWithIntAndMask(seq, values[0], andMask, addrFactory, monitor);
			Varnode v1 = simplifyWithIntAndMask(seq, values[1], andMask, addrFactory, monitor);
			if (v0 == null && v1 == null) {
				op.setSimplified(true);
				return null;
			}
			if (v0 != null) {
				values[0] = v0;
			}
			if (v1 != null) {
				values[1] = v1;
			}
			return simplify(pcodeOp, values, addrFactory, monitor);
		}
		else if (opcode == PcodeOp.INT_LEFT) {
			Varnode[] leftValues = op.getInputValues();
			if (leftValues[1].isConstant() && (leftValues[0] instanceof VarnodeOperation)) {
				int leftShift = (int) leftValues[1].getOffset();
				VarnodeOperation shiftedOp = (VarnodeOperation) leftValues[0];
				long shiftedMask = VALUE_MASK[shiftedOp.getSize()] & (andMask >>> leftShift);
				if (shiftedMask == 0) {
					// shifted value output masked out
					return new Varnode(addrFactory.getConstantAddress(0), op.getSize());
				}
				Varnode modifiedOp =
					simplifyWithIntAndMask(seq, shiftedOp, shiftedMask, addrFactory, monitor);
				if (modifiedOp != null) {
					leftValues[0] = modifiedOp;
					return simplify(pcodeOp, leftValues, addrFactory, monitor);
				}
			}
		}
		else if (opcode == PcodeOp.INT_RIGHT) {
			Varnode[] rightValues = op.getInputValues();
			if (rightValues[1].isConstant() && (rightValues[0] instanceof VarnodeOperation)) {
				int rightShift = (int) rightValues[1].getOffset();
				VarnodeOperation shiftedOp = (VarnodeOperation) rightValues[0];
				long shiftedMask = VALUE_MASK[shiftedOp.getSize()] & (andMask << rightShift);
				if (shiftedMask == 0) {
					// shifted value output masked out
					return new Varnode(addrFactory.getConstantAddress(0), op.getSize());
				}
				Varnode modifiedOp =
					simplifyWithIntAndMask(seq, shiftedOp, shiftedMask, addrFactory, monitor);
				if (modifiedOp != null) {
					rightValues[0] = modifiedOp;
					return simplify(pcodeOp, rightValues, addrFactory, monitor);
				}
			}
		}
		else if (opcode == PcodeOp.SUBPIECE) {
			Varnode[] spValues = op.getInputValues();
			int shift = (int) spValues[1].getOffset() * 8;
			long modifiedMask = (VALUE_MASK[spValues[0].getSize()] & (andMask >> shift) << shift);
			if (modifiedMask == 0) {
				// shifted value output masked out
				return new Varnode(addrFactory.getConstantAddress(0), op.getSize());
			}
			Varnode shiftedOp =
				simplifyWithIntAndMask(seq, spValues[0], modifiedMask, addrFactory, monitor);
			if (shiftedOp != null) {
				spValues[0] = shiftedOp;
				return simplify(pcodeOp, spValues, addrFactory, monitor);
			}
		}
		else if (opcode == PcodeOp.INT_ZEXT) {
			Varnode[] inValues = op.getInputValues();
			long modifiedMask = VALUE_MASK[inValues[0].getSize()] & andMask;
			if (modifiedMask == 0) {
				// Extended value output masked out
				return new Varnode(addrFactory.getConstantAddress(0), op.getSize());
			}
			Varnode extendedOp =
				simplifyWithIntAndMask(seq, inValues[0], modifiedMask, addrFactory, monitor);
			if (extendedOp != null) {
				inValues[0] = extendedOp;
				return simplify(pcodeOp, inValues, addrFactory, monitor);
			}
		}
		else if (opcode == PcodeOp.INT_ADD) {
			// assume constant has already been placed in second input
			Varnode[] values = op.getInputValues();
			Varnode v0 = values[0];
			Varnode v1 = values[1];
			if (v1.isConstant() && (v0 instanceof VarnodeOperation)) {
				// check for add which would not have carry into masked area and would result in 
				// either one of the operands
				if ((v1.getOffset() & ~andMask) == 0) {
					Varnode checkVn =
						simplifyWithIntAndMask(seq, v0, andMask, addrFactory, monitor);
					if (checkVn != null && checkVn.isConstant() && checkVn.getOffset() == 0) {
						return v1;
					}
				}
				else if ((v1.getOffset() & andMask) == 0) {
					VarnodeOperation vop = (VarnodeOperation) v0;
					return simplify(vop.getPCodeOp(), vop.getInputValues(), addrFactory, monitor);
				}
			}
		}
		op.setSimplified(true);
		return null;
	}

	private List<Address> handleIndirectFlow(PcodeOp pcodeOp, Varnode destValue,
			ContextState currentState, TaskMonitor monitor) throws CancelledException {
		List<Address> destinations = null;
		if (analyzer != null) {
			destinations =
				analyzer.unresolvedIndirectFlow(pcodeOp, findOpIndex(pcodeOp, pcodeOp.getInput(0)),
					destValue, currentState, this, monitor);
			if (destinations != null) {
				for (Address dest : destinations) {
					if (pcodeOp.getOpcode() == PcodeOp.BRANCHIND) {
						todoList.add(new BranchDestination(pcodeOp.getSeqnum(), dest, currentState));
					}
					disassemble(dest, monitor);
// TODO: Should we analyze destination function and resume this analysis later ??
				}
			}
		}
		return destinations;
	}

	private void handleDirectFlow(PcodeOp pcodeOp, Address address, ContextState currentState,
			TaskMonitor monitor) throws CancelledException {
		int opcode = pcodeOp.getOpcode();
		if (opcode == PcodeOp.BRANCH || opcode == PcodeOp.CBRANCH) {
			todoList.add(new BranchDestination(pcodeOp.getSeqnum(), address, currentState));
		}
		if (analyzer != null &&
			analyzer.resolvedFlow(pcodeOp, findOpIndex(pcodeOp, pcodeOp.getInput(0)), address,
				currentState, this, monitor)) {
			disassemble(address, monitor);
// TODO: Should we analyze destination function and resume this analysis later ??
		}
	}

	private void disassemble(Address address, TaskMonitor monitor) throws CancelledException {
		CodeUnit cu = listing.getCodeUnitAt(address);
		if (cu instanceof Instruction) {
			return;
		}
		if (cu == null) {
			cu = listing.getCodeUnitContaining(address);
		}
		if (cu == null || !(cu instanceof Data && !((Data) cu).isDefined())) {
			program.getBookmarkManager().setBookmark((cu == null ? address : cu.getMinAddress()),
				BookmarkType.ERROR, "Instruction Expected", "Expected instruction at " + address);
			return;
		}
		if (DEBUG) {
			Msg.debug(this, "Disassemble at " + address);
		}
		DisassembleCommand cmd = new DisassembleCommand(address, null, true);
		cmd.applyTo(program, monitor);
		monitor.checkCanceled();
	}

	/**
	 * Check value assignments for items of interest:
	 * <ul>
	 * <li>Frame pointer identification</li>
	 * <li>Tracking of modified registers</li>
	 * </ul>
	 * @param output output varnode
	 * @param value assigned value
	 * @param op pcode operation
	 * @throws CancelledException 
	 */
	private void checkAssignment(Varnode output, Varnode value, PcodeOp op, TaskMonitor monitor)
			throws CancelledException {

		Varnode[] inputs = op.getInputs();
		int opcode = op.getOpcode();
		if (output != null && !output.isUnique() && opcode != PcodeOp.LOAD &&
			opcode != PcodeOp.STORE && opcode != PcodeOp.COPY) {
			checkStackOffsetAssignment(op, value, monitor);
		}

		Register reg = program.getRegister(output.getAddress(), output.getSize());
		if (reg == null || reg.isProgramCounter() || reg.isProcessorContext() ||
			framePointerCandidatesDismissed.contains(reg.getBaseRegister())) {
			Msg.debug(this, "SET: " + output + " = " + value);
			return;
		}
		if (addRegister(reg, registersModified)) {
			if (DEBUG) {
				Msg.debug(this, "MODIFIED: " + reg + " = " + value);
			}
		}
		else {
			Msg.debug(this, "SET: " + output + " = " + value);
		}
		if (framePointerCandidates.containsKey(reg)) {
			if (value.getAddress().equals(reg.getAddress())) {
				return; // Ignore register restore
			}
			framePointerCandidatesDismissed.add(reg);
			framePointerCandidates.remove(reg);
			return;
		}

		if (opcode != PcodeOp.LOAD) {
			if (value.equals(getStackPointerVarnode()) ||
				(inputs.length == 1 && inputs[0].equals(getStackPointerVarnode())) ||
				(inputs.length == 2 && (inputs[0].equals(getStackPointerVarnode()) || inputs[1].equals(getStackPointerVarnode())))) {
				framePointerCandidates.put(reg, new FramePointerCandidate(reg, op.getSeqnum(),
					value));
				return;
			}
		}
		framePointerCandidatesDismissed.add(reg);
	}

	private void checkStackOffsetAssignment(PcodeOp op, Varnode value, TaskMonitor monitor)
			throws CancelledException {
		if (analyzer == null || !(value instanceof VarnodeOperation)) {
			return;
		}
		Varnode output = op.getOutput();
		if (output == null || output.isUnique()) {
			return;
		}
		FrameNode frameNode = ContextState.getFrameNode(value, program.getLanguage());
		if (frameNode == null || !getStackPointerVarnode().equals(frameNode.getFramePointer())) {
			return;
		}
		Varnode[] inputs = op.getInputs();
		for (Varnode input : inputs) {
			if (input.isConstant() || (input.isUnique() && inputs.length != 1)) {
				continue;
			}
			int opIndex = findOpIndex(op, input);
			if (opIndex >= 0) {
				analyzer.stackReference(op, opIndex, (int) frameNode.getFrameOffset(), -1, -1,
					RefType.DATA, monitor);
				return;
			}
		}
	}

	public class FramePointerCandidate {
		public final Register register;
		public final SequenceNumber assignedAt;
		public final Varnode value;

		FramePointerCandidate(Register register, SequenceNumber assignedAt, Varnode value) {
			this.register = register;
			this.assignedAt = assignedAt;
			this.value = value;
		}

		@Override
		public String toString() {
			return "(" + assignedAt.getTarget() + ", " + register.getName() + "=" +
				value.toString(program.getLanguage()) + ")";
		}
	}

	/**
	 * Returns collection of frame pointer candidates.
	 */
	public Collection<FramePointerCandidate> getFramePointerCandidates() {
		return framePointerCandidates.values();
	}

	/**
	 * Returns the set of registers which were modified yet preserved.
	 */
	public List<Register> getPreservedRegisters() {
		if (registersPreserved == null) {
			reconcileModifiedRegisters();
		}
		return registersPreserved;
	}

	/**
	 * Returns the set of registers which were modified
	 */
	public List<Register> getModifiedRegisters() {
		if (registersPreserved == null) {
			reconcileModifiedRegisters();
		}
		return registersModified;
	}

	private void reconcileModifiedRegisters() {
		if (busy) {
			throw new IllegalStateException(
				"ResultsState.getPreservedRegisters and ResultsState.getModifiedRegisters may not be invoked during instantiation");
		}
		registersPreserved = new ArrayList<Register>();
		for (Register reg : registersModified) {
			if (isPreserved(reg)) {
				registersPreserved.add(reg);
			}
		}
		registersModified.removeAll(registersPreserved);
	}

	private boolean isPreserved(Register reg) {
		Varnode v = new Varnode(reg.getAddress(), reg.getMinimumByteSize());
		Set<Varnode> returnValues = getReturnValues(v);
		if (returnValues.isEmpty()) {
			// TODO: Register was modified but value appears to be unknown ??
			return false;
		}
		for (Varnode val : returnValues) {
			if (!v.equals(val)) {
				return false;
			}
		}
		return true;
	}

//	private boolean operationRefersTo(VarnodeOperation op, Varnode v) {
//		for (Varnode in : op.getInputValues()) {
//			if (in instanceof VarnodeOperation) {
//				if (operationRefersTo((VarnodeOperation)in, v)) {
//					return true;
//				}
//			}
//			else if (in.equals(v)) {
//				return true;
//			}
//		}
//		return false;
//	}

	private int findOpIndex(PcodeOp op, Varnode loc) {
		if (loc instanceof VarnodeOperation) {
			return -1;
		}
		Instruction instr = listing.getInstructionAt(op.getSeqnum().getTarget());
		int numOperands = instr.getNumOperands();
		for (int i = 0; i < numOperands; i++) {
			PcodeOp[] operandPcode = instr.getPcode(i);
			if (operandPcode == null || operandPcode.length == 0) {
				continue;
			}
			if (matchOpPcodeObjectAssignment(operandPcode, loc)) {
				return i;
			}
		}
		int opMatchCnt = 0;
		int lastOpMatch = -1;
		for (int i = 0; i < numOperands; i++) {
			// Check representation
			if (matchOpObject(instr, i, loc)) {
				++opMatchCnt;
				lastOpMatch = i;
			}
		}
		if (opMatchCnt == 1) {
			return lastOpMatch;
		}
		return Reference.MNEMONIC;
	}

	private boolean matchOpPcodeObjectAssignment(PcodeOp[] operandPcode, Varnode loc) {
		for (PcodeOp op : operandPcode) {
			if (loc.equals(op.getOutput())) {
				return true;
			}
		}
		return false;
	}

	private boolean matchOpObject(Instruction instr, int opIndex, Varnode loc) {
		Address addr = loc.getAddress();
		for (Object obj : instr.getDefaultOperandRepresentationList(opIndex)) {
			if (obj instanceof Address) {
				if (addr.equals(obj)) {
					return true;
				}
			}
			else if (obj instanceof Register) {
				Register reg = (Register) obj;
				if (addr.equals(reg.getAddress())) {
					return true;
				}
			}
		}
		return false;
	}

	boolean isStackParameterOffset(long offset) {
		// if there is no offset, then input is not passed on the stack
		if (paramBaseStackOffset == null) {
			return false;
		}
		return (stackGrowsNegative && offset >= paramBaseStackOffset) ||
			(!stackGrowsNegative && offset <= paramBaseStackOffset);
	}

	/**
	 * Check for register corresponding to the specified varnode and add to inputRegs.
	 * @param addressVarnode register or address varnode which has not been written
	 */
	private void checkInput(Varnode addressVarnode) {
// TODO: Should we limit to registers defined in input parameter block
		Address addr = addressVarnode.getAddress();
		Register reg = program.getRegister(addr, addressVarnode.getSize());
		if (reg == null || reg.isProcessorContext() || reg.isProgramCounter() ||
			containsRegister(reg, registersModified)) {
			return;
		}
		addRegister(reg, inputRegs);
	}

	private boolean addRegister(Register reg, List<Register> regList) {
		// Ignore duplicate / reconcile related register
		for (int i = 0; i < regList.size(); i++) {
			Register existingReg = regList.get(i);
			Register parentReg = reg.getParentRegister();
			if (existingReg == reg || existingReg == parentReg ||
				existingReg == reg.getBaseRegister()) {
				return false;
			}
			if (parentReg != null && existingReg.getParentRegister() == parentReg) {
				regList.set(i, parentReg);
				return true;
			}
		}
		regList.add(reg);
		return true;
	}

	private boolean containsRegister(Register reg, List<Register> regList) {
		for (Register existingReg : regList) {
			Register parentReg = reg.getParentRegister();
			if (existingReg == reg || existingReg == parentReg ||
				existingReg == reg.getBaseRegister()) {
				return true;
			}
			if (parentReg != null && existingReg.getParentRegister() == parentReg) {
				return false;
			}
		}
		return false;
	}

	/**
	 * Returns list of registers which are read before written.
	 */
	public List<Register> getInputRegisters() {
		return inputRegs;
	}

	private void handleIndirectCall(PcodeOp pcodeOp, Address indirectPtr, Varnode destValue,
			ContextState currentState, TaskMonitor monitor) throws InlineCallException,
			CancelledException {

		Function func = null;

		Address destAddr = null;
		List<Address> destinations = handleIndirectFlow(pcodeOp, destValue, currentState, monitor);
		if (destinations != null && !destinations.isEmpty()) {
			destAddr = destinations.get(0);
		}
		else if (destValue.isConstant()) {
			destAddr = pcodeOp.getSeqnum().getTarget().getNewAddress(destValue.getOffset());
		}
		if (destAddr != null) {
			func = program.getListing().getFunctionAt(destAddr);
		}
		if (func == null) {
			if (indirectPtr != null) {
				// Check pointer thunk
				func = program.getListing().getFunctionAt(indirectPtr);
			}
			else if (destValue.isConstant()) {
				Address thunkAddr = externalThunkMap.get(destAddr.getOffset());
				if (thunkAddr != null) {
					func = program.getListing().getFunctionAt(thunkAddr);
				}
			}
		}
		else if (func.isInline()) {
			throw new InlineCallException(func.getEntryPoint());
		}

		if (func == null) {
			if (DEBUG) {
				Msg.debug(this, "Function not found at " + indirectPtr +
					" indirectly called from " + pcodeOp.getSeqnum().getTarget() +
					" - call affects unknown");
			}
			return;
		}

		applyFunctionAffects(pcodeOp.getSeqnum(), destAddr, func, currentState, monitor);

		applyFunctionPurge(pcodeOp.getSeqnum(), destAddr, func, currentState, monitor);
	}

	private void handleCall(PcodeOp pcodeOp, Address indirectPtr, Address destAddr,
			ContextState currentState, TaskMonitor monitor) throws InlineCallException,
			CancelledException {

		handleDirectFlow(pcodeOp, destAddr, currentState, monitor);

		Function func = program.getListing().getFunctionAt(destAddr);
		if (func == null) {
			if (indirectPtr != null) {
				// Check pointer thunk
				func = program.getListing().getFunctionAt(indirectPtr);
			}
			else {
				Address thunkAddr = externalThunkMap.get(destAddr.getOffset());
				if (thunkAddr != null) {
					func = program.getListing().getFunctionAt(thunkAddr);
				}
			}
		}
		else if (func.isInline()) {
			throw new InlineCallException(func.getEntryPoint());
		}

		if (func == null) {
			if (DEBUG) {
				Msg.debug(this, "Function not found at " + destAddr + " called from " +
					pcodeOp.getSeqnum().getTarget() + " - call affects unknown");
			}
			return;
		}

		applyFunctionAffects(pcodeOp.getSeqnum(), destAddr, func, currentState, monitor);

		applyFunctionPurge(pcodeOp.getSeqnum(), destAddr, func, currentState, monitor);
	}

	private void applyFunctionAffects(SequenceNumber calledFrom, Address destAddr, Function func,
			ContextState currentState, TaskMonitor monitor) {

		PrototypeModel callingConvention = null;
		if (func != null) {
			callingConvention = func.getCallingConvention();
		}
		if (callingConvention == null) {
			callingConvention = program.getCompilerSpec().getDefaultCallingConvention();
		}

		// TODO: Apply other affects other than return ??

		// TODO: We really do not know what has been affected - how do we manage constant/expression propagation after a call ??

		// Must invalidate return varnode
		DataType returnType = null;
		if (func == null) {
			if (DEBUG) {
				Msg.debug(this,
					"No function at " + destAddr + " called from " + calledFrom.getTarget() +
						" - default return/affects assumed");
			}
		}
		else {
			returnType = func.getReturnType();
			if (VoidDataType.dataType.isEquivalent(returnType)) {
				return;
			}
		}

		VariableStorage retStorage = callingConvention.getReturnLocation(returnType, program);
		Varnode varnode = null;
		if (retStorage.isValid() && (retStorage.getVarnodeCount()==1)) {
			varnode = retStorage.getFirstVarnode();
		}
		if (varnode != null) {
			// invalidate stored value
			currentState.store(varnode, getInvalidatedVarnode(calledFrom, varnode));
		}
	}

	/**
	 * Generate an INDIRECT pcodeop operation representing an unknown state
	 * for an affectedVarnode resulting from a function call at the specified seq.
	 * @param seq CALL or CALLIND pcodeop sequence
	 * @param affectVarnode affected varnode (e.g., return register)
	 * @return indirect varnode operation
	 */
	private VarnodeOperation getInvalidatedVarnode(SequenceNumber seq, Varnode affectVarnode) {
		PcodeOp op = new PcodeOp(seq, PcodeOp.INDIRECT, 0, affectVarnode);
		return new VarnodeOperation(op, op.getInputs());
	}

	private void applyFunctionPurge(SequenceNumber calledFrom, Address destAddr, Function func,
			ContextState currentState, TaskMonitor monitor) throws CancelledException {

		PrototypeModel callingConvention = null;
		if (func != null) {
			callingConvention = func.getCallingConvention();
		}
		if (callingConvention == null) {
			callingConvention = program.getCompilerSpec().getDefaultCallingConvention();
		}
		int stackShift = callingConvention.getStackshift();

		int purge = getFunctionPurge(program, func);
		if (purge == Function.UNKNOWN_STACK_DEPTH_CHANGE ||
			purge == Function.INVALID_STACK_DEPTH_CHANGE) {
			String name = func != null ? func.getName() : ("at " + destAddr);
			if (DEBUG) {
				Msg.debug(this, "Stack purge unknown for function " + name + " called from " +
					calledFrom.getTarget() + " - stack pointer invalidated");
			}
			currentState.store(getStackPointerVarnode(),
				getInvalidatedVarnode(calledFrom, getStackPointerVarnode()));
			return;
		}

		purge += stackShift;
		if (purge == 0) {
			return;
		}
		Varnode stackVarnode = getStackPointerVarnode();
		Varnode purgeVal =
			new Varnode(program.getAddressFactory().getConstantAddress(purge),
				stackVarnode.getSize());
		Varnode stackVal = currentState.get(stackVarnode, monitor);
		if (stackVal == null) {
			stackVal = stackVarnode;
		}
		Varnode purgeResult = null;
		if (stackVal instanceof VarnodeOperation) {
			//purgeResult = combineIntAddOffset(purgePcodeOp, (VarnodeOperation)stackVal, purge, monitor);
			purgeResult =
				pushDownIntAddOffset((VarnodeOperation) stackVal, purge, addrFactory, monitor);
		}
		if (purgeResult == null) {
			PcodeOp purgePcodeOp =
				new PcodeOp(calledFrom, PcodeOp.INT_ADD, new Varnode[] { stackVarnode, purgeVal },
					stackVarnode);
			purgeResult = new VarnodeOperation(purgePcodeOp, new Varnode[] { stackVal, purgeVal });
		}
		currentState.store(stackVarnode, purgeResult);
	}

	/**
	 * Get/Compute the Purge size from the stack for the function
	 * @param func function or null
	 * @return size in bytes that is removed from the stack after the function
	 *         is called.
	 */
	private static int getFunctionPurge(Program functionProgram, Function func) {

		if (func == null) {
			return getDefaultStackDepthChange(functionProgram, Function.UNKNOWN_STACK_DEPTH_CHANGE);
		}

		int depth = func.getStackPurgeSize();
		if (func.isStackPurgeSizeValid()) {
			return depth;
		}

		PrototypeModel proto = func.getCallingConvention();
		if (proto == null) {
			return getDefaultStackDepthChange(functionProgram, depth);
		}

		int callStackMod = proto.getExtrapop();
		int callStackShift = proto.getStackshift();
		if (callStackMod != PrototypeModel.UNKNOWN_EXTRAPOP && callStackShift >= 0) {
			return callStackShift - callStackMod;
		}
		return depth;
	}

	/**
	 * Get the default/assumed stack depth change for this language
	 * 
	 * @param depth stack depth to return if the default is unknown for the language
	 * @return
	 */
	private static int getDefaultStackDepthChange(Program depthProgram, int depth) {
		PrototypeModel defaultModel = depthProgram.getCompilerSpec().getDefaultCallingConvention();
		int callStackMod = defaultModel.getExtrapop();
		int callStackShift = defaultModel.getStackshift();
		if (callStackMod != PrototypeModel.UNKNOWN_EXTRAPOP && callStackShift >= 0) {
			return callStackShift - callStackMod;
		}
		return depth;
	}

	/**
	 * 
	 * @return Varnode that represents the stack pointer register
	 */
	public Varnode getStackPointerVarnode() {
		if (stackVarnode != null) {
			return stackVarnode;
		}

		// figure out what register is used for return values, it must be assumed to be unknown upon return.
		Register stackReg = program.getCompilerSpec().getStackPointer();
		if (stackReg == null) {
			return null;
		}

		stackVarnode = new Varnode(stackReg.getAddress(), stackReg.getMinimumByteSize());
		return stackVarnode;
	}

//	private Varnode combineIntAddOffset(PcodeOp currentOp, VarnodeOperation previousOp, long offset, TaskMonitor monitor) throws CancelledException {
//		if (currentOp.getOpcode() != PcodeOp.INT_ADD && currentOp.getOpcode() != PcodeOp.INT_SUB) {
//			throw new IllegalArgumentException("Unexpected currentOp opcode");
//		}
//		PcodeOp previousPcodeOp = previousOp.getPCodeOp();
//		if (previousPcodeOp.getOpcode() == PcodeOp.INT_ADD || previousPcodeOp.getOpcode() == PcodeOp.INT_SUB) {
//			Varnode[] prevOpValues = previousOp.getInputValues();
//			if (prevOpValues[1].isConstant()){
//				// pull-up constant and combine with offset
//				long prevOffset = getSignedOffset(prevOpValues[1], previousOp.getSize());
//				if (previousPcodeOp.getOpcode() == PcodeOp.INT_SUB) {
//					prevOffset = -prevOffset;
//				}
//				long newOffset = prevOffset + offset;
//				if (currentOp.getOpcode() == PcodeOp.INT_SUB) {
//					newOffset = -newOffset;
//				}
//				Varnode[] simplifiedInputValues = new Varnode[] {
//							prevOpValues[0], 
//							new Varnode(addrFactory.getConstantAddress(newOffset), currentOp.getOutput().getSize())	// new constant
//						};
//				return new VarnodeOperation(currentOp, simplifiedInputValues);
//			}
//			else if (prevOpValues[0] instanceof VarnodeOperation) {
//				// attempt to push constant down to prevOpValues[0] ADD/SUB
//				return pushDownIntAddOffset(previousOp, offset, monitor);
//			}
//		}
//		return null;
//	}

	private static Varnode pushDownIntAddOffset(VarnodeOperation op, long offset,
			AddressFactory addrFactory, TaskMonitor monitor) {
		PcodeOp pcodeOp = op.getPCodeOp();
		if (pcodeOp.getOpcode() == PcodeOp.INT_ADD || pcodeOp.getOpcode() == PcodeOp.INT_SUB) {
			Varnode[] opValues = op.getInputValues();
			if (opValues[1].isConstant()) {
				// push-down constant and combine with offset
				if (pcodeOp.getOpcode() == PcodeOp.INT_SUB) {
					offset = -offset;
				}
				long newOffset = getSignedOffset(opValues[1]) + offset;
				if (newOffset == 0) {
					return opValues[0];
				}
				Varnode[] simplifiedInputValues =
					new Varnode[] {
						opValues[0],
						new Varnode(addrFactory.getConstantAddress(newOffset &
							VALUE_MASK[op.getSize()]), op.getSize())	// new constant
					};
				return new VarnodeOperation(pcodeOp, simplifiedInputValues);
			}
			else if (opValues[0] instanceof VarnodeOperation) {
				Varnode newOpValue0 =
					pushDownIntAddOffset((VarnodeOperation) opValues[0], offset, addrFactory,
						monitor);
				if (newOpValue0 != null) {
					Varnode[] simplifiedInputValues = new Varnode[] { newOpValue0, opValues[1] };
					return new VarnodeOperation(pcodeOp, simplifiedInputValues);
				}
			}
		}
		return null;
	}

	public Set<SequenceNumber> getReturnAddresses() {
		return endStateMap.keySet();
	}

	public Set<Varnode> getReturnValues(Varnode varnode) {
		HashSet<Varnode> valueSet = new HashSet<Varnode>();
		for (List<ContextState> endStateList : endStateMap.values()) {
			for (ContextState state : endStateList) {
				Varnode val = state.get(varnode);
				if (val != null) {
					valueSet.add(val);
				}
			}
		}
		return valueSet;
	}

	public static long getUnsignedOffset(Varnode v, int size) {
		if (size == 0 || size >= 8) {
			return v.getOffset();
		}
		return VALUE_MASK[size] & v.getOffset();
	}

	public static long getSignedOffset(Varnode v) {
		int size = v.getSize();
		if (size == 0 || size >= 8) {
			return v.getOffset();
		}
		long offset = v.getOffset();
		if (offset > 0 && (offset & SIGN_BIT[size]) != 0) {
			offset |= ~VALUE_MASK[size];
		}
		return offset;
	}

}
