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
package ghidra.program.util;

import java.math.BigInteger;
import java.util.*;

import org.apache.commons.collections4.map.LRUMap;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CallDepthChangeInfo;
import ghidra.pcode.opbehavior.*;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.BigEndianDataConverter;
import ghidra.util.Msg;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

public class SymbolicPropogator {
	private static int LRU_SIZE = 4096;
	// QUESTIONS
	// 1. How are "register-relative" varnodes distinguished based upon target space ?  Not sure how we handle wrapping/truncation concerns.
	//   1) The offset is the only thing that could be used as a reference.

	private static final int _POINTER_MIN_BOUNDS = 0x100;

	// mask for sub-piece extraction
	private static long[] maskSize = { 0xffL, 0xffL, 0xffffL, 0xffffffL, 0xffffffffL, 0xffffffffffL,
		0xffffffffffffL, 0xffffffffffffffL, 0xffffffffffffffffL };

	protected List<AddressSpace> memorySpaces;        // list of real memory/overlay spaces
	private boolean defaultSpacesAreTheSame = false;  // true if the data space and default space the same space

	protected ContextEvaluator evaluator = null;
	protected Program program;
	protected ProgramContext programContext;
	protected ProgramContext spaceContext;
	protected ProgramContext savedProgramContext;
	protected ProgramContext savedSpaceContext;
	protected boolean canceled = false;
	protected boolean readExecutableAddress;
	protected VarnodeContext context;

	protected AddressSet body;             // body of processed instructions
	protected boolean hitCodeFlow = false; // no branching so far

	protected boolean debug = false;

	private final static NotFoundException valueTooBigException =
		new NotFoundException("Value too big to fit in Scalar");

	private final static NotFoundException divideByZeroException =
		new NotFoundException("Divide by zero");

	private long pointerMask;
	private int pointerSize;
	private DataType pointerSizedDT = null;

	protected static final int MAX_EXACT_INSTRUCTIONS = 100;

	// Cache flows from instructions
	Map<Address, Address[]> instructionFlowsCache = new LRUMap<>(LRU_SIZE);

	// Cache PcodeOps so that we won't have to grab them again if we re-visit the node.
	Map<Address, PcodeOp[]> pcodeCache = new LRUMap<>(LRU_SIZE);

	// Cache Instructions looked up by At
	Map<Address, Instruction> instructionAtCache = new LRUMap<>(LRU_SIZE);

	// Cache instructions looked up by containing
	Map<Address, Instruction> instructionContainingCache = new LRUMap<>(LRU_SIZE);

	// cache for pcode callother injection payloads
	HashMap<Long, InjectPayload> injectPayloadCache = new HashMap<Long, InjectPayload>();

	public SymbolicPropogator(Program program) {
		this.program = program;

		Language language = program.getLanguage();

		programContext = new ProgramContextImpl(language);
		spaceContext = new ProgramContextImpl(language);

		setPointerMask(program);

		context = new VarnodeContext(program, programContext, spaceContext);
		context.setDebug(debug);
	}

	public void setDebug(boolean debug) {
		this.debug = debug;
		context.setDebug(debug);
	}

	/**
	 * set up a pointer mask to be used when creating pointers into this memory
	 * 
	 */
	private void setPointerMask(Program program) {
		int ptrSize = program.getDefaultPointerSize();
		if (ptrSize > 8) {
			ptrSize = 8;
		}
		pointerSize = ptrSize;
		pointerMask = maskSize[ptrSize];
		pointerSizedDT = IntegerDataType.getUnsignedDataType(pointerSize, null);
	}

	/**
	 * Process a subroutine using the processor function.
	 * The process function can control what flows are followed and when to stop.
	 * 
	 * @param startAddr start address
	 * @param restrictSet the address set to restrict the constant flow to
	 * @param eval the context evaluator to use
	 * @param saveContext true if the context should be saved
	 * @param monitor the task monitor
	 * @return the address set of instructions that were followed
	 * @throws CancelledException if the task is cancelled
	 */
	public AddressSet flowConstants(Address startAddr, AddressSetView restrictSet,
			ContextEvaluator eval, boolean saveContext, TaskMonitor monitor)
			throws CancelledException {

		this.evaluator = eval;

		AddressSpace defaultDataSpace = program.getLanguage().getDefaultDataSpace();
		AddressSpace defaultSpace = program.getLanguage().getDefaultSpace();
		defaultSpacesAreTheSame = defaultSpace.equals(defaultDataSpace);

		AddressSpace defaultAddrSpace = program.getAddressFactory().getDefaultAddressSpace();

		// Only make reference if other reference or symbol exists
		memorySpaces = new ArrayList<>();
		for (AddressSpace space : program.getAddressFactory().getAddressSpaces()) {
			if (!space.isLoadedMemorySpace()) {
				continue;
			}
			if (space == defaultAddrSpace) {
				memorySpaces.add(0, space); // default space is always at index 0
			}
			else {
				memorySpaces.add(space);
			}
		}

		// if assuming, make a copy of programContext
		savedProgramContext = programContext;
		savedSpaceContext = spaceContext;
		if (!saveContext) {
			context = saveOffCurrentContext(startAddr);
		}

		// copy any current registers with values into the context
		Register[] regWithVals = program.getProgramContext().getRegistersWithValues();
		for (Register regWithVal : regWithVals) {
			RegisterValue regVal =
				program.getProgramContext().getRegisterValue(regWithVal, startAddr);
			if (regVal == null) {
				continue;
			}
			if (!regVal.hasValue()) {
				continue;
			}
			context.setFutureRegisterValue(startAddr, regVal);
			// put it in memory too, if memory mapped
			if (regVal.getRegister().getAddress().isMemoryAddress()) {
				Register reg = regVal.getRegister();
				context.putValue(context.getRegisterVarnode(reg), context.createConstantVarnode(
					regVal.getUnsignedValue().longValue(), reg.getMinimumByteSize()), false);
			}
		}

		AddressSet bodyDone = null;
		try {
			bodyDone = flowConstants(startAddr, restrictSet, eval, context, monitor);
		}
		finally {
			programContext = savedProgramContext;
			spaceContext = savedSpaceContext;
		}

		readExecutableAddress = context.readExecutableCode();

		return bodyDone;
	}

	/**
	 * Save off the current context and set the current context to a copy
	 * This is done so that the values in the context are not changed, but can be used for computation.
	 * 
	 * @param startAddr
	 * @return
	 */
	protected VarnodeContext saveOffCurrentContext(Address startAddr) {
		Language language = program.getLanguage();
		ProgramContext newValueContext = new ProgramContextImpl(language);
		ProgramContext newSpaceContext = new ProgramContextImpl(language);
		VarnodeContext newContext = new VarnodeContext(program, newValueContext, newSpaceContext);
		newContext.setDebug(debug);
		int constantSpaceID = program.getAddressFactory().getConstantSpace().getSpaceID();
		// copy any current registers with values into the context
		Register[] regWithVals = programContext.getRegistersWithValues();
		for (Register regWithVal : regWithVals) {
			RegisterValue regVal;
			regVal = programContext.getRegisterValue(regWithVal, startAddr);

			RegisterValue spRegVal;
			spRegVal = spaceContext.getRegisterValue(regWithVal, startAddr);

			// for now only copy constants into start of current flow,
			//   maybe should do any value...
			// TODO: need a better way to figure this out!
			if (regVal != null && (spRegVal == null || (spRegVal.getUnsignedValue() != null &&
				spRegVal.getUnsignedValue().longValue() == constantSpaceID))) {
				newContext.setFutureRegisterValue(startAddr, regVal);
			}
		}
		programContext = newValueContext;
		spaceContext = newSpaceContext;

		return newContext;
	}

	/**
	 * <code>Value</code> corresponds to a constant value or register relative value.
	 * @see SymbolicPropogator#getRegisterValue(Address, Register)
	 */
	public class Value {
		final Register relativeRegister;
		final long value;

		Value(Register relativeRegister, long value) {
			this.relativeRegister = relativeRegister;
			this.value = value;
		}

		Value(long value) {
			this.relativeRegister = null;
			this.value = value;
		}

		/**
		 * @return constant value.  This value is register-relative
		 * if isRegisterRelativeValue() returns true.
		 */
		public long getValue() {
			return value;
		}

		/**
		 * @return true if value is relative to a particular input register.
		 * @see #getRelativeRegister()
		 */
		public boolean isRegisterRelativeValue() {
			return relativeRegister != null;
		}

		/**
		 * @return relative-register or null if this Value is a simple constant.
		 */
		public Register getRelativeRegister() {
			return relativeRegister;
		}
	}

	/**
	 * Get constant or register relative value assigned to the 
	 * specified register at the specified address
	 * @param toAddr address
	 * @param reg register
	 * @return register value
	 */
	public Value getRegisterValue(Address toAddr, Register reg) {
		//
		// TODO: WARNING: NO_ADDRESS Might not be correct here,
		//    will only get a value if it has been stored, or is in the current flowing context!
		//    Will not be gotten from the FUTURE FLOWING context
		//
		Varnode val = context.getRegisterVarnodeValue(reg, Address.NO_ADDRESS, toAddr, true);
		if (val == null) {
			return null;
		}
		if (context.isConstant(val)) {
			return new Value(val.getOffset());
		}
		AddressSpace space = val.getAddress().getAddressSpace();
		if (space.getName().startsWith("track_")) {
			return new Value(val.getOffset());
		}
		Register relativeReg = program.getRegister(space.getName());
		if (relativeReg != null) {
			return new Value(relativeReg, val.getOffset());
		}
		return null;
	}

	/**
	 * Do not depend on this method!  For display debugging purposes only.
	 * This will change.
	 * 
	 * @param addr
	 * @param reg
	 * @return
	 */
	public String getRegisterValueRepresentation(Address addr, Register reg) {
		//
		// TODO: WARNING: NO_ADDRESS Might not be correct here,
		//    will only get a value if it has been stored, or is in the current flowing context!
		//    Will not be gotten from the FUTURE FLOWING context
		//
		Varnode val = context.getRegisterVarnodeValue(reg, Address.NO_ADDRESS, addr, true);
		if (val == null) {
			return "-";
		}
		if (val.isConstant()) {
			return context.getRegisterValue(reg, Address.NO_ADDRESS, addr).toString();
		}
		AddressSpace space = val.getAddress().getAddressSpace();
		if (space.getName().startsWith("track_")) {
			return reg + "+" + BigInteger.valueOf(val.getOffset()).toString(16);
		}

		if (context.isSymbol(val)) {
			return val.getAddress().getAddressSpace().getName() + " + " + val.getOffset();
		}

		return "-";
	}

	public void setRegister(Address addr, Register stackReg) {
		context.flowStart(Address.NO_ADDRESS, addr);
		int spaceID = context.getAddressSpace(stackReg.getName());
		Varnode vnode = context.createVarnode(0, spaceID, stackReg.getBitLength() / 8);
		context.putValue(context.getRegisterVarnode(stackReg), vnode, false);
		context.propogateResults(false);
		context.flowEnd(addr);
	}

	protected class SavedFlowState {
		Address source;
		Address destination;
		boolean continueAfterHittingFlow;

		public SavedFlowState(VarnodeContext vContext, Address source, Address destination,
				boolean continueAfterHittingFlow) {
			super();
			this.source = source;
			this.destination = destination;
			this.continueAfterHittingFlow = continueAfterHittingFlow;
			vContext.pushMemState();
		}

		public Address getSource() {
			return source;
		}

		public Address getDestination() {
			return destination;
		}

		public boolean isContinueAfterHittingFlow() {
			return continueAfterHittingFlow;
		}

		public void restoreState(VarnodeContext vContext) {
			vContext.popMemState();
		}
	}

	// Used to stop runs of the same exact instruction
	protected int lastFullHashCode = 0;  // full byte hash code
	protected int lastInstrCode = -1;    // last instruction prototype hashcode
	protected int sameInstrCount = 0;    // # of the same instructions

	private boolean checkForParamRefs = true;  // true if params to functions should be checked for references
	private boolean checkForParamPointerRefs = true;  // true if param must be a marked pointer data type
	private boolean checkForReturnRefs = true; // true if return values from functions should be checked for references
	private boolean checkForStoredRefs = true; // true if stored values should be checked for references

	public AddressSet flowConstants(Address startAddr, AddressSetView restrictSet,
			ContextEvaluator eval, VarnodeContext vContext, TaskMonitor monitor)
			throws CancelledException {
		return flowConstants(Address.NO_ADDRESS, startAddr, restrictSet, eval, vContext, monitor);
	}

	public AddressSet flowConstants(Address fromAddr, Address startAddr, AddressSetView restrictSet,
			ContextEvaluator eval, VarnodeContext vContext, TaskMonitor monitor)
			throws CancelledException {
		body = new AddressSet();
		AddressSet conflicts = new AddressSet();

		// prime the context stack with the entry point address
		Stack<SavedFlowState> contextStack = new Stack<>();
		contextStack.push(new SavedFlowState(vContext, fromAddr, startAddr, true));
		canceled = false;

		// only stop flowing on unknown bad calls when the stack depth could be unknown
		boolean callCouldCauseBadStackDepth = program.getCompilerSpec()
				.getDefaultCallingConvention()
				.getExtrapop() == PrototypeModel.UNKNOWN_EXTRAPOP;

		while (!contextStack.isEmpty()) {
			monitor.checkCancelled();
			if (canceled) {
				body.add(conflicts); // put the conflict/redone addresses back in
				return body;
			}

			// if we run into a flow that has already been done, flow until
			//   hit our flow again, or hit a branching instruction
			boolean hitOtherFlow = false;

			SavedFlowState nextFlow = contextStack.pop();
			Address nextAddr = nextFlow.getDestination();
			Address flowFromAddr = nextFlow.getSource();
			boolean continueAfterHittingFlow = nextFlow.isContinueAfterHittingFlow();
			nextFlow.restoreState(vContext);

			// already done it!
			if (body.contains(nextAddr)) {
				// allow it to keep flowing until the next branch/call/ret flow!
				hitOtherFlow = true;
				if (!continueAfterHittingFlow) {
					continue;
				}
			}

			// special flow start, retrieves the flow from/to saved state if there is one, and applies it
			//    As if a mergeFuture flow had been done.
			vContext.flowStart(flowFromAddr, nextAddr);

			lastFullHashCode = 0;
			lastInstrCode = -1;
			sameInstrCount = 0;
			Address maxAddr = null;
			while (nextAddr != null) {

				monitor.checkCancelled();

				// already done it!
				if (body.contains(nextAddr)) {
					// allow it to keep flowing until the next branch/call/ret flow!
					hitOtherFlow = true;
					if (!continueAfterHittingFlow) {
						break;
					}
				}

				if (restrictSet != null && !restrictSet.contains(nextAddr)) {
					break;
				}

				Instruction instr = getInstructionAt(nextAddr);
				if (instr == null) {
					break;
				}
				FlowType originalFlowType = instr.getFlowType();

				// check that we aren't in a string of the same instruction
				if (checkSameInstructionRun(instr)) {
					break;
				}

				Address minInstrAddress = instr.getMinAddress();
				maxAddr = instr.getMaxAddress();

				// if this instruction has a delay slot, adjust maxAddr accordingly
				//
				if (instr.getPrototype().hasDelaySlots()) {
					maxAddr = minInstrAddress.add(instr.getDefaultFallThroughOffset() - 1);
				}

				vContext.setCurrentInstruction(instr);

				vContext.flowToAddress(flowFromAddr, maxAddr);

				if (evaluator != null) {
					if (evaluator.evaluateContextBefore(vContext, instr)) {
						body.add(conflicts); // put the conflict/redone addresses back in
						return body;
					}
				}

				//
				// apply the pcode effects
				//
				Address retAddr = applyPcode(vContext, instr, monitor);

				// add this instruction to processed body set
				body.addRange(minInstrAddress, maxAddr);

				/* Allow evaluateContext routine to change override the flowtype of an instruction.
				 * Jumps Changed to calls will now continue processing.
				 * There is a danger with this, since the calling convention might not get applied correctly.
				 * TODO: The side-effects are fixed if this occurs, except for things like callfixup.
				 */
				if (evaluator != null) {
					if (evaluator.evaluateContext(vContext, instr)) {
						body.add(conflicts); // put the conflict/redone addresses back in
						return body;
					}
				}

				// if the instruction changed it's type to a call, need to handle the call side effects
				FlowType instrFlow = instr.getFlowType();
				if (!originalFlowType.equals(instrFlow) && instrFlow.isCall()) {
					Address targets[] = getInstructionFlows(instr);
					for (Address target : targets) {
						handleFunctionSideEffects(instr, target, monitor);
					}
				}

				Address inlineCall = null;

				boolean simpleFlow = isSimpleFallThrough(instrFlow);
				// once we encounter any flow, must set the hitCodeFlow flag
				//   This should be set after the current instruction has been processed.
				hitCodeFlow |= !simpleFlow;

				// follow flow, except for call flow
				boolean doFallThruLast = false;
				if (!simpleFlow) {
					Address flows[] = getInstructionFlows(instr);
					if (flows != null && flows.length > 0) {
						// if already hit another flow, don't continue past any type of branching instruction
						if (hitOtherFlow) {
							nextAddr = null;
							break;
						}
						if (!instrFlow.isCall()) {
							for (Address flow : flows) {
								contextStack.push(new SavedFlowState(vContext, minInstrAddress,
									flow, continueAfterHittingFlow));
							}
						}
						else if (flows.length > 1) {
							// could have attached flows from a callfixup.
							Reference[] flowRefs = instr.getReferencesFrom();
							for (Reference flowRef : flowRefs) {
								RefType referenceType = flowRef.getReferenceType();
								if (referenceType.isComputed() && referenceType.isJump()) {
									contextStack.push(new SavedFlowState(vContext, minInstrAddress,
										flowRef.getToAddress(), continueAfterHittingFlow));
								}
							}
						}
						else {
							inlineCall = flows[0];
						}
					}
					else if (instrFlow.isComputed() && instrFlow.isCall()) {
						// save this fallthru for later, since we might not know the side-effects of the call.
						doFallThruLast = true;
					}
				}

				if (inlineCall != null) {
					Function func = program.getFunctionManager().getFunctionAt(inlineCall);
					if (func != null && func.isInline()) {
						vContext.mergeToFutureFlowState(maxAddr, inlineCall);
						vContext.flowEnd(maxAddr);
						flowConstants(maxAddr, inlineCall, func.getBody(), eval, vContext, monitor);
						vContext.mergeToFutureFlowState(minInstrAddress, maxAddr);

						//
						// TODO: WARNING, might not start the flow correctly if there is no future flow here.
						//       FLOW end will probably work correctly, but....
						//
						vContext.flowStart(minInstrAddress, maxAddr);
					}
				}

				// go to the fall thru address, unless this instruction had flow
				// then add it's flow to the end of the list and process other flows
				Address fallThru = instr.getFallThrough();
				nextAddr = null;
				if (retAddr != null) {
					contextStack.push(new SavedFlowState(vContext, minInstrAddress, retAddr,
						continueAfterHittingFlow));
					fallThru = null;
				}

				if (fallThru != null) {
					if (doFallThruLast) {
						vContext.mergeToFutureFlowState(minInstrAddress, fallThru);

						// put it lowest on the stack to do later!
						contextStack.push(new SavedFlowState(vContext, minInstrAddress, fallThru,
							!callCouldCauseBadStackDepth));
					}
					else if (fallThru.compareTo(maxAddr) < 0) {
						// this isn't a normal fallthru, must break it up
						//   don't continue flowing if something else is hit, this is an odd case
						vContext.mergeToFutureFlowState(minInstrAddress, fallThru);

						contextStack.push(
							new SavedFlowState(vContext, minInstrAddress, fallThru, false));
					}
					else {
						// no need to store future flow state, will continue on the fall-thru flow
						nextAddr = fallThru;
						fallThru = null;
					}
					// Used to break if there were any references to a place.  This will miss some references.
					// Just follow fallthru for now.  Later we can follow if the context is different.
					// else if (!program.getReferenceManager().hasReferencesTo(fallThru)) {
					//else {
					//	nextAddr = fallThru;
					//	fallThru = null;
					//}
					// else {
					//	vContext.mergeToFutureFlowState(instr.getMinAddress(), fallThru);  // need to push flow for later.
					//	contextStack.push(new SavedFlowState(instr.getMinAddress(), fallThru,
					//		continueAfterHittingFlow));
					//}
				}
			}
			vContext.flowEnd(maxAddr);
		}

		body.add(conflicts); // put the conflict/redone addresses back in
		return body;
	}

	private boolean isSimpleFallThrough(FlowType instrFlow) {
		return !instrFlow.isCall() && !instrFlow.isJump() && !instrFlow.isTerminal() &&
			instrFlow.hasFallthrough();
	}

	/**
	 * Check that we haven't hit a run of the same exact instruction.
	 *    Uses hashcodes in an attempt to be as fast as possible.
	 * @param instr new instruction to check
	 * @return true if we have hit the max number of exact same instructions.
	 */
	private boolean checkSameInstructionRun(Instruction instr) {
		if (lastInstrCode == instr.getPrototype().hashCode()) {
			// allow same prototype once, before starting to get bytes and do careful check
			if (lastFullHashCode == 0) {
				lastFullHashCode = -1;
			}
			else {
				int instrByteHashCode = -1;
				try {
					instrByteHashCode = Arrays.hashCode(instr.getBytes());
				}
				catch (MemoryAccessException e) {
					// this should NEVER happen, should always be able to get the bytes...
					instrByteHashCode = instr.toString().hashCode();
				}
				if (lastFullHashCode == -1) {
					lastFullHashCode = instrByteHashCode;
				}
				if (lastFullHashCode == instrByteHashCode) {
					sameInstrCount++;
					if (sameInstrCount > MAX_EXACT_INSTRUCTIONS) {
						return true;
					}
				}
				else {
					// isn't exactly the same
					lastFullHashCode = 0;
					sameInstrCount = 0;
				}
			}
		}
		else {
			// isn't exactly the same
			sameInstrCount = 0;
			lastFullHashCode = 0;
		}
		lastInstrCode = instr.getPrototype().hashCode();
		return false;
	}

	private PcodeOp[] getInstructionPcode(Instruction instruction) {
		PcodeOp ops[] = pcodeCache.get(instruction.getMinAddress());
		if (ops == null) {
			ops = instruction.getPcode(true);
			pcodeCache.put(instruction.getMinAddress(), ops);
		}
		return ops;
	}

	private Instruction getInstructionAt(Address addr) {
		Instruction instr = instructionAtCache.get(addr);
		if (instr != null) {
			return instr;
		}
		if (instructionAtCache.containsKey(addr)) {
			return null;
		}
		instr = program.getListing().getInstructionAt(addr);
		instructionAtCache.put(addr, instr);
		if (instr != null) {
			instructionContainingCache.put(instr.getMaxAddress(), instr);
		}
		return instr;
	}

	private Instruction getInstructionContaining(Address addr) {
		// try at cache first
		Instruction instr = getInstructionAt(addr);
		if (instr != null) {
			return instr;
		}

		// then try containing
		instr = instructionContainingCache.get(addr);
		if (instr != null) {
			return instr;
		}
		if (instructionContainingCache.containsKey(addr)) {
			return null;
		}
		instr = program.getListing().getInstructionContaining(addr);
		instructionContainingCache.put(addr, instr);
		return instr;
	}

	private Address[] getInstructionFlows(Instruction instruction) {
		Address addr = instruction.getMinAddress();

		Address[] flows = instructionFlowsCache.get(addr);
		if (flows != null) {
			return flows;
		}
		flows = instruction.getFlows();
		instructionFlowsCache.put(addr, flows);
		return flows;
	}

	private Address applyPcode(VarnodeContext vContext, Instruction instruction,
			TaskMonitor monitor) {
		Address nextAddr = null;

		if (instruction == null) {
			return nextAddr;
		}

		// might have run into this pcode before, cache it, in case we run into it again.
		PcodeOp[] ops = getInstructionPcode(instruction);

		if (ops.length <= 0) {
			return nextAddr;
		}

		Address minInstrAddress = instruction.getMinAddress();
		if (debug)
		{
			Msg.info(this, minInstrAddress + "   " + instruction);
		}

		// callfixup injection targets that have already been used
		HashSet<Address> previousInjectionTarget = new HashSet<>();

		int mustClearAllUntil_PcodeIndex = -1;
		// flag won't get set until there is something to clear
		boolean mustClearAll = false;
		// if inject pcode, don't want to do any store pcode ops for the injected code
		boolean injected = false;

		int ptype = 0;
		for (int pcodeIndex = 0; pcodeIndex < ops.length; pcodeIndex++) {

			mustClearAll = pcodeIndex < mustClearAllUntil_PcodeIndex;

			PcodeOp pcodeOp = ops[pcodeIndex];
			ptype = pcodeOp.getOpcode();
			Varnode out = pcodeOp.getOutput();
			Varnode[] in = pcodeOp.getInputs();

			Varnode val1, val2, val3, result;
			long lval1, lval2;
			long lresult;
			boolean suspectOffset = false;
			Varnode vt;
			if (debug) {
				Msg.info(this, "   " + pcodeOp);
			}

			try {
				switch (ptype) {
					case PcodeOp.COPY:
						if (in[0].isAddress() &&
							!in[0].getAddress().getAddressSpace().hasMappedRegisters()) {
							makeReference(vContext, instruction,  Reference.MNEMONIC, in[0],
								null, RefType.READ, ptype, true, monitor);
						}
						vContext.copy(out, in[0], mustClearAll, evaluator);
						break;

					case PcodeOp.LOAD:
						val1 = vContext.getValue(in[0], evaluator);
						val2 = vContext.getValue(in[1], evaluator);

						suspectOffset = vContext.isSuspectConstant(val2);
						
						vt = vContext.getVarnode(in[0], val2, out.getSize(), evaluator);
						
						// TODO: may need to use DATA refType in some cases
						addLoadStoreReference(vContext, instruction, ptype, vt, in[0], in[1],
							RefType.READ, suspectOffset==false, monitor);

						// If vt is a bad varnode (bad space, no memory, no value in varnode) you won't get a value
						Varnode memVal = vContext.getValue(vt, evaluator);
						vContext.putValue(out, memVal, mustClearAll);
						
						break;

					case PcodeOp.STORE:

						Varnode offs = null;
						try {
							offs = vContext.getValue(in[1], true, evaluator);
							suspectOffset = vContext.isSuspectConstant(offs);
							out = getStoredLocation(vContext, in[0], offs, in[2]);
						} catch (NotFoundException e) {
							// if can't get the value of the relative store location
							//   this isn't an exception, the output will be null/unknown
						}
						
						// TODO: may need to use DATA refType in some cases
						addLoadStoreReference(vContext, instruction, ptype, out, in[0], in[1],
							RefType.WRITE, suspectOffset==false, monitor);

						val3 = vContext.getValue(in[2], null);

						if (!injected) {
							addStoredReferences(vContext, instruction, out, val3, monitor);
						}
						vContext.putValue(out, val3, mustClearAll);
						break;

					case PcodeOp.BRANCHIND:
						try {
							val1 = vContext.getValue(in[0], evaluator);
							suspectOffset = vContext.isSuspectConstant(val1);
							
							vt = getConstantOrExternal(vContext, minInstrAddress, val1);
							makeReference(vContext, instruction, -1, vt, null,
								instruction.getFlowType(), ptype, !suspectOffset, monitor);
						}
						catch (NotFoundException e) {
							// constant not found, ignore
						}
						// even though we don't know the destination, propogate the flow to attached destinations
						vContext.propogateResults(false);
						Reference[] flowRefs = instruction.getReferencesFrom();
						for (Reference flowRef : flowRefs) {
							RefType referenceType = flowRef.getReferenceType();
							if (referenceType.isComputed() && referenceType.isJump()) {
								vContext.mergeToFutureFlowState(flowRef.getFromAddress(),
									flowRef.getToAddress());
							}
						}

						if (evaluator != null &&
							evaluator.evaluateDestination(vContext, instruction)) {
							canceled = true;
							return null;
						}
						break;

					case PcodeOp.CALLIND:
					case PcodeOp.CALL:
						Address target = null;
						Function func = null;
						val1 = in[0];
						if (ptype == PcodeOp.CALLIND) {
							try {
								val1 = vContext.getValue(val1, evaluator);

								// TODO: Revisit handling of external functions...

								if (vContext.isConstant(val1)) {
									suspectOffset = vContext.isSuspectConstant(val1);
									// indirect target - assume single code space (same as instruction)
									target = instruction.getAddress()
											.getNewTruncatedAddress(val1.getOffset(), true);
								}
								else if (val1.isAddress()) {
									// TODO: could this also occur if a memory location was copied ??
									// unable to resolve indirect value - can we trust stored pointer?
									// if not, we must rely on reference to function.
									target = resolveFunctionReference(val1.getAddress());
								}
								else if (vContext.isExternalSpace(val1.getSpace())) {
									target = val1.getAddress();
								}
								// if the value didn't get changed, then the real value isn't in here, don't make a reference
								if (target != null) {
									Reference[] refs = instruction.getReferencesFrom();
									// make sure we aren't replacing a read ref with a call to the same place
									if (refs.length <= 0 ||
										!refs[0].getToAddress().equals(target)) {
										target = makeReference(vContext, instruction, Reference.MNEMONIC,
											//  Use target in case location has shifted (external...)
											target.getAddressSpace().getSpaceID(),
											target.getAddressableWordOffset(), val1.getSize(),
											null,
											instruction.getFlowType(), ptype, !suspectOffset, false, monitor);
									}
								}

							}
							catch (NotFoundException e) {
								val1 = null;
							}
						}
						else {
							// CALL will always provide address
							target = val1.getAddress();

							// TODO: If address not contained within memory we should 
							//       try to locate corresponding external function
						}

						Program prog = instruction.getProgram();

						if (target != null) {
							if (target.isMemoryAddress()) {
								vContext.propogateResults(false);
								vContext.mergeToFutureFlowState(minInstrAddress, target);
							}
							func = prog.getFunctionManager().getFunctionAt(target);
							if (func == null && ptype == PcodeOp.CALLIND) {
								Reference[] refs = instruction.getReferencesFrom();
								if (refs != null && refs.length > 0) {
									Reference firstRef = refs[0];
									if (firstRef.getReferenceType().isData() ||
										firstRef.getReferenceType().isIndirect()) {
										target = firstRef.getToAddress();
										func = prog.getFunctionManager().getFunctionAt(target);
									}
								}
							}
							// check for pcode replacement - callfixup
							//   don't re-inject to the same site.
							if (!previousInjectionTarget.contains(target)) {
								PcodeOp[] injectionPcode =
									checkForCallFixup(prog, func, instruction);
								if (injectionPcode != null && injectionPcode.length > 0) {
									previousInjectionTarget.add(target);
									ops = injectPcode(ops, pcodeIndex, injectionPcode);
									pcodeIndex = -1;
									injected = true;
									continue;
								}
							}
						}

						handleFunctionSideEffects(instruction, target, monitor);

						// check for pcode replacement - calling convention uponreturn injection
						PcodeOp[] injectionPcode = checkForUponReturnCallMechanismInjection(prog,
							func, target, instruction);
						if (injectionPcode != null && injectionPcode.length > 0) {
							ops = injectPcode(ops, pcodeIndex, injectionPcode);
							pcodeIndex = -1;
							injected = true;
							continue;
						}

						break;

					// for callother, could be an interrupt, need to look at it like a call
					case PcodeOp.CALLOTHER:
						PcodeOp[] callOtherPcode = doCallOtherPcodeInjection(instruction, in, out);

						if (callOtherPcode != null) {
							ops = injectPcode(ops, pcodeIndex, callOtherPcode);
							pcodeIndex = -1;
							injected = true;
						}
						else if (out != null) {
							// clear out settings for the output from call other.
							vContext.putValue(out, vContext.createBadVarnode(), mustClearAll);
						}
						break;

					case PcodeOp.BRANCH:

						if (in[0].isConstant()) {
							// handle internal branch
							int sequenceOffset = (int) in[0].getOffset();
							if (sequenceOffset < 0) { // avoid internal looping
								pcodeIndex = ops.length; // break out of the processing
								break;
							}
							pcodeIndex += sequenceOffset - 1;
							ptype = PcodeOp.UNIMPLEMENTED; // just in case we are branching to the next instruction - allow context propagation
							break; // follow internal branch
						}

						if (!in[0].isAddress()) {
							throw new AssertException("Not a valid Address on instruction at " +
								instruction.getAddress());
						}
						vContext.propogateResults(false);
						vContext.mergeToFutureFlowState(minInstrAddress, in[0].getAddress());
						pcodeIndex = ops.length; // break out of the processing
						break;

					case PcodeOp.CBRANCH:
						vt = null;
						boolean internalBranch = in[0].isConstant();
						if (internalBranch) {
							int sequenceOffset = (int) in[0].getOffset();
							if ((pcodeIndex + sequenceOffset) >= ops.length) {
								vContext.propogateResults(false);
								vContext.mergeToFutureFlowState(minInstrAddress,
									instruction.getFallThrough());
							}
						}
						else if (in[0].isAddress()) {
							vt = in[0];
							vContext.propogateResults(false);
							vContext.mergeToFutureFlowState(minInstrAddress, in[0].getAddress());
						}

						Varnode condition = null;
						try {
							condition = vContext.getValue(in[1], null);
						}
						catch (NotFoundException e) {
							Address fallThru = instruction.getFallThrough();
							// if the fallthru and conditional branch are the same must CLEAR
							//   because we don't know which way is right for any value set after this
							if (fallThru != null && vt != null &&
								vt.getOffset() == fallThru.getOffset()) {
								// check that the last pcode isn't a branch, which means FT
								//   came from the conditional branch.
								int op = ops[ops.length - 1].getOpcode();
								if (op == PcodeOp.BRANCH || op == PcodeOp.RETURN ||
									op == PcodeOp.BRANCHIND) {
									ptype = op;  // this really isn't a fallthru, make it the correct flow
									// this will cause the effects after this not to flow to next instr.
								}
								else {
									mustClearAllUntil_PcodeIndex = ops.length;
								}
							}
							else if (internalBranch) {
								// if internal flow joins back together, just skip over effect
								// Warning this is arbitrary choice of one branch over the other....!!!
								// look at pcode up to destination, if all non flow or internal, just skip
								int sequenceOffset = pcodeIndex + (int) in[0].getOffset();
								int i = pcodeIndex + 1;
								for (; i < sequenceOffset; i++) {
									if (isBranch(ops[i])) {
										break;
									}
								}
								if (i == sequenceOffset) {
									// everything that is in the cache from here on should be cleared
									mustClearAllUntil_PcodeIndex = sequenceOffset;
									break;
								}
							}
							throw e;
						}

						lval1 = vContext.getConstant(condition, null);

						if (lval1 != 0) {
							if (internalBranch) {
								// handle internal branch
								int sequenceOffset = (int) in[0].getOffset();
								if (sequenceOffset > 0) {
									pcodeIndex += sequenceOffset - 1;
								}
								else if (!evaluator.followFalseConditionalBranches()) {
									pcodeIndex = ops.length;
									break;
								}
							}
							else if (!evaluator.followFalseConditionalBranches()) {
								// pcode addresses are raw addresses, make sure address is in same instruction space
								nextAddr = minInstrAddress.getAddressSpace()
										.getOverlayAddress(in[0].getAddress());
								pcodeIndex = ops.length; // break out of the processing
							}
						}
						break;

					case PcodeOp.RETURN:

						// if return value is a location, give evaluator a chance to check the value
						try {
							val1 = vContext.getValue(in[0], evaluator);
							if (evaluator != null &&
								evaluator.evaluateReturn(val1, vContext, instruction)) {
								canceled = true;
								return null;
							}
						}
						catch (NotFoundException e) {
							// constant not found, ignore
						}
						// put references on any return value that is a pointer and could be returned

						addReturnReferences(instruction, vContext, monitor);
						break;

					case PcodeOp.INT_ZEXT:
						if (in[0].isAddress()) {
							makeReference(vContext, instruction, Reference.MNEMONIC, in[0],
								null, RefType.READ, ptype, true, monitor);
						}
						val1 = vContext.extendValue(out, in, false, evaluator);
						vContext.putValue(out, val1, mustClearAll);
						break;

					case PcodeOp.INT_SEXT:
						if (in[0].isAddress()) {
							makeReference(vContext, instruction,  Reference.MNEMONIC, in[0],
								null, RefType.READ, ptype, true, monitor);
						}
						val1 = vContext.extendValue(out, in, true, evaluator);
						vContext.putValue(out, val1, mustClearAll);
						break;

					case PcodeOp.INT_ADD:
						try {
							val1 = vContext.getValue(in[0], false, evaluator);
						}
						catch (NotFoundException exc) {
							val1 = vContext.createBadVarnode();
						}
						try {
							val2 = vContext.getValue(in[1], false, evaluator);
						}
						catch (NotFoundException exc) {
							val2 = vContext.createBadVarnode();
						}
						if (val1.equals(val2)) {
							long v = vContext.getConstant(val1, evaluator);
							val1 = val2 = vContext.createConstantVarnode(v, val1.getSize());
						}
						result = vContext.add(val1, val2, evaluator);
						vContext.putValue(out, result, mustClearAll);
						break;

					case PcodeOp.INT_SUB:
						val1 = vContext.getValue(in[0], false, evaluator);
						val2 = vContext.getValue(in[1], false, evaluator);
						result = vContext.subtract(val1, val2, evaluator);
						vContext.putValue(out, result, mustClearAll);
						break;

					case PcodeOp.INT_CARRY:
					case PcodeOp.INT_SCARRY:
					case PcodeOp.INT_SBORROW:
						BinaryOpBehavior binaryBehavior =
							(BinaryOpBehavior) OpBehaviorFactory.getOpBehavior(ptype);
						val1 = vContext.getValue(in[0], false, evaluator);
						val2 = vContext.getValue(in[1], false, evaluator);
						lresult = binaryBehavior.evaluateBinary(out.getSize(), in[0].getSize(),
							vContext.getConstant(val1, evaluator),
							vContext.getConstant(val2, evaluator));
						result = vContext.createConstantVarnode(lresult, val1.getSize());
						vContext.putValue(out, result, mustClearAll);
						break;

					case PcodeOp.INT_2COMP:
						UnaryOpBehavior unaryBehavior =
							(UnaryOpBehavior) OpBehaviorFactory.getOpBehavior(ptype);
						val1 = vContext.getValue(in[0], false, evaluator);
						lresult = unaryBehavior.evaluateUnary(out.getSize(), in[0].getSize(),
							vContext.getConstant(val1, evaluator));
						result = vContext.createConstantVarnode(lresult, val1.getSize());
						vContext.putValue(out, result, mustClearAll);
						break;

					case PcodeOp.INT_NEGATE:
						val1 = vContext.getValue(in[0], false, evaluator);
						result = vContext.createConstantVarnode(
							~vContext.getConstant(val1, evaluator), val1.getSize());
						vContext.putValue(out, result, mustClearAll);
						break;

					case PcodeOp.INT_XOR:
						if (in[0].isRegister() && in[0].equals(in[1])) {
							result = vContext.createConstantVarnode(0, out.getSize());
						}
						else {
							val1 = vContext.getValue(in[0], false, evaluator);
							val2 = vContext.getValue(in[1], false, evaluator);
							lresult = vContext.getConstant(val1, evaluator) ^
								vContext.getConstant(val2, evaluator);
							result = vContext.createConstantVarnode(lresult, val1.getSize());
						}
						vContext.putValue(out, result, mustClearAll);
						break;

					case PcodeOp.INT_AND:
						val1 = vContext.getValue(in[0], false, evaluator);
						val2 = vContext.getValue(in[1], false, evaluator);
						result = vContext.and(val1, val2, evaluator);
						vContext.putValue(out, result, mustClearAll);
						break;

					case PcodeOp.INT_OR:
						val1 = vContext.getValue(in[0], false, evaluator);
						val2 = vContext.getValue(in[1], false, evaluator);
						result = vContext.or(val1, val2, evaluator);
						vContext.putValue(out, result, mustClearAll);
						break;

					case PcodeOp.INT_LEFT:
						val1 = vContext.getValue(in[0], false, evaluator);
						val2 = vContext.getValue(in[1], false, evaluator);
						result = vContext.left(val1, val2, evaluator);
						vContext.putValue(out, result, mustClearAll);
						break;

					case PcodeOp.INT_RIGHT:
						val1 = vContext.getValue(in[0], false, evaluator);
						val2 = vContext.getValue(in[1], false, evaluator);
						lresult = vContext.getConstant(val1, evaluator) >> vContext
								.getConstant(val2, evaluator);
						result = vContext.createConstantVarnode(lresult, val1.getSize());
						vContext.putValue(out, result, mustClearAll);
						break;

					case PcodeOp.INT_SRIGHT:
						val1 = vContext.getValue(in[0], true, evaluator);
						val2 = vContext.getValue(in[1], false, evaluator);
						lresult = vContext.getConstant(val1, evaluator) >>> vContext
								.getConstant(val2, evaluator);
						result = vContext.createConstantVarnode(lresult, val1.getSize());
						vContext.putValue(out, result, mustClearAll);
						break;

					case PcodeOp.INT_MULT:
						val1 = vContext.getValue(in[0], true, evaluator);
						val2 = vContext.getValue(in[1], true, evaluator);
						lresult = vContext.getConstant(val1, evaluator) *
							vContext.getConstant(val2, evaluator);
						result = vContext.createConstantVarnode(lresult, val1.getSize());
						vContext.putValue(out, result, mustClearAll);
						break;

					case PcodeOp.INT_DIV:
						val1 = vContext.getValue(in[0], false, evaluator);
						val2 = vContext.getValue(in[1], false, evaluator);
						lval1 = vContext.getConstant(val1, evaluator);
						lval2 = vContext.getConstant(val2, evaluator);
						if (lval2 == 0) {
							throw divideByZeroException;
						}
						lresult = lval1 / lval2;
						result = vContext.createConstantVarnode(lresult, val1.getSize());
						vContext.putValue(out, result, mustClearAll);
						break;

					case PcodeOp.INT_SDIV:
						val1 = vContext.getValue(in[0], true, evaluator);
						val2 = vContext.getValue(in[1], true, evaluator);
						lval1 = vContext.getConstant(val1, evaluator);
						lval2 = vContext.getConstant(val2, evaluator);
						if (lval2 == 0) {
							throw divideByZeroException;
						}
						lresult = lval1 / lval2;
						result = vContext.createConstantVarnode(lresult, val1.getSize());
						vContext.putValue(out, result, mustClearAll);
						break;

					case PcodeOp.INT_REM:
						val1 = vContext.getValue(in[0], false, evaluator);
						val2 = vContext.getValue(in[1], false, evaluator);
						lval1 = vContext.getConstant(val1, evaluator);
						lval2 = vContext.getConstant(val2, evaluator);
						if (lval2 == 0) {
							throw divideByZeroException;
						}
						lresult = lval1 % lval2;
						result = vContext.createConstantVarnode(lresult, val1.getSize());
						vContext.putValue(out, result, mustClearAll);
						break;

					case PcodeOp.INT_SREM:
						val1 = vContext.getValue(in[0], true, evaluator);
						val2 = vContext.getValue(in[1], true, evaluator);
						lval1 = vContext.getConstant(val1, evaluator);
						lval2 = vContext.getConstant(val2, evaluator);
						if (lval2 == 0) {
							throw divideByZeroException;
						}
						lresult = lval1 % lval2;
						result = vContext.createConstantVarnode(lresult, val1.getSize());
						vContext.putValue(out, result, mustClearAll);
						break;

					case PcodeOp.SUBPIECE:
						val1 = vContext.getValue(in[0], true, evaluator);
						val2 = vContext.getValue(in[1], true, evaluator);
						long subbyte = 8 * vContext.getConstant(val2, evaluator);

						if (vContext.isSymbol(val1) & subbyte == 0 &&
							out.getSize() == instruction.getAddress().getPointerSize()) {
							// assume the subpiece is just downcasting to be used as a pointer, just ignore, since this is already an offset, and shouldn't matter.
							result = val1;

						}
						else if (out.getSize() > 8) {
							throw valueTooBigException;
						}
						else {
							lresult = (vContext.getConstant(val1, evaluator) >> (subbyte)) &
								maskSize[out.getSize()];
							result = vContext.createConstantVarnode(lresult, out.getSize());
						}
						vContext.putValue(out, result, mustClearAll);
						break;

					case PcodeOp.INT_LESS:
						val1 = vContext.getValue(in[0], false, evaluator);
						val2 = vContext.getValue(in[1], false, evaluator);
						lval1 = vContext.getConstant(val1, evaluator);
						lval2 = vContext.getConstant(val2, evaluator);
						lresult = Long.compareUnsigned(lval1, lval2) < 0 ? 1 : 0;
						result = vContext.createConstantVarnode(lresult, val1.getSize());
						vContext.putValue(out, result, mustClearAll);
						break;

					case PcodeOp.INT_SLESS:
						val1 = vContext.getValue(in[0], true, evaluator);
						val2 = vContext.getValue(in[1], true, evaluator);
						lval1 = vContext.getConstant(val1, evaluator);
						lval2 = vContext.getConstant(val2, evaluator);
						lresult = (vContext.getConstant(val1, evaluator) < vContext
								.getConstant(val2, evaluator)) ? 1 : 0;
						result = vContext.createConstantVarnode(lresult, val1.getSize());
						vContext.putValue(out, result, mustClearAll);
						break;

					case PcodeOp.INT_LESSEQUAL:
						val1 = vContext.getValue(in[0], false, evaluator);
						val2 = vContext.getValue(in[1], false, evaluator);
						lval1 = vContext.getConstant(val1, evaluator);
						lval2 = vContext.getConstant(val2, evaluator);
						lresult = Long.compareUnsigned(lval1, lval2) <= 0 ? 1 : 0;
						result = vContext.createConstantVarnode(lresult, val1.getSize());
						vContext.putValue(out, result, mustClearAll);
						break;

					case PcodeOp.INT_SLESSEQUAL:
						val1 = vContext.getValue(in[0], true, evaluator);
						val2 = vContext.getValue(in[1], true, evaluator);
						lresult = (vContext.getConstant(val1, evaluator) <= vContext
								.getConstant(val2, evaluator)) ? 1 : 0;
						result = vContext.createConstantVarnode(lresult, val1.getSize());
						vContext.putValue(out, result, mustClearAll);
						break;

					case PcodeOp.INT_EQUAL:

						val1 = vContext.getValue(in[0], false, evaluator);
						val2 = vContext.getValue(in[1], false, evaluator);
						lresult = (vContext.getConstant(val1, evaluator) == vContext
								.getConstant(val2, evaluator)) ? 1 : 0;
						result = vContext.createConstantVarnode(lresult, val1.getSize());
						vContext.putValue(out, result, mustClearAll);
						break;

					case PcodeOp.INT_NOTEQUAL:
						val1 = vContext.getValue(in[0], false, evaluator);
						val2 = vContext.getValue(in[1], false, evaluator);
						lresult = (vContext.getConstant(val1, evaluator) != vContext
								.getConstant(val2, evaluator)) ? 1 : 0;
						result = vContext.createConstantVarnode(lresult, val1.getSize());
						vContext.putValue(out, result, mustClearAll);
						break;

					case PcodeOp.BOOL_NEGATE:
						val1 = vContext.getValue(in[0], false, evaluator);
						lresult = (vContext.getConstant(val1, evaluator) == 0 ? 1 : 0);
						result = vContext.createConstantVarnode(lresult, val1.getSize());
						vContext.putValue(out, result, mustClearAll);
						break;

					case PcodeOp.BOOL_XOR:
						val1 = vContext.getValue(in[0], false, evaluator);
						val2 = vContext.getValue(in[1], false, evaluator);
						lresult = vContext.getConstant(val1, evaluator) ^
							vContext.getConstant(val2, evaluator);
						result = vContext.createConstantVarnode(lresult, val1.getSize());
						vContext.putValue(out, result, mustClearAll);
						break;

					case PcodeOp.BOOL_AND:
						val1 = vContext.getValue(in[0], false, evaluator);
						val2 = vContext.getValue(in[1], false, evaluator);
						lresult = vContext.getConstant(val1, evaluator) &
							vContext.getConstant(val2, evaluator);
						result = vContext.createConstantVarnode(lresult, val1.getSize());
						vContext.putValue(out, result, mustClearAll);
						break;

					case PcodeOp.BOOL_OR:
						val1 = vContext.getValue(in[0], false, evaluator);
						val2 = vContext.getValue(in[1], false, evaluator);
						lresult = vContext.getConstant(val1, evaluator) |
							vContext.getConstant(val2, evaluator);
						result = vContext.createConstantVarnode(lresult, val1.getSize());
						vContext.putValue(out, result, mustClearAll);
						break;

					default:
						// clear out any output varnode - set to null
						if (out != null) {
							vContext.putValue(out, null, false);
						}
						break;
				}
			}
			catch (NotFoundException e) {
				// didn't have a value for some piece of the computation
				if (out != null) {
					vContext.putValue(out, vContext.createBadVarnode(), false);
				}
			}
			catch (AddressOutOfBoundsException e) {
				// The computation did something bad for some reason, need to null the out varnode
				if (out != null) {
					vContext.putValue(out, null, false);
				}
			}
		}

		vContext.propogateResults(true);

		Address fallthru = instruction.getFallThrough();
		if (ptype == PcodeOp.BRANCH || ptype == PcodeOp.RETURN || ptype == PcodeOp.BRANCHIND) {
			// if says this is branch, but has a fallthru, then really isn't a fallthru
			//   assume the future flow will have flowed the correct info.
			nextAddr = fallthru;
		}

		return nextAddr;
	}

	private Varnode getConstantOrExternal(VarnodeContext vContext, Address minInstrAddress,
			Varnode val1) throws NotFoundException {
		Varnode vt;
		if (!context.isExternalSpace(val1.getSpace())) {
			long lval = vContext.getConstant(val1, evaluator);
			vt = vContext.getVarnode(minInstrAddress.getAddressSpace().getSpaceID(), lval, 0);
		}
		else {
			vt = val1;
		}
		return vt;
	}
	
	private Varnode getStoredLocation(VarnodeContext vContext, Varnode space, Varnode offset, Varnode size) {
		Varnode out = null;

		if (offset == null) {
			return null;
		}
		
		try {			
			// out is a calculated location for store.  If got to here, need to set out
			//   because it might need to be cleared by a bad value access!
			out = vContext.getVarnode(space, offset, size.getSize(), evaluator);
		}
		catch (NotFoundException e) {
			// if can't get the value of the relative store location
			//   this isn't an exception, the output will be null/unknown
		}

		return out;
	}

	private void handleFunctionSideEffects(Instruction instruction, Address target,
			TaskMonitor monitor) {

		Function targetFunc = null;
		if (target != null) {
			targetFunc = program.getFunctionManager().getFunctionAt(target);
		}
		Address fallThruAddr = instruction.getFallThrough();
		// if the call is right below this routine, ignore the call
		//   otherwise clear out the return and killed by call variables
		if (fallThruAddr == null || target == null ||
			target.getOffset() != fallThruAddr.getOffset()) {

			// need to pass noAddress if don't know the target, in case
			// evaluator wants to look something up about the function
			if (checkForParamRefs && evaluator != null &&
				evaluator.evaluateReference(context, instruction, PcodeOp.UNIMPLEMENTED,
					(target == null ? Address.NO_ADDRESS : target), 0,
					null, RefType.UNCONDITIONAL_CALL)) {
				// put references on any register parameters with values in
				// them.
				addParamReferences(targetFunc, target, instruction, context, monitor);
			}

			// clear out settings for any return variables
			Varnode returnVarnodes[] = context.getReturnVarnode(targetFunc);
			if (returnVarnodes != null) {
				for (Varnode varnode : returnVarnodes) {
					context.putValue(varnode, context.createBadVarnode(), false);
				}
			}
			
			// clear out any killed by call variables
			Varnode killedVarnodes[] = context.getKilledVarnodes(targetFunc);
			if (killedVarnodes != null) {
				for (Varnode varnode : killedVarnodes) {
					context.putValue(varnode, context.createBadVarnode(), false);
				}
			}
		}

		// inlined function, don't worry about it's function effects
		if (targetFunc != null && targetFunc.isInline()) {
			return;
		}

		// Update the stack offset if necessary
		Varnode outStack = context.getStackVarnode();

		if (outStack != null && (targetFunc == null || !targetFunc.isInline())) {
			int purge = getFunctionPurge(program, targetFunc);
			purge = addStackOverride(program, instruction.getMinAddress(), purge);

			if (purge == Function.UNKNOWN_STACK_DEPTH_CHANGE ||
				purge == Function.INVALID_STACK_DEPTH_CHANGE) {
				Varnode curVal = null;
				if (fallThruAddr != null) {

					// find any flowing addresses to this location in hopes
					// of finding a good stack value right after this function from some other flow
					Address[] knownFlowToAddresses = context.getKnownFlowToAddresses(fallThruAddr);

					for (Address knownFlowToAddresse : knownFlowToAddresses) {
						curVal = context.getRegisterVarnodeValue(context.getStackRegister(),
							knownFlowToAddresse, fallThruAddr, false);
						if (curVal != null) {
							break;
						}
					}

				}
				if (curVal != null) {
					context.putValue(outStack, curVal, false);
				}
				else if (instruction.getLength() != 1) {
					context.putValue(outStack, null, false);
				}
			}
			else if (purge != 0) {
				try {
					Varnode purgeVar = context.createConstantVarnode(purge, outStack.getSize());
					Varnode val1 = context.getValue(outStack, true, evaluator);
					Varnode val2 = context.add(val1, purgeVar, evaluator);
					context.putValue(outStack, val2, false);
				}
				catch (NotFoundException e) {
					context.putValue(outStack, context.createBadVarnode(), false);
				}
			}
		}
	}

	private boolean isBranch(PcodeOp pcodeOp) {
		if (pcodeOp.isAssignment()) {
			return false;
		}
		int opcode = pcodeOp.getOpcode();
		if (opcode == PcodeOp.STORE || opcode == PcodeOp.LOAD) {
			return false;
		}
		return true;
	}

	private Address resolveFunctionReference(Address addr) {
		Address extAddr = null;
		for (Reference ref : program.getReferenceManager().getReferencesFrom(addr)) {
			if (ref.isExternalReference()) {
				extAddr = ref.getToAddress();
			}
			else if (ref.isMemoryReference()) {
				if (ref.getReferenceType().isCall()) {
					return ref.getToAddress();
				}
			}
		}
		return extAddr;
	}

	private PcodeOp[] checkForCallFixup(Program prog, Function func, Instruction instr) {
		if (func == null) {
			return null;
		}
		String callFixupName = func.getCallFixup();
		if (callFixupName == null) {
			return null;
		}

		PcodeInjectLibrary snippetLibrary = prog.getCompilerSpec().getPcodeInjectLibrary();
		InjectPayload payload =
			snippetLibrary.getPayload(InjectPayload.CALLFIXUP_TYPE, callFixupName);
		if (payload == null) {
			return null;
		}
		InjectContext con = snippetLibrary.buildInjectContext();
		con.baseAddr = instr.getMinAddress();
		con.nextAddr = con.baseAddr.add(instr.getDefaultFallThroughOffset());
		con.callAddr = func.getEntryPoint();
		con.refAddr = con.callAddr;
		try {
			return payload.getPcode(prog, con);
		}
		catch (Exception e) {
			Msg.warn(this, e.getMessage());
		}
		return null;
	}

	private PcodeOp[] checkForUponReturnCallMechanismInjection(Program prog, Function func,
			Address target, Instruction instr) {
		PrototypeModel callingConvention = null;
		if (func != null) {
			callingConvention = func.getCallingConvention();
		}
		if (callingConvention == null) {
			callingConvention = prog.getCompilerSpec().getDefaultCallingConvention();
		}

		// magic incantation to get the uponreturn injection from the injection library
		String injectionName = callingConvention.getName() + "@@inject_uponreturn";

		PcodeInjectLibrary snippetLibrary = prog.getCompilerSpec().getPcodeInjectLibrary();
		InjectPayload payload =
			snippetLibrary.getPayload(InjectPayload.CALLMECHANISM_TYPE, injectionName);
		if (payload == null) {
			return null;
		}
		InjectContext con = snippetLibrary.buildInjectContext();
		con.baseAddr = instr.getMinAddress();
		con.nextAddr = con.baseAddr.add(instr.getDefaultFallThroughOffset());
		con.callAddr = target;
		con.refAddr = con.callAddr;
		try {
			return payload.getPcode(prog, con);
		}
		catch (Exception e) {
			Msg.warn(this, e.getMessage());
		}
		return null;
	}

	private PcodeOp[] injectPcode(PcodeOp[] currentPcode, int pcodeIndex, PcodeOp[] replacePcode) {
		// if the length of replacePcode is 0, then the call will get replaced correctly.
		// Normally this routine should not be called to replace a null or empty array replacePcode.
		int opsRemaining = currentPcode.length - pcodeIndex - 1;
		if (opsRemaining == 0) {
			// simple case, call is the last pcode-op
			currentPcode = replacePcode;
		}
		else {
			// include any remaining pcode-ops to be processed after call-fixup
			// TODO: should really perform complete call replacement with repair of any internal branching
			PcodeOp[] replacePcodeExpanded = new PcodeOp[replacePcode.length + opsRemaining];
			System.arraycopy(replacePcode, 0, replacePcodeExpanded, 0, replacePcode.length);
			System.arraycopy(currentPcode, pcodeIndex + 1, replacePcodeExpanded,
				replacePcode.length, opsRemaining);
			currentPcode = replacePcodeExpanded;
		}
		return currentPcode;
	}

	/**
	 * Check for pcode replacement for a callother pcode op
	 * 
	 * @param instr instruction whose pcodeop we might replace
	 * @param ins input varnodes to callother pcodeop, ins[0] is callother nameindex
	 * @param out output varnode for pcodeop
	 * @return pcode that should replace callother, null otherwise
	 * 
	 * @throws NotFoundException
	 */
	private PcodeOp[] doCallOtherPcodeInjection(Instruction instr, Varnode ins[], Varnode out)
			throws NotFoundException {
		Program prog = instr.getProgram();

		PcodeInjectLibrary snippetLibrary = prog.getCompilerSpec().getPcodeInjectLibrary();
		InjectPayload payload = findPcodeInjection(prog, snippetLibrary, ins[0].getOffset());
		// no injection defined for this call-other pcodeop
		if (payload == null) {
			return null;
		}

		ArrayList<Varnode> inputs = new ArrayList<Varnode>();
		for (int i = 1; i < ins.length; i++) {
			Varnode vval = context.getValue(ins[i], evaluator);
			if (!context.isConstant(vval)) {
				return null;
			}
			inputs.add(vval);
		}

		InjectContext con = snippetLibrary.buildInjectContext();
		con.baseAddr = instr.getMinAddress();
		con.nextAddr = con.baseAddr.add(instr.getDefaultFallThroughOffset());
		con.callAddr = null;
		con.refAddr = con.callAddr;
		con.inputlist = inputs;
		con.output = new ArrayList<Varnode>();
		con.output.add(out);
		try {
			return payload.getPcode(prog, con);
		}
		catch (Exception e) {
			Msg.warn(this, e.getMessage());
		}
		return null;
	}

	private InjectPayload findPcodeInjection(Program prog, PcodeInjectLibrary snippetLibrary,
			long callOtherIndex) {
		InjectPayload payload = injectPayloadCache.get(callOtherIndex);

		// has a payload value for the pcode callother index
		if (payload != null) {
			return payload;
		}

		// value null, if contains the key, then already looked up
		if (injectPayloadCache.containsKey(callOtherIndex)) {
			return null;
		}

		String opName = prog.getLanguage().getUserDefinedOpName((int) callOtherIndex);

		// segment is special named injection
		if ("segment".equals(opName)) {
			payload =
				snippetLibrary.getPayload(InjectPayload.EXECUTABLEPCODE_TYPE, "segment_pcode");
		}
		else {
			payload = snippetLibrary.getPayload(InjectPayload.CALLOTHERFIXUP_TYPE, opName);
		}

		// save payload in cache for next lookup
		injectPayloadCache.put(callOtherIndex, payload);
		return payload;
	}

	/**
	 * Get/Compute the Purge size from the stack for the function starting at
	 * entryPoint.
	 * 
	 * @param prog -
	 *            program containing the function to analyze
	 * @param function -
	 * 
	 * @return size in bytes that is removed from the stack after the function
	 *         is called.
	 */
	private int getFunctionPurge(Program prog, Function function) {

		if (function == null) {
			return getDefaultStackDepthChange(prog, null, Function.UNKNOWN_STACK_DEPTH_CHANGE);
		}

		PrototypeModel conv = function.getCallingConvention();

		if (function.isStackPurgeSizeValid()) {
			int depth = function.getStackPurgeSize();
			return getDefaultStackDepthChange(prog, conv, depth);
		}

		return getDefaultStackDepthChange(prog, conv, Function.UNKNOWN_STACK_DEPTH_CHANGE);
	}

	/**
	 * Get the default/assumed stack depth change for this language
	 * 
	 * @param model calling convention to use
	 * @param depth stack depth to return if the default is unknown for the language
	 * @return default assumed stack depth
	 */
	private int getDefaultStackDepthChange(Program prog, PrototypeModel model, int depth) {
		if (model == null) {
			model = prog.getCompilerSpec().getDefaultCallingConvention();
		}
		if (model == null) {
			return Function.UNKNOWN_STACK_DEPTH_CHANGE;
		}

		int callStackMod = model.getExtrapop();
		int callStackShift = model.getStackshift();
		if (callStackMod != PrototypeModel.UNKNOWN_EXTRAPOP) {
			// TODO: If the purge is set, the calling convention could be wrong
			//       If the purge can from a RET <X> if will be correct so should use it!
			//       Need to make sure that is happening in the program before accepting
			return callStackShift;
		}
		if (depth == Function.UNKNOWN_STACK_DEPTH_CHANGE ||
			depth == Function.INVALID_STACK_DEPTH_CHANGE) {
			return Function.UNKNOWN_STACK_DEPTH_CHANGE;
		}
		return callStackShift + depth;
	}

	/**
	 * Modify the function purge by any stack depth override
	 * 
	 * @param prog program
	 * @param addr addr of instruction that could have an override of the stack depth
	 * @param purge current purge depth.
	 * @return new purge, which includes the extrapop value
	 */
	private int addStackOverride(Program prog, Address addr, int purge) {
		Integer stackDepthChange = CallDepthChangeInfo.getStackDepthChange(prog, addr);
		if (stackDepthChange == null) {
			return purge;
		}

		int extrapop = CallDepthChangeInfo.getStackDepthChange(prog, addr);
		if (purge == Function.UNKNOWN_STACK_DEPTH_CHANGE ||
			purge == Function.INVALID_STACK_DEPTH_CHANGE) {
			return extrapop;
		}
		return purge + extrapop;
	}

	private void addParamReferences(Function func, Address callTarget, Instruction instruction,
			VarnodeContext varnodeContext, TaskMonitor monitor) {

		if (!checkForParamRefs) {
			return;
		}

		// don't check for params on external calls
		if (callTarget != null && callTarget.isExternalAddress()) {
			return;
		}

		// find the calling conventions
		// look up any register parameters
		//     get the value of each, as soon as find no value, stop
		//     look back to see when register value was set
		//     add a reference on to the register at that point
		PrototypeModel conv;
		conv = program.getCompilerSpec().getDefaultCallingConvention();

		Parameter[] params = new Parameter[0];
		SourceType signatureSource = SourceType.DEFAULT;
		if (func != null) {
			PrototypeModel funcConv = func.getCallingConvention();
			if (funcConv != null) {
				conv = funcConv;
			}
			params = func.getParameters();
			signatureSource = func.getSignatureSource();
		}
		else if (checkForParamPointerRefs) {
			// no function chan't check for pointer types
			return;
		}

		long callOffset = (callTarget == null ? -1 : callTarget.getOffset());

		// If there are params defined or the params were specified (meaning it could be VOID params)
		boolean signatureAssigned = signatureSource != SourceType.DEFAULT;
		boolean trustSignature = signatureAssigned || params.length > 0;
		if (trustSignature && !func.hasVarArgs()) {
			// Loop through defined parameters for a valid address value
			for (Parameter param : params) {
				Parameter p = param;

				// check if known pointer DT.
				//  construct pointer of the right type, given the constant
				// if not a pointer && flag must be pointer, don't add pointer
				DataType dataType = p.getDataType();

				if (!(dataType instanceof Pointer ||
				      (dataType instanceof TypeDef && ((TypeDef) dataType).isPointer()))) {
					// wasn't a pointer immediately
					if (checkForParamPointerRefs) {
						continue;
					}
					// if undefined, or int/long could still be pointer
					if (!(Undefined.isUndefined(dataType) || dataType instanceof IntegerDataType)) {
						continue;
					}
				}
				// use the varnode to pull out the bytes from the varnode
				//   only use constants, not symbolic?
				//   put the bytes in a membuffer
				//   Hand bytes to data type to decode as if in memory
				//   get pointer out
				createVariableStorageReference(instruction, varnodeContext, monitor, conv,
					p.getVariableStorage(), dataType, callOffset);
			}
		}
		else if (!checkForParamPointerRefs) {
			// loop through potential params, since none defined, to find a potential pointer
			// only check the first seven param locations, if don't have a signature
			for (int pi=0; pi < 8; pi++) {
				// TODO Should cache the arg locations for each convention
				VariableStorage var = conv.getArgLocation(pi, null, pointerSizedDT, program);
				// can't trust stack storage if params aren't known
				if (var.isStackStorage()) {
					continue;
				}
				createVariableStorageReference(instruction, varnodeContext, monitor, conv, var,
						null, callOffset);
			}
		}
	}

	private void addReturnReferences(Instruction instruction, VarnodeContext varnodeContext,
			TaskMonitor monitor) {
		if (!checkForReturnRefs) {
			return;
		}

		Function func =
			program.getFunctionManager().getFunctionContaining(instruction.getMinAddress());

		// get the return location
		// see if it has a pointer value in it
		// if it does, then find the last set location, and put a reference there
		VariableStorage returnLoc = getReturnLocationStorage(func);
		if (returnLoc == null) {
			return;
		}

		createVariableStorageReference(instruction, varnodeContext, monitor, null, returnLoc, null, 0);
	}

	private void addLoadStoreReference(VarnodeContext vContext, Instruction instruction,
			int pcodeType, Varnode refLocation, Varnode targetSpaceID, Varnode assigningVarnode,
			RefType reftype, boolean knownReference, TaskMonitor monitor) {

		// no output or load
		if (refLocation == null) {
			return;
		}

		int opIndex = findOperandWithVarnodeAssignment(instruction, assigningVarnode);

		if (instruction.getFlowType().isCall()) {
			makeReference(vContext, instruction, opIndex, refLocation, null, reftype, pcodeType, knownReference, monitor);
		}
		else {
			int spaceID = refLocation.getSpace();
			if (vContext.isSymbolicSpace(spaceID)) {
				// see if the offset is a large constant offset from the symbolic space
				long offset = refLocation.getOffset();

				if (evaluator != null) {
					if (!vContext.isStackSymbolicSpace(refLocation) && evaluator != null) {
						Address constant = program.getAddressFactory()
								.getAddress((int) targetSpaceID.getOffset(), offset);
						Address newTarget = evaluator.evaluateConstant(vContext, instruction,
							pcodeType, constant, 0, null, reftype);
						// TODO: This is speculative, should not be doing here
						//       need to check if there is a memory/label at the other end, or some other
						//       corroborating evidence very late in analysis
						if (newTarget != null ) {
							makeReference(vContext, instruction, Reference.MNEMONIC,
								newTarget.getAddressSpace().getSpaceID(), newTarget.getOffset(), 0,
								null, reftype.DATA, pcodeType, false, false, monitor);
							return;
						}
					}
				}
			}
			// even if this is symbolic space, give the evaluator a chance to do something with the symbolic value
			makeReference(vContext, instruction, opIndex, refLocation, null, reftype, pcodeType, knownReference, monitor);
		}
	}

	/**
	 * Find the operand that is assigning to the varnode with contains the load or store reference offset
	 * 
	 * @param instruction the instruction with operands
	 * @param assigningVarnode varnode representing the load/store assignment
	 * @return operand index if found or -1 if not
	 */
	private int findOperandWithVarnodeAssignment(Instruction instruction,
			Varnode assigningVarnode) {
		// only check uniques
		if (!assigningVarnode.isUnique()) {
			return -1;
		}
		// This may not always work, if the output of the operand is not immmediately loaded,
		//  and first goes into another unique, or is used in further based constructor pcode
		//  before the load or store pcode op.
		for (int opIndex = 0; opIndex < instruction.getNumOperands(); opIndex++) {
			PcodeOp[] pcode = instruction.getPcode(opIndex);
			for (int j = pcode.length - 1; j >= 0; j--) {
				if (assigningVarnode.equals(pcode[j].getOutput())) {
					return opIndex;
				}
			}
		}
		return -1;
	}

	/**
	 * check if the offset is large enough to possibly be an address
	 *     It shouldn't be smaller than +- MIN_BOUNDS
	 * @param offset assumed relative to another register
	 * @return true if it could be an address
	 */
	private boolean checkPossibleOffsetAddr(long offset) {
		long maxAddrOffset = this.pointerMask;
		if ((offset >= 0 && offset < _POINTER_MIN_BOUNDS) ||
			(Math.abs(maxAddrOffset - offset) < _POINTER_MIN_BOUNDS)) {
			return false;
		}
		return true;
	}

	private void addStoredReferences(VarnodeContext vContext, Instruction instruction,
			Varnode storageLocation, Varnode valueToStore, TaskMonitor monitor) {
		if (!checkForStoredRefs) {
			return;
		}

		// storing into a register isn't a reference
		if (storageLocation != null && storageLocation.isRegister()) {
			return;
		}

		// if val to be stored is known, check it for a constant ref to memory

		// TODO: this could be a calculated OFFSET reference with a base address

		if (!vContext.isConstant(valueToStore)) {
			return;
		}

		long valueOffset = valueToStore.getOffset();

		makeReference(vContext, instruction, -1, -1, valueOffset, 0, null, RefType.DATA, PcodeOp.STORE,
			false, false, monitor);
	}

	private void createVariableStorageReference(Instruction instruction,
			VarnodeContext varnodeContext, TaskMonitor monitor, PrototypeModel conv, VariableStorage storage,
			DataType dataType, long callOffset) {
		
		Address lastSetAddr;
		BigInteger bval;
		
		// TODO: need to handle memory
		// TODO: need to handle multi-piece variables and re-assemble
		//
		
		if (storage.isStackStorage()) {
			if (conv == null) {
				return;
			}
			Varnode sVnode = storage.getFirstVarnode();
			
			// translate the variable relative to the current stackpointer symbolic value
			Varnode stackVarnode = varnodeContext.getStackVarnode();
			Varnode stackVal = null;
			try {
				stackVal = varnodeContext.getValue(stackVarnode, null);
				if (stackVal == null) {
					return;
				}
			} catch (NotFoundException e) {
				return;
			}
			Varnode realSPVarnode = varnodeContext.createVarnode(stackVal.getOffset() + sVnode.getOffset(),
					stackVal.getSpace(), sVnode.getAddress().getAddressSpace().getPointerSize());
			
			Varnode value = null;
			try {
				value = varnodeContext.getValue(realSPVarnode,evaluator);
			}
			catch (NotFoundException e) {
				return;
			}				

			if (!varnodeContext.isConstant(value)) {
				return;
			}
			bval = BigInteger.valueOf(value.getOffset());
			
			lastSetAddr = varnodeContext.getLastSetLocation(realSPVarnode, bval);
			
			// TODO: What if last set location is in a delayslot?
		}
		else if (storage.isRegisterStorage()) {
			// TODO: need to handle compound register storage (e.g., two registers
			// used)
			Register reg = storage.getRegister();
	
			// RegisterValue rval =
			// context.getRegisterValue(reg,instruction.getMinAddress());
			RegisterValue rval = varnodeContext.getRegisterValue(reg);
			if (rval == null || !rval.hasValue()) {
				return;
			}
			
			reg = rval.getRegister();

			bval = rval.getUnsignedValue();
			lastSetAddr = varnodeContext.getLastSetLocation(reg, bval);
			// if instruction has a delay slot, carefully check the location of the
			// lastSetAddr Value
			// to make sure it matches. If it doesn't, use this instruction
			if (lastSetAddr != null && instruction.getPrototype().hasDelaySlots()) {
				RegisterValue lastRval = varnodeContext.getRegisterValue(reg, lastSetAddr);
				if (lastRval == null || !lastRval.hasAnyValue() || !lastRval.equals(rval)) {
					lastSetAddr = instruction.getMaxAddress();
				}
			}
			
		}
		else {
			return;
		}
		
		makeVariableStorageReference(storage, instruction, varnodeContext, monitor, callOffset, dataType, lastSetAddr, bval);
	}

	private void makeVariableStorageReference(VariableStorage storage, Instruction instruction, VarnodeContext varnodeContext,
			TaskMonitor monitor, long callOffset, DataType dataType, Address lastSetAddr, BigInteger bval) {
		
		if (lastSetAddr == null) {
			lastSetAddr = instruction.getMaxAddress();
		}
		if (bval == null) {
			return;
		}
		long val = bval.longValue();

		if (val == callOffset) {
			return;
		}

		if (lastSetAddr == null) {
			return;
		}
		
		// if the dataType is known, try to interpret it to an address given the
		// bytes in the storage location
		int knownSpaceID = -1;
		boolean knownReference = false;
		if (dataType != null) {
			if ((dataType instanceof TypeDef typedef && typedef.isPointer())) {
				// pointer type defs need to be handled specially they could be re-mapping to another space
				// or interpretting the value
				Object value = getPointerDataTypeValue(dataType, lastSetAddr, bval);
				if (value instanceof Address) {
					Address addrVal = (Address) value;
					val = addrVal.getAddressableWordOffset();
					knownSpaceID = addrVal.getAddressSpace().getSpaceID();
					knownReference = true;
				}
			}
		}

		// last setAddr could be in the base instruction
		Instruction instr = instruction;
		if (!instr.contains(lastSetAddr)) {
			instr = getInstructionContaining(lastSetAddr);
		}
		Reference[] refs = instr.getReferencesFrom();
		boolean found = false;
		for (Reference ref : refs) {
			Address refAddr = ref.getToAddress();
			Address addr = refAddr.getAddressSpace().getTruncatedAddress(val, true);
			if (ref.getReferenceType() == RefType.PARAM  && !body.contains(ref.getFromAddress())) {
				// if reference address is not in body yet, this is the first time at this location
				// get rid of the reference, reference could be changed to new AddressSpace or value
				instr.removeOperandReference(ref.getOperandIndex(), refAddr);
			} else if (refAddr.getOffset() == addr.getOffset()) {
				found = true;
			}
		}
		
		RefType refType = (callOffset == 0 ? RefType.DATA : RefType.PARAM);
		makeReference(varnodeContext, instr, Reference.MNEMONIC, knownSpaceID, val, 0, dataType, refType,
				PcodeOp.UNIMPLEMENTED, knownReference, found, monitor);
	}

	private Object getPointerDataTypeValue(DataType dataType, Address lastSetAddr,
			BigInteger bval) {
		
		int len = dataType.getLength();
		byte[] byteArray = new byte[len];

		BigEndianDataConverter.INSTANCE.putBigInteger(byteArray, 0, len, bval);

		MemBuffer buf =
			new ByteMemBufferImpl(program.getMemory(), lastSetAddr, byteArray, true);

		// if not enough bytes for data type, can't do it
		if (len > byteArray.length) {
			return null;
		}
		
		Object value = dataType.getValue(buf, dataType.getDefaultSettings(), len);
		
		return value;
	}	


	/**
	 * get the return variable storage location for this function
	 * 
	 */
	private VariableStorage getReturnLocationStorage(Function func) {
		// get the function containing the instruction if can
		//    if not, just use default
		VariableStorage returnLoc = null;
		int pointerSize = program.getDefaultPointerSize();
		PrototypeModel conv = null;
		if (func != null) {
			conv = func.getCallingConvention();
			DataType returnType = func.getReturnType();
			if (returnType != null && !(returnType instanceof DefaultDataType) &&
				returnType.getLength() < pointerSize) {
				return null;
			}
		}
		if (conv == null) {
			conv = program.getCompilerSpec().getDefaultCallingConvention();
		}

		// only want returns that can fit in a pointer!
		returnLoc =
			conv.getReturnLocation(new PointerDataType(Undefined.DEFAULT, pointerSize), program);

		return returnLoc;
	}

	/**
	 * Find the best address space to use for the reference if the space was unknown.
	 * 
	 * @param instruction - reference is to be placed on (used for address)
	 * @param offset - offset into the address space. (word addressing based)
	 * 
	 * @return spaceID of address to use for the reference
	 */
	private int getReferenceSpaceID(Instruction instruction, long offset) {
		// TODO: this should be passed to the client callback to make the decision
		if (offset <= 4 && offset >= -1) {
			return -1; // don't make speculative reference to certain offset values
		}

		AddressSpace defaultSpace = program.getLanguage().getDefaultDataSpace();

		// if only one memory space, no overlays, just return default space
		if (memorySpaces.size() == 1) {
			return defaultSpace.getSpaceID();
		}

		int realMemSpaceCnt = 0; // count of real memory spaces that could contain the target

		int containingMemSpaceCnt = 0; // number of memory blocks that have the target defined
		Address containingAddr = null;

		int symbolTargetCnt = 0;  // number of targets with a primary symbol at the address
		Address symbolTarget = null; // primary symbol target

		AddressSpace instrSpace = instruction.getMinAddress().getAddressSpace();

		// Find likely preferred target space
		// 1. only non-overlay space is default space, or
		// 2. presence of destination symbol/reference at only one of many possible targets

		// if this instruction is in an overlay space overlaying the default space, change the default space
		if (instrSpace.isOverlaySpace() &&
			((OverlayAddressSpace) instrSpace).getBaseSpaceID() == defaultSpace.getSpaceID()) {
			defaultSpace = instrSpace;
		}

		for (AddressSpace space : memorySpaces) {
			if (space.isOverlaySpace()) {
				if (space != instrSpace) {
					continue; // skip overlay spaces which do not contain instruction
				}
			}
			else {
				// don't add overlay spaces to realMemSpaceCnt
				++realMemSpaceCnt;
			}

			Address addr = space.getTruncatedAddress(offset, true);
			if (space.isOverlaySpace() && !addr.getAddressSpace().equals(space)) {
				continue; // overlay space address ended up in the base space, don't use it twice.
			}

			if (space.hasMappedRegisters() && program.getRegister(addr) != null) {
				if (!space.isOverlaySpace()) {
					realMemSpaceCnt--;
				}
				continue; // skip registers
			}

			if (program.getMemory().contains(addr)) {
				containingMemSpaceCnt++;
				containingAddr = addr;
			}
			if (program.getReferenceManager().hasReferencesTo(addr) ||
				program.getSymbolTable().getPrimarySymbol(addr) != null) {
				symbolTargetCnt++;
				symbolTarget = addr;
			}
		}

		// if only one memory space held a valid value, use it
		if (containingMemSpaceCnt == 1 && containingAddr != null) {
			return containingAddr.getAddressSpace().getSpaceID();
		}
		if (symbolTargetCnt == 1 && symbolTarget != null) {
			return symbolTarget.getAddressSpace().getSpaceID();
		}

		// nothing to lead to one space or the other, and code/data spaces are not the same
		if (realMemSpaceCnt != 1 && !defaultSpacesAreTheSame) {
			return -1;
		}
		return defaultSpace.getSpaceID();
	}

	/**
	 * Make from the instruction to the reference based on the varnode passed in.
	 * 
	 * @param varnodeContext - context to use for any other infomation needed
	 * @param instruction - instruction to place the reference on.
	 * @param pcodeop - pcode op that caused the reference
	 * @param opIndex - operand it should be placed on, or -1 if unknown
	 * @param vt - place to reference, could be a full address, or just a constant
	 * @param refType - type of reference
	 * @param knownReference true if this is a know good address, speculative otherwise
	 * @param monitor to cancel
	 * @return address that was marked up, null otherwise
	 */
	public Address makeReference(VarnodeContext varnodeContext, Instruction instruction, int opIndex, Varnode vt, DataType dataType, RefType refType,
			int pcodeop, boolean knownReference, TaskMonitor monitor) {
		if (!vt.isAddress() && !varnodeContext.isExternalSpace(vt.getSpace())) {
			if (evaluator != null) {
				evaluator.evaluateSymbolicReference(varnodeContext, instruction, vt.getAddress());
			}
			return null;
		}

		// offset must be word based to compute the reference correctly
		return makeReference(varnodeContext, instruction, opIndex, vt.getSpace(), vt.getWordOffset(),
			 vt.getSize(), dataType, refType, pcodeop, knownReference, false, monitor);
	}

	/**
	 *
	 * Make a reference from the instruction to the address based on the spaceID,offset passed in.
	 *   This could make a reference into an overlay (overriding the spaceID), or into memory, if
	 *   spaceID is a constant space.
	 *  The target could be an external Address carried along and then finally used.
	 *  External addresses are OK as long as nothing is done to the offset.
	 *  
	 * @param vContext - context to use for any other information needed
	 * @param instruction - instruction to place the reference on.
	 * @param opIndex - operand it should be placed on, or -1 if unknown
	 * @param knownSpaceID target space ID or -1 if only offset is known
	 * @param wordOffset - target offset that is word addressing based
	 * @param size - size of the access to the location
	 * @param refType - type of reference
	 * @param pcodeop - op that caused the reference
	 * @param knownReference - true if reference is known to be a real reference, not speculative
	 * @param preExisting preExisting reference
	 * @param monitor - the task monitor
	 * @return address that was marked up, null otherwise

	 */
	public Address makeReference(VarnodeContext vContext, Instruction instruction, int opIndex,
			long knownSpaceID, long wordOffset, int size, DataType dataType, RefType refType, int pcodeop,
			boolean knownReference, boolean preExisting, TaskMonitor monitor) {

		long spaceID = knownSpaceID;
		if (spaceID == -1) { // speculative reference - only offset is known
			spaceID = getReferenceSpaceID(instruction, wordOffset);
			if (spaceID == -1) {
				return null; // don't make speculative reference
			}
		}

		Address instructionAddress = instruction.getMinAddress();

		Address target;
		try {
			AddressSpace space = program.getAddressFactory().getAddressSpace((int) spaceID);

			if (space.isExternalSpace()) {
				target = space.getAddress(wordOffset, true);
			}
			else {
				// do checks that are actual memory, and not fabricated externals
				if (!space.isLoadedMemorySpace()) {
					return null;
				}
				// for now, don't mark up this area of memory.
				//   Memory at too low an offset could be from a bad calculation (use of zero or other small number)
				if (wordOffset == 0) {
					return null;
				}

				// wrap offset within address space
				if (wordOffset < 0) {
					// offset was sign extended, chop off sign extension
					// Note: this will only work for 64-bit signed extensions like Mips 64/32 hybrid
					target = space.getTruncatedAddress(wordOffset, true);
				}
				else {
					// take offset as is, value might not be a valid address
					target = space.getAddress(wordOffset, true);
				}

				wordOffset = target.getAddressableWordOffset();

				// don't make references to registers
				if (space.hasMappedRegisters() && program.getRegister(target) != null) {
					return null;
				}

				// normalize the address into this overlay space.
				target = instructionAddress.getAddressSpace().getOverlayAddress(target);

				// if this isn't known to be a good address, check that memory contains it
				if (!knownReference && !program.getMemory().contains(target)) {
					// it could be in a non-allocated memory space
					// TODO: Really at this point it should be a constant, and put on a list
					//       to be considered later as a pointer.
					// allow flow references to memory not in program
					//   program could be located in the wrong place, or other flow issues
					if (!refType.isFlow() && !program.getReferenceManager().hasReferencesTo(target)) {
						return null;
					}
				}
			}

			// if the refType is a call, and it isn't computed, we shouldn't be here
			if (refType.isCall() && !refType.isComputed()) {
				return null;
			}

			// give evaluator a chance to stop or change the reference
			target = evaluateReference(vContext, instruction, knownSpaceID, wordOffset, size,
				dataType, refType, pcodeop, knownReference, target);
			if (target == null || preExisting) {
				return null;
			}

			// Pure data references need to be scrutinized
			// TODO: This is a speculative type of reference, and should probably be done elsewhere.
			//
			if (refType.isData() &&
				!evaluatePureDataRef(instruction, wordOffset, refType, target)) {
				return null;
			}

			if (refType.isJump() && refType.isComputed()) {
				// if there are already some reference, don't do the jump here
				// if there are more than one reference, don't do the jump here
				Address[] flows = getInstructionFlows(instruction);
				if (flows.length > 1) {
					return target;
				}
				for (Address address : flows) {
					if (address.equals(target)) {
						return target;
					}
				}
			}
		}
		catch (AddressOutOfBoundsException e) {
			return null;
		}

		opIndex = findOpIndexForRef(vContext, instruction, opIndex, wordOffset, refType);

		// if didn't get the right opIndex, and has a delayslot, and this instruction is not the right flow for the reference
		if (opIndex == -1 && instruction.getPrototype().hasDelaySlots()) {
			if (!instruction.getFlowType().equals(refType)) {
				instruction = instruction.getNext();
				if (instruction == null) {
					return target;
				}
				opIndex = findOpIndexForRef(vContext, instruction, opIndex, wordOffset, refType);
			}
		}

		if (opIndex == -1) {
			if (!refType.isFlow() || target.isExternalAddress()) {
				opIndex = instruction.getNumOperands() - 1;
				// if it is invisible, don't put anything here.  Just put it on the mnemonic
				List<Object> list = instruction.getDefaultOperandRepresentationList(opIndex);
				if (list == null || list.size() == 0) {
					opIndex = -1;
				}
				// if is external, and any refs, just throw the ref on the mnemonic
				if (target.isExternalAddress() && instruction.getReferencesFrom().length != 0) {
					opIndex = -1;
				}
			}
		}

		if (opIndex == Reference.MNEMONIC) {
			instruction.addMnemonicReference(target, refType, SourceType.ANALYSIS);
		}
		else {
			instruction.addOperandReference(opIndex, target, refType, SourceType.ANALYSIS);
		}
		
		return target;
	}

	private Address evaluateReference(VarnodeContext vContext, Instruction instruction,
			long knownSpaceID, long wordOffset, int size, DataType dataType, RefType refType,
			int pcodeop, boolean knownReference, Address target) {
		if (evaluator == null) {
			return target;
		}

		// if this was a speculative reference, pass to the evaluateConstant
		if (knownSpaceID == -1 || !knownReference) {
			Address constant = program.getAddressFactory().getConstantAddress(wordOffset);
			Address newTarget = evaluator.evaluateConstant(vContext, instruction, pcodeop,
				constant, size, dataType, refType);
			if (newTarget == null) {
				return null;
			}
			if (newTarget != constant) {
				target = newTarget; // updated the target, if same, then don't update to constant
									// since the target address was already computed.
			}
		}

		// was a known reference, or constant evalutator allowed the reference and
		// didn't handle it
		if (!evaluator.evaluateReference(vContext, instruction, pcodeop, target, size,
			dataType, refType)) {
			return null;
		}
			
		return target;
	}

	/**
	 * Evaluate reference type for a pure data reference for valid reference to instructions
	 * 
	 * @param instruction that reference is from
	 * @param target of reference
	 * @param wordOffset target address word offset
	 * @param refType type of reference
	 * 
	 * @return true if not a pure data ref, or the reference is OK to make
	 */
	private boolean evaluatePureDataRef(Instruction instruction, long wordOffset, RefType refType,
			Address target) {
		if (refType.isRead() || refType.isWrite()) {
			return true;  // not a pure data ref
		}

		// if target is the fallthrough of this instruction
		//   any flow override might be an overriden call/return
		// this is a sanity check in case a speculative constant matches the fallthru of the instruction
		//  we shouldn't make these type of references.
		// Note: it is possible that the reference is to the data right below it by passing a parameter
		//       and the call override is referencing right below this function.  Would have to check
		//       where the value is stored (return address location).  So treat as bad ref value if flow-override.
		if (instruction.hasFallthrough() || instruction.getFlowOverride() != FlowOverride.NONE) {

			long fallAddrOffset =
				instruction.getMinAddress().getOffset() + instruction.getDefaultFallThroughOffset();
			if (fallAddrOffset == wordOffset) {
				return false;
			}
		}

		// TODO: This should be a speculative constant reference, and then we wouldn't need
		//       to check containing, or maybe containing would be checked later
		if (program.getMemory().contains(target)) {
			Instruction targetInstr = getInstructionContaining(target);
			if (targetInstr != null) {
				// if not at the top of an instruction, don't do it
				if (!targetInstr.getMinAddress().equals(target)) {
					return false;
				}
				if (targetInstr.isInDelaySlot()) {
					return false;
				}

				// if not at the top of an instruction flow, don't do it
				Function func = program.getFunctionManager().getFunctionContaining(target);
				if (func != null && !func.getEntryPoint().equals(target)) {
					return false;
				}
			}
		}
		return true;
	}

	private int findOpIndexForRef(VarnodeContext vcontext, Instruction instruction, int opIndex,
			long wordOffset, RefType refType) {

		int numOperands = instruction.getNumOperands();

		for (int i = 0; i < numOperands; i++) {
			int opType = instruction.getOperandType(i);

			if ((opType & OperandType.ADDRESS) != 0) {
				Address opAddr = instruction.getAddress(i);
				if (opAddr != null && opAddr.getAddressableWordOffset() == wordOffset) {
					opIndex = i;
					break;
				}
			}
			if ((opType & OperandType.SCALAR) != 0) {
				Scalar s = instruction.getScalar(i);
				if (s != null) {
					long val = s.getUnsignedValue();
					// sort of a hack, for memory that is not byte addressable
					if (val == wordOffset || val == (wordOffset >> 1)) {
						opIndex = i;
						break;
					}
				}
			}
			
			// Don't check more complicated operands if already found an operand that matches
			// only continue checking for an exact scalar/address operand
			if (opIndex != Reference.MNEMONIC) {
				continue;
			}
			
			// markup the program counter for any flow
			if ((opType & OperandType.REGISTER) != 0) {
				Register reg = instruction.getRegister(i);
				if (refType.isFlow() && reg != null && reg.isProgramCounter()) {
					opIndex = i;
					break;
				}
				if (reg != null) {
					// value for pointer can differ by 1 bit, which is sometimes ignored for flow
					if (checkOffByOne(reg, wordOffset)) {
						opIndex = i;
						if (refType.isFlow()) {
							break;
						}
					}
					if (checkOffByOne(reg.getParentRegister(), wordOffset)) {
						opIndex = i;
						if (refType.isFlow()) {
							break;
						}
					}
				}
			}

			if ((opType & OperandType.DYNAMIC) != 0) {
				List<Object> list = instruction.getDefaultOperandRepresentationList(i);
				int len = list.size();
				if (len > 0) {
					long baseRegVal = 0;
					long offset_residue_pos = wordOffset; // subtract all register values and add constants, check for zero
					long offset_residue_neg = wordOffset; // subtract all registers and subtract constants, check for zero
					for (int idx = 0; idx < len; idx++) {
						Object obj = list.get(idx);
						if (obj instanceof Scalar) {
							long val = ((Scalar) obj).getUnsignedValue();
							// sort of a hack, for memory that is not byte addressable
							if (val == wordOffset || val == (wordOffset >> 1) ||
								(val + baseRegVal) == wordOffset) {
								opIndex = i;
								break;
							}
							val = ((Scalar) obj).getSignedValue();
							offset_residue_neg -= val;
							offset_residue_pos += val;
						}
						if (obj instanceof Register) {
							Register reg = (Register) obj;
							BigInteger val = vcontext.getValue(reg, false);
							if (val != null) {
								baseRegVal = val.longValue();
								if ((baseRegVal & pointerMask) == wordOffset) {
									opIndex = i;
								}
								offset_residue_neg -= baseRegVal;
								offset_residue_pos -= baseRegVal;
							}
						}
					}
					if (offset_residue_neg == 0 || offset_residue_pos == 0) {
						opIndex = i;
						break;
					}
					if (opIndex == Reference.MNEMONIC && i == (numOperands - 1)) {
						opIndex = i;
					}
				}
			}
		}
		return opIndex;
	}

	/**
	 * check if the current Register value and wordOffset are off by just the low-bit.
	 * 
	 * @param reg - register to get a current value for
	 * @param wordOffset - word offset for the reference
	 * @return True if the two values are off by just the one bit.
	 */
	private boolean checkOffByOne(Register reg, long wordOffset) {
		if (reg == null) {
			return false;
		}
		BigInteger val = context.getValue(reg, false);
		if (val == null) {
			return false;
		}
		long lval = val.longValue() & pointerMask;
		return (lval == wordOffset || (lval ^ wordOffset) == 1);
	}

	/**
	 * @return true if any branching instructions have been encountered
	 */
	public boolean encounteredBranch() {
		return hitCodeFlow;
	}

	/**
	 * @return return true if the code ever read from an executable location
	 */
	public boolean readExecutable() {
		return readExecutableAddress;
	}

	/**
	 * enable/disable checking parameters for constant references
	 * 
	 * @param checkParamRefsOption true to enable
	 */
	public void setParamRefCheck(boolean checkParamRefsOption) {
		checkForParamRefs = checkParamRefsOption;
	}

	/**
	 * enable/disable creating param references for constants
	 * only if the function parameter is specified as a known pointer
	 * 
	 * @param checkParamRefsOption true to enable
	 */
	public void setParamPointerRefCheck(boolean checkParamRefsOption) {
		checkForParamPointerRefs = checkParamRefsOption;
	}
	
	/**
	 * enable/disable checking return for constant references
	 * 
	 * @param checkReturnRefsOption true if enable check return for constant references
	 */
	public void setReturnRefCheck(boolean checkReturnRefsOption) {
		checkForReturnRefs = checkReturnRefsOption;
	}

	/**
	 * enable/disable checking stored values for constant references
	 * 
	 * @param checkStoredRefsOption true if enable check for stored values for constant references
	 */
	public void setStoredRefCheck(boolean checkStoredRefsOption) {
		checkForStoredRefs = checkStoredRefsOption;
	}

}
