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
package ghidra.app.cmd.function;

import java.math.BigInteger;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

import ghidra.app.util.PseudoDisassembler;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainObject;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.*;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.*;
import ghidra.program.util.*;
import ghidra.util.Msg;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * Command for creating a thunk function at an address.
 */
public class CreateThunkFunctionCmd extends BackgroundCommand {
	private Address entry;
	private AddressSetView body;
	private Address referencedFunctionAddr;
	private Symbol referencedSymbol;
	private Function thunkFunction;
	private Function referencedFunction;
	private List<Address> referringThunkAddresses = new ArrayList<>();
	private boolean checkForSideEffects = true;

	private static final int MAX_NUMBER_OF_THUNKING_INSTRUCTIONS = 8;

	static String DEFAULT_FUNCTION_COMMENT = " THUNK-FUNCTION";

	/**
	 * Constructs a new command for creating a thunk function.
	 * @param entry entry point address for the function to be created.
	 * @param body set of addresses to associated with the function to be created.
	 * The addresses must not already be included in the body of any existing function.
	 * If null, and entry corresponds to an existing function, that function will be
	 * converted to a thunk, otherwise an error will result.
	 * @param referencedFunctionAddr the function address to which this thunk refers.  If no function
	 * exists at that specified referencedFunctionAddr one will be created per the following scheme:
	 * <br><ul>
	 * <li>If referencedFunctionAddr is not contained within a memory block, an external function will<br>
	 * be created (a check will be done to look for an previously defined external location)</li>
	 * <li>If referencedFunctionAddr corresponds to an instruction, a new function will be<br>
	 * created at that address.</li>
	 * </ul>
	 */
	public CreateThunkFunctionCmd(Address entry, AddressSetView body,
			Address referencedFunctionAddr, List<Address> referringThunkAddresses) {
		this(entry, body, referencedFunctionAddr);
		if (referringThunkAddresses != null) {
			this.referringThunkAddresses.addAll(0, referringThunkAddresses);
		}
	}

	/**
	 * Constructs a new command for creating a thunk function.
	 * @param entry entry point address for the function to be created.
	 * @param body set of addresses to associated with the function to be created.
	 * The addresses must not already be included in the body of any existing function.
	 * If null, and entry corresponds to an existing function, that function will be
	 * converted to a thunk, otherwise an error will result.
	 * @param referencedFunctionAddr the function address to which this thunk refers.  If no function
	 * exists at that specified referencedFunctionAddr one will be created per the following scheme:
	 * <br><ul>
	 * <li>If referencedFunctionAddr is not contained within a memory block, an external function will<br>
	 * be created (a check will be done to look for an previously defined external location)</li>
	 * <li>If referencedFunctionAddr corresponds to an instruction, a new function will be<br>
	 * created at that address.</li>
	 * </ul>
	 */
	public CreateThunkFunctionCmd(Address entry, AddressSetView body,
			Address referencedFunctionAddr) {
		super("Create Thunk Function", false, false, false);
		this.entry = entry;
		this.body = body;
		this.referencedFunctionAddr = referencedFunctionAddr;
		referringThunkAddresses.add(entry);
	}

	/**
	 * Constructs a new command for creating a thunk function.
	 * @param entry entry point address for the function to be created.
	 * @param body set of addresses to associated with the function to be created.
	 * The addresses must not already be included in the body of any existing function.
	 * If null, and entry corresponds to an existing function, that function will be
	 * converted to a thunk, otherwise an error will result.
	 * @param referencedSymbol the symbol which identifies the intended function to which this thunk refers.
	 * If no function exists at that specified referencedSymbol location, one will be created per the following scheme:
	 * <br><ul>
	 * <li>If referencedFunctionAddr is not contained within a memory block, an external function will<br>
	 * be created (a check will be done to look for an previously defined external location)</li>
	 * <li>If referencedFunctionAddr corresponds to an instruction, a new function will be<br>
	 * created at that address.</li>
	 * <li>If referencedSymbol corresponds to an external CODE symbol, it will be converted to an<br>
	 * external FUNCTION</li>
	 * </ul>
	 */
	public CreateThunkFunctionCmd(Address entry, AddressSetView body, Symbol referencedSymbol) {
		this(entry, body, (Address) null);
		this.referencedSymbol = referencedSymbol;
	}

	/**
	 * Constructs a new command for creating a thunk function that can compute the function this function is thunking to.
	 * 
	 * @param entry entry point address for the function to be created.
	 * @param checkForSideEffects true to check for side-effects that indicate it is not a pure thunk.
	 * 
	 * The body may be computed.  References to the thunked to function may be created.
	 * 
	 * If no function exists at the location being thunked, it will be created based on the above rules.
	 */
	public CreateThunkFunctionCmd(Address entry, boolean checkForSideEffects) {
		this(entry, (AddressSetView) null, (Symbol) null);
		this.checkForSideEffects = checkForSideEffects;
	}

	@Override
	public boolean applyTo(DomainObject obj, TaskMonitor monitor) {
		Program program = (Program) obj;

		FunctionManager functionMgr = program.getFunctionManager();

		if (referencedFunctionAddr == Address.NO_ADDRESS) {
			referencedFunctionAddr = null;
		}

		// TODO: If thunk already exists as a function with a non-default signature (i.e., imported)
		// should we migrate that signature to the thunked function (referencedFunction) if it has
		// a default signature

		thunkFunction = functionMgr.getFunctionAt(entry);
		if (body != null) {
			for (Function f : functionMgr.getFunctions(body, true)) {
				if (f != thunkFunction) {
					setStatusMsg("Specified body overlaps existing function '" + f.getName() +
						"' at " + f.getEntryPoint());
					return false;
				}
			}
		}

		referencedFunction = getReferencedFunction(
			referencedFunctionAddr == null && referencedSymbol == null, program, monitor);
		if (referencedFunction == null) {
			thunkFunction = null;
			return false;
		}
		referencedFunctionAddr = referencedFunction.getEntryPoint();

		if (thunkFunction != null) {
			try {
				thunkFunction.setThunkedFunction(referencedFunction);
			}
			catch (IllegalArgumentException e) {
				setStatusMsg("Invalid thunked function specified: " + e.getMessage());
				return false;
			}
			if (body != null) {
				try {
					thunkFunction.setBody(body);
				}
				catch (OverlappingFunctionException e) {
					setStatusMsg("Specified body overlaps existing function(s): " + e.getMessage());
					return false;
				}
			}
			return true;
		}

		if (program.getListing().getFunctionContaining(entry) != null) {
			setStatusMsg("Thunk function entry contained within another function");
			return false;
		}

		if (body == null) {
			body = computeThunkBody(program);
			if (body == null) {
				return false;
			}
		}
		else if (body.contains(referencedFunctionAddr)) {
			// TODO: This only handles the simple cases of fixing body
			body = body.subtract(referencedFunction.getBody());
			if (body.getNumAddressRanges() != 1 || !body.contains(entry)) {
				return false;
			}
		}

		Namespace namespace = program.getGlobalNamespace();
		String name = null;
		SourceType source = SourceType.DEFAULT;
		Symbol s = program.getSymbolTable().getPrimarySymbol(entry);
		if (s != null) {
			name = s.getName();
			namespace = s.getParentNamespace();
			source = s.getSource();
		}

		try {
			thunkFunction = functionMgr.createThunkFunction(name, namespace, entry, body,
				referencedFunction, source);
		}
		catch (OverlappingFunctionException e) {
			setStatusMsg("Specified body overlaps existing function(s): " + e.getMessage());
			return false;
		}

		return true;
	}

	private AddressSetView computeThunkBody(Program program) {
		if (MemoryBlock.isExternalBlockAddress(entry, program)) {
			return new AddressSet(entry, entry);
		}
		Listing listing = program.getListing();
		Instruction instr = listing.getInstructionAt(entry);
		if (instr == null) {
			return null;
		}
		FlowType flowtype = instr.getFlowType();
		if (flowtype == RefType.UNCONDITIONAL_JUMP || flowtype == RefType.COMPUTED_JUMP ||
			flowtype == RefType.COMPUTED_CALL_TERMINATOR || flowtype == RefType.CALL_TERMINATOR) {
			return new AddressSet(instr.getMinAddress(), instr.getMaxAddress());
		}
		setStatusMsg("Must specify thunk function body");
		return null;
	}

	private Function getReferencedFunction(boolean autoThunkOK, Program program,
			TaskMonitor monitor) {

		Listing listing = program.getListing();

		if (referencedSymbol != null) {
			Object obj = referencedSymbol.getObject();
			if (obj instanceof Function) {
				return (Function) obj;
			}
			if (obj instanceof ExternalLocation) {
				return ((ExternalLocation) obj).createFunction();
			}
			referencedFunctionAddr = referencedSymbol.getAddress();
		}
		else if ((referencedFunctionAddr == null || referencedFunctionAddr == Address.NO_ADDRESS) &&
			autoThunkOK) {
			// first try to get the address that is already there
			referencedFunctionAddr = getThunkedExternalFunctionAddress(program, entry);
			if (referencedFunctionAddr == null) {
				referencedFunctionAddr = getThunkedAddr(program, entry, checkForSideEffects);
			}
			// if can't get an address, try to calculate it
			if (referencedFunctionAddr == null || referencedFunctionAddr == Address.NO_ADDRESS) {
				try {
					if (resolveComputableFlow(program, entry, monitor)) {
						referencedFunctionAddr =
							getThunkedAddr(program, entry, checkForSideEffects);
					}
				}
				catch (CancelledException e) {
					// TODO: Is this the right thing to do on a canceled exception?
					return null;
				}
			}
		}
		else if (referencedFunctionAddr != null) {
			// Ignore low-bit for certain languages (e.g., Thumb)
			referencedFunctionAddr =
				PseudoDisassembler.getNormalizedDisassemblyAddress(program, referencedFunctionAddr);
		}

		if (referencedFunctionAddr == null) {
			setStatusMsg(
				"Failed to create thunk at " + entry + ": unable to find thunked function");
			return null;
		}

		Function f = listing.getFunctionAt(referencedFunctionAddr);
		if (f == null) {
			// If referencedFunctionAddr contained within EXTERNAL block attempt to 
			// create a thunk function for it
			if (MemoryBlock.isExternalBlockAddress(referencedFunctionAddr, program)) {
				CreateThunkFunctionCmd extThunkCmd =
					new CreateThunkFunctionCmd(referencedFunctionAddr, false);
				if (extThunkCmd.applyTo(program)) {
					f = extThunkCmd.getThunkFunction();
				}
			}
		}
		if (f != null) {
			// no circular thunking allowed
			if (f.getEntryPoint().equals(entry)) {
				setStatusMsg("Invalid referenced function: circular reference");
				return null;
			}
			return f;
		}

		if (referencedFunctionAddr.isExternalAddress()) {
			Symbol s = program.getSymbolTable().getPrimarySymbol(referencedFunctionAddr);
			if (s != null) {
				ExternalLocation extLoc = (ExternalLocation) s.getObject();
				Msg.trace(this,
					"Converting external location to function as a result of thunk at: " + entry);
				return extLoc.createFunction();
			}
			return null;
		}

		if (!referencedFunctionAddr.isMemoryAddress()) {
			setStatusMsg("Referenced address/symbol is not a valid memory location");
			return null;
		}

		if (!program.getMemory().contains(referencedFunctionAddr)) {
			return getExternalFunction(program);
		}

		f = listing.getFunctionContaining(referencedFunctionAddr);
		if (f != null || listing.getInstructionAt(referencedFunctionAddr) == null) {
			setStatusMsg("Invalid referenced function entry address");
			return null;
		}

		if (referringThunkAddresses.contains(referencedFunctionAddr)) {
			setStatusMsg("Invalid referenced function: circular reference");
			return null;
		}

		CreateFunctionCmd funcCmd =
			new CreateFunctionCmd(referencedFunctionAddr, referringThunkAddresses);
		if (funcCmd.applyTo(program)) {
			return funcCmd.getFunction();
		}
		setStatusMsg("Failed to create thunk at " + entry +
			": unable to create thunked-function at " + referencedFunctionAddr);
		return null;
	}

	private Function getExternalFunction(Program program) {

		ExternalManager externalMgr = program.getExternalManager();
		ExternalLocationIterator externalLocations =
			externalMgr.getExternalLocations(referencedFunctionAddr);
		if (!externalLocations.hasNext()) {
			// create new external location
			ExternalLocation extLoc;
			try {
				extLoc = externalMgr.addExtFunction(Library.UNKNOWN, null, referencedFunctionAddr,
					SourceType.DEFAULT);
				Msg.debug(this, "Created new external location for address " +
					referencedFunctionAddr + ": " + extLoc.toString());
			}
			catch (DuplicateNameException | InvalidInputException e) {
				throw new RuntimeException("Unexpected exception", e);
			}
			return extLoc.getFunction();
		}

		ExternalLocation extLoc = externalLocations.next();
		if (extLoc.isFunction()) {
			// found existing external function with same address
			return extLoc.getFunction();
		}

		Msg.debug(this, "Converting external location to a function: " + extLoc.toString());
		return extLoc.createFunction();
	}

	/**
	 * resolve the flow destination by computing to a single value with a restriction to a single basic block.
	 *   
	 * @return single flow address, null if single flow can't be resolved
	 */
	private boolean resolveComputableFlow(Program program, Address location, TaskMonitor monitor)
			throws CancelledException {

		Register isaModeSwitchRegister = program.getRegister("ISAModeSwitch");
		Register isaModeRegister = program.getRegister("ISA_MODE");

		// get the basic block
		//
		// NOTE: Assumption, target addres must be computable in single flow, or else isn't a thunk

		BasicBlockModel basicBlockModel = new BasicBlockModel(program);

		final CodeBlock jumpBlockAt =
			basicBlockModel.getFirstCodeBlockContaining(location, monitor);
		// If the jump target can has a computable target with only the instructions in the basic block it is found in
		//  then it isn't a switch statment
		//
		// NOTE: Assumption, we have found all flows leading to the switch that might split the basic block

		final AtomicInteger foundCount = new AtomicInteger(0);
		SymbolicPropogator prop = new SymbolicPropogator(program);

		prop.flowConstants(jumpBlockAt.getFirstStartAddress(), jumpBlockAt,
			new ContextEvaluatorAdapter() {
				@Override
				public boolean evaluateReference(VarnodeContext context, Instruction instr,
						int pcodeop, Address address, int size, RefType refType) {
					// go ahead and place the reference, since it is a constant.
					if (refType.isComputed() && refType.isFlow() &&
						program.getMemory().contains(address)) {
						propogateCodeMode(context, address);
						foundCount.incrementAndGet();
						return true;
					}
					return false;
				}

				@Override
				public boolean allowAccess(VarnodeContext context, Address addr) {
					return true;
				}

				private void propogateCodeMode(VarnodeContext context, Address addr) {
					// get CodeModeRegister and flow it to destination, if it is set here

					if (isaModeSwitchRegister == null) {
						return;
					}
					BigInteger value = context.getValue(isaModeSwitchRegister, false);
					if (value != null && program.getListing().getInstructionAt(addr) == null) {
						try {
							program.getProgramContext()
									.setValue(isaModeRegister, addr, addr,
										value);
						}
						catch (ContextChangeException e) {
							// ignore
						}
					}
				}
			}, false, monitor);

		// If added only one computed flow reference, then recovered a good thunk.

		return foundCount.get() == 1;
	}

	/**
	 * @return function if create command was successful
	 */
	public Function getThunkFunction() {
		return thunkFunction;
	}

	/**
	 * @return the function referenced by the newly created thunk function
	 * is command was successful
	 */
	public Function getReferencedFunction() {
		return referencedFunction;
	}

	/**
	 * if the code starting at entry is a thunk, return the thunked addess if known.
	 * 
	 * @param program code resides in
	 * @param entry start of the code
	 * @return the function address, Address.NO_ADDRESS if thunk but unknonw addr, null otherwise
	 */
	public static Address getThunkedAddr(Program program, Address entry) {
		return getThunkedAddr(program, entry, true);
	}

	/**
	 * Get the address that this function would thunk if it is a valid thunk
	 *
	 * @param program
	 * @param entry location to check for a thunk
	 * @param checkForSideEffects true if there should be no extra registers affected
	 *
	 * @return address that the thunk thunks,Address.NO_ADDRESS if thunk but unknown addr, null otherwise
	 */
	public static Address getThunkedAddr(Program program, Address entry,
			boolean checkForSideEffects) {
		// General algorithm:
		//
		// get function, if has no other calls, and no other flow
		// if does no other computation than computing the jump???
		// simple number of instructions?  Specialized for a given processor?
		// Danger that side-effects are not found.
		// All other instruction refs are just reads, and have good addresses?
		// All instructions go into the computation of the jump, simplified away?
		// Put it in the patterns file?
		// small number of instructions, look at pcode, all loads, arith
		// no branching other than final computed jump

		// check if the first instruction is an indirect jump
		Listing listing = program.getListing();

		Instruction instr = listing.getInstructionAt(entry);
		if (instr == null) {
			return null;
		}

		FlowType flowType;

		// Treat single jump or call-return as thunk
		Address simpleFlowAddr = getSimpleFlow(instr);
		if (simpleFlowAddr != null) {
			return simpleFlowAddr;
		}

		// 8-bit registers are normally flag registers
		//   for 16-bit address spaces, the registers may be too small, so don't allow
		//   non-use of an 8-bit register
		boolean allow8bitNonUse = true;
		if (program.getAddressFactory().getDefaultAddressSpace().getSize() <= 16) {
			allow8bitNonUse = false;
		}

		// only go three instructions deep
		// keep a list of outputs and inputs
		// if inputs are used, get rid of them
		// if only output is the PC, and small registers, assume OK
		// any write to memory is bad
		int numInstr = 1;
		HashSet<Varnode> setAtStartRegisters = new HashSet<>();
		HashSet<Varnode> setRegisters = new HashSet<>();
		HashSet<Varnode> usedRegisters = new HashSet<>();

		// add in the registers that are set at the beginning of the function
		addSetRegisters(program, entry, setAtStartRegisters);

		while (instr != null && numInstr++ <= MAX_NUMBER_OF_THUNKING_INSTRUCTIONS) {
			flowType = instr.getFlowType();

			// Keep track of any read/writes to registers, need to see if there are any side-effects
			// check Pcode, any writes to memory are bad
			PcodeOp[] pcode = instr.getPcode(false);
			for (PcodeOp element : pcode) {
				PcodeOp pcodeOp = element;

				// Storing to a location is not allowed for a thunk
				//   as a side-effect of the thunk.
				if (pcodeOp.getOpcode() == PcodeOp.STORE) {
					return null;
				}

				// record any used registers, checking for use of an unexpected unset register
				if (checkForSideEffects && !addRegisterUsage(program, setAtStartRegisters,
					setRegisters, usedRegisters, pcodeOp, allow8bitNonUse)) {
					return null;
				}
			}

			// any instruction with a delay slot is actually a branching instruction.
			//  only do this for instructions that aren't delay slot instructions
			if (instr.isFallthrough() && instr.getDelaySlotDepth() == 0) {
				Address fallAddr = instr.getFallThrough();
				instr = listing.getInstructionAt(fallAddr);
				continue;
			}

			// keep going if flow target is right below, allow only a simple branch.
			if (isLocalBranch(listing, instr, flowType)) {
				continue;
			}

			// reached a flow, end of the line, gotta see what we have
			return getFlowingAddrFromFinalState(program, instr, flowType, checkForSideEffects,
				setRegisters, usedRegisters);
		}

		return null;
	}

	private static void addSetRegisters(Program program, Address entry,
			HashSet<Varnode> setRegisters) {
		Register[] regWithVals = program.getProgramContext().getRegistersWithValues();
		for (Register register : regWithVals) {
			if (register.isProcessorContext()) {
				continue;
			}

			RegisterValue regVal = program.getProgramContext().getRegisterValue(register, entry);
			if (regVal == null) {
				continue;
			}
			if (!regVal.hasValue()) {
				continue;
			}
			Register reg = regVal.getRegister();
			setRegisters.add(new Varnode(reg.getAddress(), reg.getMinimumByteSize()));
		}
	}

	/**
	 * Handle conversion of label within reserved EXTERNAL block to a real 
	 * external function which can be thunked.  This may be necessary when a
	 * loaded symbol failed to identify itself as a function.  This will 
	 * only handle single symbols contained within the global namespace.
	 * 
	 * @param program 
	 * @param entry function being created
	 * @return newly created external function address or null
	 */
	static Address getThunkedExternalFunctionAddress(Program program, Address entry) {

		if (!MemoryBlock.isExternalBlockAddress(entry, program)) {
			return null;
		}

		SymbolTable symbolTable = program.getSymbolTable();
		Symbol[] symbols = symbolTable.getSymbols(entry);
		if (symbols.length != 1) {
			return null;
		}
		Symbol s = symbols[0];
		if (s.isDynamic() || s.getSymbolType() != SymbolType.LABEL ||
			!s.getParentNamespace().isGlobal()) {
			return null;
		}
		try {
			ExternalManager extMgr = program.getExternalManager();
			ExternalLocation extLoc =
				extMgr.addExtFunction(Library.UNKNOWN, s.getName(), null, s.getSource());
			return extLoc.getExternalSpaceAddress();
		}
		catch (DuplicateNameException | InvalidInputException e) {
			// ignore - unexpected
		}
		return null;
	}

	private static boolean isLocalBranch(Listing listing, Instruction instr, FlowType flowType) {
		if ((flowType.isJump() && !flowType.isConditional())) {
			Address[] flows = instr.getFlows();
			// allow a jump of 4 instructions forward.
			if (flows.length == 1 && Math.abs(flows[0].subtract(instr.getMinAddress())) <= 4) {
				return true;
			}
		}
		return false;
	}

	private static Address getFlowingAddrFromFinalState(Program program, Instruction instr,
			FlowType flowType, boolean checkForSideEffects, HashSet<Varnode> setRegisters,
			HashSet<Varnode> usedRegisters) {

		// conditional jumps can't be thunks.
		// any other flow, not good
		Address flowingAddr = null;
		if ((flowType.isJump() || flowType.equals(RefType.COMPUTED_CALL_TERMINATOR) ||
			flowType.equals(RefType.CALL_TERMINATOR)) && !flowType.isConditional()) {
			// program counter should be assumed to be used

			// assume PC is used when considering registers that have been set
			Register PC = program.getLanguage().getProgramCounter();
			if (PC != null) {
				usedRegisters.add(new Varnode(PC.getAddress(), PC.getMinimumByteSize()));
			}
			setRegisters.removeAll(usedRegisters);

			// check that the setRegisters are all hidden, meaning don't care.
			for (Iterator<Varnode> iterator = setRegisters.iterator(); iterator.hasNext();) {
				Varnode rvnode = iterator.next();
				Register reg = program.getRegister(rvnode);
				// the register pcode access could have fallen in the middle of a valid register
				//  thus no register will exist at the varnode
				if (reg != null && reg.isHidden()) {
					iterator.remove();
				}
			}

			// if not checking for sideEffect registers set, or there are no side-effects
			if (!checkForSideEffects || setRegisters.size() == 0) {
				flowingAddr = getFlowingAddress(program, instr);
			}
		}
		return flowingAddr;
	}

	/**
	 * try to get a simple flow address from a single instruction
	 *
	 * @param instr to check for simple flow to target
	 * @return targetAddr if was a simple flow, null otherwise
	 */
	private static Address getSimpleFlow(Instruction instr) {
		FlowType flowType;
		flowType = instr.getFlowType();
		if (instr.getDelaySlotDepth() == 0 && !flowType.isConditional() &&
			(flowType.isJump() || (flowType.isCall() && flowType.isTerminal()))) {
			Address[] flows = instr.getFlows();
			if (flows.length == 1) {
				return flows[0];
			}
		}
		return null;
	}

	/**
	 * add in all registers used/set in the pcodeop, checking for a register with an unknown input.
	 *
	 * @param program - program this pcode belongs to
	 * @param setAtStartRegisters - registers that were set at the start of the function
	 * @param setRegisters - registers that are currently set to a value
	 * @param usedRegisters - registers that have been used by any pcode op
	 * @param pcode - pcode operation.
	 * @param allow8bitNonUse - TRUE to allow setting of 8bit size registers without
	 *                          eventual use of the value.
	 *                          8-bit registers are normally flags. For 16-bit or
	 *                          8-bit processors, this should be FALSE
	 *
	 * @return true if all input registers had a valid input
	 *         false if input register found that was not initialized
	 */
	private static boolean addRegisterUsage(Program program, HashSet<Varnode> setAtStartRegisters,
			HashSet<Varnode> setRegisters, HashSet<Varnode> usedRegisters, PcodeOp pcode,
			boolean allow8bitNonUse) {
		int opcode = pcode.getOpcode();
		Varnode output = pcode.getOutput();

		// copying from a memory address is an unknown input
		if (opcode == PcodeOp.COPY) {
			if (output.isAddress()) {
				return false;
			}
			// if input same as output, is a NOP pcode op
			if (output.equals(pcode.getInput(0))) {
				return true;
			}
		}

		Varnode[] inputs = pcode.getInputs();
		for (Varnode input : inputs) {
			// if scalar, is OK
			// if memory load, OK
			// if register, must be on the set list
			Varnode inVarnode = input;
			if (inVarnode.isRegister()) {
				if ((!allow8bitNonUse || inVarnode.getSize() > 1) &&
					!containsRegister(program, setRegisters, inVarnode) &&
					!containsRegister(program, setAtStartRegisters, inVarnode)) {
					return false;
				}
				// it doesn't count as use if the sizes aren't equivalent
				//  some instructions set flags as a side-effect
				if (output == null || output.getSize() >= inVarnode.getSize()) {
					usedRegisters.add(inVarnode);
				}
			}
		}

		// if address, bad
		// if big enough register, must be on set list
		if (output != null && output.isRegister()) {
			if (!allow8bitNonUse || output.getSize() > 1) {
				setRegisters.add(output);
				// we set it, now it needs a new use!
				usedRegisters.remove(output);
			}
		}
		return true;
	}

	/**
	 * Check if the setRegisters contains the varnode or any of its parents.
	 * If a parent register has been set, then this varnode is set
	 */
	private static boolean containsRegister(Program program, HashSet<Varnode> setRegisters,
			Varnode regVarnode) {
		if (setRegisters.contains(regVarnode)) {
			return true;
		}
		// check the parent varnode
		Register register = program.getRegister(regVarnode);
		if (register == null) {
			return false;
		}
		Register parentRegister = register.getParentRegister();
		if (parentRegister == null) {
			return false;
		}
		Varnode parentVarnode =
			new Varnode(parentRegister.getAddress(), parentRegister.getBitLength() / 8);
		return setRegisters.contains(parentVarnode);
	}

	private static Address getFlowingAddress(Program program, Instruction instr) {
		// check the refs to see if we can determine single flow destination
		Reference flowRef = null;
		Reference dataRef = null;
		for (Reference reference : instr.getReferencesFrom()) {
			RefType refType = reference.getReferenceType();
			if (refType.isData()) {
				dataRef = reference;
				continue;
			}
			if (!refType.isFlow()) {
				continue;
			}
			if (flowRef != null) {
				return null; // can't handle multiple flow-refs
			}
			flowRef = reference;
		}
		if (flowRef == null) {
			flowRef = dataRef;
		}
		if (flowRef != null) {
			RefType refType = flowRef.getReferenceType();
			if (refType.isData() || refType.isIndirect()) {
				// some references are labeled as INDIRECT which correspond to flow via a pointer
				Address toAddr = flowRef.getToAddress();
				Reference[] referencesFrom =
					program.getReferenceManager().getReferencesFrom(toAddr);
				if (referencesFrom.length == 1 &&
					(referencesFrom[0].getReferenceType() == RefType.DATA ||
						referencesFrom[0].isExternalReference())) {
					return referencesFrom[0].getToAddress();
				}
				return null; // can't use indirection in single 
			}
			return flowRef.getToAddress();
		}

		// it would have been a thunk, so return a bad address signaling it was a thunk
		return Address.NO_ADDRESS;
	}

	/**
	 * Check if this is a Thunking function.
	 *
	 * @return true if this is a function thunking another.
	 */
	public static boolean isThunk(Program program, Function func) {
		Address entry = func.getEntryPoint();

		if (getThunkedAddr(program, entry) == null) {
			return false;
		}
		return true;
	}

}
