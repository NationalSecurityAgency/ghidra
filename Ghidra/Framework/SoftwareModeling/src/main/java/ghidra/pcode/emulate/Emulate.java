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
package ghidra.pcode.emulate;

import java.lang.reflect.Constructor;
import java.math.BigInteger;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.error.LowlevelError;
import ghidra.pcode.memstate.MemoryState;
import ghidra.pcode.memstate.UniqueMemoryBank;
import ghidra.pcode.opbehavior.*;
import ghidra.pcode.pcoderaw.PcodeOpRaw;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
/// \brief A SLEIGH based implementation of the Emulate interface
///
/// This implementation uses a Translate object to translate machine instructions into
/// pcode and caches pcode ops for later use by the emulator.  The pcode is cached as soon
/// as the execution address is set, either explicitly, or via branches and fallthrus.  There
/// are additional methods for inspecting the pcode ops in the current instruction as a sequence.

public class Emulate {

	private MemoryState memstate; // the memory state of the emulator.
	private UniqueMemoryBank uniqueBank;

	private BreakTable breaktable; ///< The table of breakpoints
	private Address current_address; ///< Address of current instruction being executed
	private Address last_execute_address;
	private volatile EmulateExecutionState executionState = EmulateExecutionState.STOPPED;
	private RuntimeException faultCause;
	private int current_op; ///< Index of current pcode op within machine instruction
	private int last_op; /// index of last pcode op executed
	private int instruction_length; ///< Length of current instruction in bytes (must include any delay slots)

	private final SleighLanguage language;
	private final AddressFactory addrFactory;
	private Register pcReg;

	private InstructionBlock lastPseudoInstructionBlock;
	private Disassembler pseudoDisassembler;
	private Instruction pseudoInstruction;
	private PcodeOp[] pcode; ///< The cache of current pcode ops

	private RegisterValue nextContextRegisterValue = null;

	private EmulateMemoryStateBuffer memBuffer; // used for instruction parsing

	private EmulateInstructionStateModifier instructionStateModifier;

	/// \param t is the SLEIGH translator
	/// \param s is the MemoryState the emulator should manipulate
	/// \param b is the table of breakpoints the emulator should invoke
	public Emulate(SleighLanguage lang, MemoryState s, BreakTable b) {
		memstate = s;
		this.language = lang;
		this.addrFactory = lang.getAddressFactory();
		pcReg = lang.getProgramCounter();
		breaktable = b;
		breaktable.setEmulate(this);
		memBuffer =
			new EmulateMemoryStateBuffer(s, addrFactory.getDefaultAddressSpace().getMinAddress());

		uniqueBank =
			new UniqueMemoryBank(lang.getAddressFactory().getUniqueSpace(), lang.isBigEndian());
		memstate.setMemoryBank(uniqueBank);

//		emitterContext = new EmulateDisassemblerContext(lang, s);

		pseudoDisassembler =
			Disassembler.getDisassembler(lang, addrFactory, TaskMonitorAdapter.DUMMY_MONITOR, null);

		initInstuctionStateModifier();
	}

	public void dispose() {
		executionState = EmulateExecutionState.STOPPED;
	}

	@SuppressWarnings("unchecked")
	private void initInstuctionStateModifier() {
		String classname = language.getProperty(
			GhidraLanguagePropertyKeys.EMULATE_INSTRUCTION_STATE_MODIFIER_CLASS);
		if (classname == null) {
			return;
		}
		try {
			Class<?> c = Class.forName(classname);
			if (!EmulateInstructionStateModifier.class.isAssignableFrom(c)) {
				Msg.error(this,
					"Language " + language.getLanguageID() + " does not specify a valid " +
						GhidraLanguagePropertyKeys.EMULATE_INSTRUCTION_STATE_MODIFIER_CLASS);
				throw new RuntimeException(classname + " does not implement interface " +
					EmulateInstructionStateModifier.class.getName());
			}
			Class<? extends EmulateInstructionStateModifier> instructionStateModifierClass =
				(Class<? extends EmulateInstructionStateModifier>) c;
			Constructor<? extends EmulateInstructionStateModifier> constructor =
				instructionStateModifierClass.getConstructor(Emulate.class);
			instructionStateModifier = constructor.newInstance(this);
		}
		catch (Exception e) {
			Msg.error(this, "Language " + language.getLanguageID() + " does not specify a valid " +
				GhidraLanguagePropertyKeys.EMULATE_INSTRUCTION_STATE_MODIFIER_CLASS);
			throw new RuntimeException(
				"Failed to instantiate " + classname + " for language " + language.getLanguageID(),
				e);
		}
	}

	public Language getLanguage() {
		return language;
	}

	/// Since the emulator can single step through individual pcode operations, the machine state
	/// may be halted in the \e middle of a single machine instruction, unlike conventional debuggers.
	/// This routine can be used to determine if execution is actually at the beginning of a machine
	/// instruction.
	/// \return \b true if the next pcode operation is at the start of the instruction translation
	public boolean isInstructionStart() {
		return executionState == EmulateExecutionState.STOPPED ||
			executionState == EmulateExecutionState.BREAKPOINT;
	}

	/**
	 * @return the current emulator execution state
	 */
	public EmulateExecutionState getExecutionState() {
		return executionState;
	}

	/// \return the currently executing machine address
	public Address getExecuteAddress() {
		return current_address;
	}

	/// \return the last address 
	public Address getLastExecuteAddress() {
		return last_execute_address;
	}

	public EmulateDisassemblerContext getNewDisassemblerContext() {
		return new EmulateDisassemblerContext(language, getContextRegisterValue());
	}

	/**
	 * Get length of instruction including any delay-slotted instructions.
	 * Must be called by emitPcode with lastPseudoInstructionBlock properly set.
	 * @param instr
	 * @return length of instruction in bytes for use in computing fall-through location
	 */
	private int getInstructionLength(Instruction instr) throws InstructionDecodeException {
		int length = instr.getLength();
		int delaySlots = instr.getDelaySlotDepth();
		while (delaySlots != 0) {
			try {
				Address nextAddr = instr.getAddress().addNoWrap(instr.getLength());
				Instruction nextInstr = lastPseudoInstructionBlock.getInstructionAt(nextAddr);
				if (nextInstr == null) {
					throw new InstructionDecodeException("Failed to parse delay slot instruction",
						nextAddr);
				}
				instr = nextInstr;
				length += instr.getLength();
				--delaySlots;
			}
			catch (AddressOverflowException e) {
				throw new InstructionDecodeException(
					"Failed to parse delay slot instruction at end of address space",
					instr.getAddress());
			}
		}
		return length;
	}

	private PcodeOp[] emitPcode(Address addr) throws InstructionDecodeException {

		memBuffer.setAddress(addr);
		pcode = null;
		pseudoInstruction = null;

		if (lastPseudoInstructionBlock != null) {
			pseudoInstruction = lastPseudoInstructionBlock.getInstructionAt(addr);
			if (pseudoInstruction != null) {
				instruction_length = getInstructionLength(pseudoInstruction);
				return pseudoInstruction.getPcode(false);
			}

			InstructionError error = lastPseudoInstructionBlock.getInstructionConflict();
			if (error != null && addr.equals(error.getInstructionAddress())) {
				throw new InstructionDecodeException(error.getConflictMessage(), addr);
			}

		}

		lastPseudoInstructionBlock =
			pseudoDisassembler.pseudoDisassembleBlock(memBuffer, nextContextRegisterValue, 1);
		nextContextRegisterValue = null;
		if (lastPseudoInstructionBlock != null) {
			pseudoInstruction = lastPseudoInstructionBlock.getInstructionAt(addr);
			if (pseudoInstruction != null) {
				instruction_length = getInstructionLength(pseudoInstruction);
				return pseudoInstruction.getPcode(false);
			}
			InstructionError error = lastPseudoInstructionBlock.getInstructionConflict();
			if (error != null && addr.equals(error.getInstructionAddress())) {
				throw new InstructionDecodeException(error.getConflictMessage(), addr);
			}
		}

		throw new InstructionDecodeException("unknown reason", addr);
	}

	/**
	 * Returns the current context register value.  The context value returned reflects
	 * its state when the previously executed instruction was 
	 * parsed/executed.  The context value returned will feed into the next 
	 * instruction to be parsed with its non-flowing bits cleared and
	 * any future context state merged in.  If no instruction has been executed,
	 * the explicitly set context will be returned.  A null value is returned
	 * if no context register is defined by the language or initial context has 
	 * not been set.
	 */
	public RegisterValue getContextRegisterValue() {
		Register contextReg = language.getContextBaseRegister();
		if (contextReg == null) {
			return null;
		}
		if (pseudoInstruction != null) {
			return pseudoInstruction.getRegisterValue(contextReg);
		}
		return nextContextRegisterValue;
	}

	/**
	 * Sets the context register value at the current execute address.
	 * The Emulator should not be running when this method is invoked.
	 * Only flowing context bits should be set, as non-flowing bits
	 * will be cleared prior to parsing on instruction.  In addition,
	 * any future context state set by the pcode emitter will
	 * take precedence over context set using this method.  This method
	 * is primarily intended to be used to establish the initial 
	 * context state.
	 * @param regValue
	 */
	public void setContextRegisterValue(RegisterValue regValue) {
		if (executionState != EmulateExecutionState.STOPPED &&
			executionState != EmulateExecutionState.BREAKPOINT) {
			throw new IllegalStateException("emulator is not STOPPED");
		}
		if (regValue != null) {
			Register reg = regValue.getRegister();
			if (!reg.isProcessorContext()) {
				throw new IllegalArgumentException("processor context register required");
			}
			if (!reg.isBaseRegister()) {
				regValue = regValue.getBaseRegisterValue();
				reg = regValue.getRegister();
				if (nextContextRegisterValue != null) {
					regValue = nextContextRegisterValue.combineValues(regValue);
				}
			}
			if (!reg.equals(language.getContextBaseRegister())) {
				throw new IllegalArgumentException("invalid processor context register");
			}
		}
		nextContextRegisterValue = regValue;
		lastPseudoInstructionBlock = null;
		pseudoInstruction = null;
	}

	/// Update the iterator into the current pcode cache, and if necessary, generate
	/// the pcode for the fallthru instruction and reset the iterator.
	public void fallthruOp() {
		current_op += 1;
		if (current_op >= pcode.length) {
			last_op = -1;
			setCurrentAddress(current_address.addWrap(instruction_length));
		}
	}

	public void executeConditionalBranch(PcodeOpRaw op) {
		Varnode condVar = op.getInput(1);
		boolean takeBranch = false;
		if (condVar.getSize() > 8) {
			takeBranch = !memstate.getBigInteger(condVar, false).equals(BigInteger.ZERO);
		}
		else {
			takeBranch = memstate.getValue(condVar) != 0;
		}
		if (takeBranch) {
			executeBranch(op);
		}
		else {
			fallthruOp();
		}
	}

	/// Since the full instruction is cached, we can do relative branches properly
	/// \param op is the particular branch op being executed
	public void executeBranch(PcodeOpRaw op) {
		Address destaddr = op.getInput(0).getAddress();
		if (destaddr.getAddressSpace().isConstantSpace()) {
			long id = destaddr.getOffset();
			id = id + current_op;
			current_op = (int) id;
			if (current_op == pcode.length) {
				fallthruOp();
			}
			else if ((current_op < 0) || (current_op >= pcode.length)) {
				throw new LowlevelError("Bad intra-instruction branch");
			}
		}
		else {
			setCurrentAddress(destaddr);
		}
	}

	/// Give instuctionStateModifier first shot at executing custom pcodeop,
	/// if not supported look for a breakpoint for the given user-defined op and invoke it.
	/// If it doesn't exist, or doesn't replace the action, throw an exception
	/// \param op is the particular user-defined op being executed
	public void executeCallother(PcodeOpRaw op) throws UnimplementedCallOtherException {
		if ((instructionStateModifier == null || !instructionStateModifier.executeCallOther(op)) &&
			!breaktable.doPcodeOpBreak(op)) {
			int userOp = (int) op.getInput(0).getOffset();
			String pcodeOpName = language.getUserDefinedOpName(userOp);
			throw new UnimplementedCallOtherException(op, pcodeOpName);
		}
		fallthruOp();
	}

	/// Set the current execution address and cache the pcode translation of the machine instruction
	/// at that address
	/// \param addr is the address where execution should continue
	public void setExecuteAddress(Address addr) {
		if (addr != null && addr.equals(current_address)) {
			return;
		}
		last_execute_address = null;
		setCurrentAddress(addr);
	}

	private void setCurrentAddress(Address addr) {
		current_address = addr;
		memstate.setValue(pcReg, current_address.getAddressableWordOffset());
		executionState = EmulateExecutionState.STOPPED;
		faultCause = null;
	}

	/// This routine executes an entire machine instruction at once, as a conventional debugger step
	/// function would do.  If execution is at the start of an instruction, the breakpoints are checked
	/// and invoked as needed for the current address.  If this routine is invoked while execution is
	/// in the middle of a machine instruction, execution is continued until the current instruction
	/// completes.
	public void executeInstruction(boolean stopAtBreakpoint, TaskMonitor monitor)
			throws CancelledException, LowlevelError, InstructionDecodeException {
		if (executionState == EmulateExecutionState.STOPPED) {
			if (last_execute_address == null && instructionStateModifier != null) {
				instructionStateModifier.initialExecuteCallback(this, current_address,
					nextContextRegisterValue);
			}
			if (breaktable.doAddressBreak(current_address) && stopAtBreakpoint) {
				executionState = EmulateExecutionState.BREAKPOINT;
				return;
			}
		}
		else if (executionState == EmulateExecutionState.FAULT) {
			// re-throw fault
			throw faultCause;
		}
		else if (executionState != EmulateExecutionState.BREAKPOINT) {
			// state is either INSTRUCTION_DECODE or EXECUTE
			throw new LowlevelError("Already executing");
		}
		try {
			executionState = EmulateExecutionState.INSTRUCTION_DECODE;
			if (language.numSections() == 0) {
				uniqueBank.clear(); // OK to clear if named sections and crossbuilds do not exist in language
			}
			pcode = emitPcode(current_address);
			last_execute_address = current_address;
			current_op = 0;
			if (pcode == null) {
				throw new InstructionDecodeException("Unexpected instruction pcode error",
					current_address);
			}
			executionState = EmulateExecutionState.EXECUTE;
			do {
				monitor.checkCanceled();
				executeCurrentOp();
			}
			while (executionState == EmulateExecutionState.EXECUTE);
			if (instructionStateModifier != null) {
				instructionStateModifier.postExecuteCallback(this, last_execute_address, pcode,
					last_op, current_address);
			}
		}
		catch (RuntimeException e) {
			faultCause = e;
			executionState = EmulateExecutionState.FAULT;
			throw e;
		}
	}

	/// \return the memory state object which this emulator uses
	public MemoryState getMemoryState() {
		return memstate;
	}

	/// This method executes a single pcode operation, the current one (returned by getCurrentOp()).
	/// The MemoryState of the emulator is queried and changed as needed to accomplish this.
	private void executeCurrentOp() throws LowlevelError {

		if (current_op >= pcode.length) {
			fallthruOp();
			return;
		}

		last_op = current_op;

		PcodeOp op = pcode[current_op];
		if (op.getOpcode() == PcodeOp.UNIMPLEMENTED) {
			throw new UnimplementedInstructionException(current_address);
		}

		PcodeOpRaw raw = new PcodeOpRaw(op);

		OpBehavior behave = raw.getBehavior();
		if (behave == null) {
			// unsupported opcode
			throw new LowlevelError(
				"Unsupported pcode op (opcode=" + op.getOpcode() + ", seq=" + op.getSeqnum() + ")");
		}
		if (behave instanceof UnaryOpBehavior) {
			UnaryOpBehavior unaryBehave = (UnaryOpBehavior) behave;
			Varnode in1var = op.getInput(0);
			Varnode outvar = op.getOutput();
			if (in1var.getSize() > 8 || outvar.getSize() > 8) {
				BigInteger in1 = memstate.getBigInteger(op.getInput(0), false);
				BigInteger out = unaryBehave.evaluateUnary(op.getOutput().getSize(),
					op.getInput(0).getSize(), in1);
				memstate.setValue(op.getOutput(), out);
			}
			else {
				long in1 = memstate.getValue(op.getInput(0));
				long out = unaryBehave.evaluateUnary(op.getOutput().getSize(),
					op.getInput(0).getSize(), in1);
				memstate.setValue(op.getOutput(), out);
			}
			fallthruOp();
		}
		else if (behave instanceof BinaryOpBehavior) {
			BinaryOpBehavior binaryBehave = (BinaryOpBehavior) behave;
			Varnode in1var = op.getInput(0);
			Varnode in2var = op.getInput(1);
			Varnode outvar = op.getOutput();
			if (in1var.getSize() > 8 || in2var.getSize() > 8 || outvar.getSize() > 8) {
				BigInteger in1 = memstate.getBigInteger(op.getInput(0), false);
				BigInteger in2 = memstate.getBigInteger(op.getInput(1), false);
				BigInteger out = binaryBehave.evaluateBinary(outvar.getSize(),
					op.getInput(0).getSize(), in1, in2);
				memstate.setValue(outvar, out);
			}
			else {
				long in1 = memstate.getValue(op.getInput(0));
				long in2 = memstate.getValue(op.getInput(1));
				long out = binaryBehave.evaluateBinary(outvar.getSize(), op.getInput(0).getSize(),
					in1, in2);
				memstate.setValue(outvar, out);
			}
			fallthruOp(); // All binary ops are fallthrus
		}
		else {
			switch (behave.getOpCode()) {
				case PcodeOp.LOAD:
					executeLoad(raw);
					fallthruOp();
					break;
				case PcodeOp.STORE:
					executeStore(raw);
					fallthruOp();
					break;
				case PcodeOp.BRANCH:
					executeBranch(raw);
					break;
				case PcodeOp.CBRANCH:
					executeConditionalBranch(raw);
					break;
				case PcodeOp.BRANCHIND:
					executeBranchind(raw);
					break;
				case PcodeOp.CALL:
					executeCall(raw);
					break;
				case PcodeOp.CALLIND:
					executeCallind(raw);
					break;
				case PcodeOp.CALLOTHER:
					executeCallother(raw);
					break;
				case PcodeOp.RETURN:
					executeBranchind(raw);
					break;
				case PcodeOp.MULTIEQUAL:
					executeMultiequal(raw);
					fallthruOp();
					break;
				case PcodeOp.INDIRECT:
					executeIndirect(raw);
					fallthruOp();
					break;
				default:
					throw new LowlevelError("Unsupported op (opcode=" + behave.getOpCode() + ")");
			}
		}
	}

	/// This routine performs a standard pcode \b load operation on the memory state
	/// \param op is the particular \e load op being executed
	public void executeLoad(PcodeOpRaw op) {

		AddressSpace space =
			addrFactory.getAddressSpace((int) op.getInput(0).getAddress().getOffset()); // Space to read from

		long offset = memstate.getValue(op.getInput(1)); // Offset to read from
		long byteOffset =
			space.truncateAddressableWordOffset(offset) * space.getAddressableUnitSize();

		Varnode outvar = op.getOutput();
		if (outvar.getSize() > 8) {
			BigInteger res =
				memstate.getBigInteger(space, byteOffset, op.getOutput().getSize(), false);
			memstate.setValue(outvar, res);
		}
		else {
			long res = memstate.getValue(space, byteOffset, op.getOutput().getSize());
			memstate.setValue(op.getOutput(), res);
		}
	}

	/// This routine performs a standard pcode \b store operation on the memory state
	/// \param op is the particular \e store op being executed
	public void executeStore(PcodeOpRaw op) {

		AddressSpace space =
			addrFactory.getAddressSpace((int) op.getInput(0).getAddress().getOffset()); // Space to store in

		long offset = memstate.getValue(op.getInput(1)); // Offset to store at
		long byteOffset =
			space.truncateAddressableWordOffset(offset) * space.getAddressableUnitSize();

		Varnode storedVar = op.getInput(2); // Value being stored
		if (storedVar.getSize() > 8) {
			BigInteger val = memstate.getBigInteger(storedVar, false);
			memstate.setValue(space, byteOffset, op.getInput(2).getSize(), val);
		}
		else {
			long val = memstate.getValue(storedVar);
			memstate.setValue(space, byteOffset, op.getInput(2).getSize(), val);
		}
	}

	/// This routine performs a standard pcode \b branch \b indirect operation on the memory state
	/// \param op is the particular \e branchind op being executed
	public void executeBranchind(PcodeOpRaw op) {
		long offset = memstate.getValue(op.getInput(0));
		AddressSpace space = op.getAddress().getAddressSpace();
		setCurrentAddress(space.getTruncatedAddress(offset, true));
	}

	/// This routine performs a standard pcode \b call operation on the memory state
	/// \param op is the particular \e call op being executed
	public void executeCall(PcodeOpRaw op) {
		setCurrentAddress(op.getInput(0).getAddress());
	}

	/// This routine performs a standard pcode \b call \b indirect operation on the memory state
	/// \param op is the particular \e callind op being executed
	public void executeCallind(PcodeOpRaw op) {
		executeBranchind(op); // same behavior as branch indirect
	}

	/// This kind of pcode op should not come up in ordinary emulation, so this routine
	/// throws an exception.
	/// \param op is the particular \e multiequal op being executed
	public void executeMultiequal(PcodeOpRaw op) {
		throw new LowlevelError("MULTIEQUAL appearing in unheritaged code?");
	}

	/// This kind of pcode op should not come up in ordinary emulation, so this routine
	/// throws an exception.
	/// \param op is the particular \e indirect op being executed
	public void executeIndirect(PcodeOpRaw op) {
		throw new LowlevelError("INDIRECT appearing in unheritaged code?");
	}

}
/** \page sleighAPIemulate The SLEIGH Emulator
    
  \section emu_overview Overview
  
  \b SLEIGH provides a framework for emulating the processors which have a specification written
   for them.  The key classes in this framework are:

  \b Key \b Classes
    - \ref MemoryState
    - \ref MemoryBank
    - \ref BreakTable
    - \ref BreakCallBack
    - \ref Emulate
    - \ref EmulatePcodeCache

  The MemoryState object holds the representation of registers and memory during emulation.  It
  understands the address spaces defined in the \b SLEIGH specification and how data is encoded
  in these spaces.  It also knows any register names defined by the specification, so these
  can be used to set or query the state of these registers naturally.

  The emulation framework can be tailored to a particular environment by creating \b breakpoint
  objects, which derive off the BreakCallBack interface.  These can be used to create callbacks
  during emulation that have full access to the memory state and the emulator, so any action
  can be accomplished.  The breakpoint callbacks can be designed to either augment or replace
  the instruction at a particular address, or the callback can be used to implement the action
  of a user-defined pcode op.  The BreakCallBack objects are managed by the BreakTable object,
  which takes care of invoking the callback at the appropriate time.

  The Emulate object serves as a basic execution engine.  Its main method is
  Emulate::executeCurrentOp() which executes a single pcode operation on the memory state.
  Methods exist for querying and setting the current execution address and examining the pcode
  op being executed.

  The main implementation of the Emulate interface is the EmulatePcodeCache object.  It uses
  SLEIGH to translate machine instructions as they are executed.  The currently executing instruction
  is translated into a cached sequence of pcode operations.  Additional methods allow this entire
  sequence to be inspected, and there is another stepping function which allows the emulator
  to be stepped through an entire machine instruction at a time.  The single pcode stepping methods
  are of course still available and the two methods can be used together without conflict.

  \section emu_membuild Building a Memory State

  Assuming the SLEIGH Translate object and the LoadImage object have already been built
  (see \ref sleighAPIbasic), the only required step left before instantiating an emulator
  is to create a MemoryState object.  The MemoryState object can be instantiated simply by
  passing the constructor the Translate object, but before it will work properly, you need
  to register individual MemoryBank objects with it, for each address space that might
  get used by the emulator.

  A MemoryBank is a representation of data stored in a single address space
  There are some choices for the type of MemoryBank associated with an address space.
  A MemoryImage is a read-only memory bank that gets its data from a LoadImage.  In order
  to make this writeable, or to create a writeable memory bank which starts with its bytes
  initialized to zero, you can use a MemoryPageOverlay.

  A MemoryPageOverlay overlays another memory bank as well.  But it implements writes to the bank
  by caching memory \e pages.  Any write creates an aligned page to hold the new data.  The class
  takes care of loading and filling in pages as needed.

  The Emulate constructor always adds a unique space memory bank using the UniqueMemoryBank, 
  the user needs not add this space.

  All the memory bank constructors need a page size, which is most relevant to the page implementation.  The
  null pointers passed in, in place of a real memory bank, indicate that the memory bank has no initial
  memory image. Once the memory banks are instantiated, they are registered with the memory state
  via the MemoryState::setMemoryBank() method.

  \section emu_breakpoints Breakpoints

  In order to provide behavior within the emulator beyond just what the core instruction emulation
  provides, the framework supports \b breakpoint classes.  A breakpoint is created by deriving a
  class from the BreakCallBack class and overriding either BreakCallBack::addressCallback() or
  BreakCallBack::pcodeCallback().  Here is an example of a breakpoint that implements a
  standard C library \e puts call an the x86 architecture.  When the breakpoint is invoked,
  a call to \e puts has just been made, so the stack pointer is pointing to the return address
  and the next 4 bytes on the stack are a pointer to the string being passed in.

  \code
    class PutsCallBack : public BreakCallBack {
    public:
      virtual bool addressCallback(const Address &addr);
    };

    bool PutsCallBack::addressCallback(const Address &addr)

    {
      MemoryState *mem = emulate->getMemoryState();
      uint1 buffer[256];
      uint4 esp = mem->getValue("ESP");
      AddrSpace *ram = mem->getTranslate()->getSpaceByName("ram");

      uint4 param1 = mem->getValue(ram,esp+4,4);
      mem->getChunk(buffer,ram,param1,255);

      cout << (char *)&buffer << endl;

      uint4 returnaddr = mem->getValue(ram,esp,4);
      mem->setValue("ESP",esp+8);
      emulate->setExecuteAddress(Address(ram,returnaddr));
  
      return true;			// This replaces the indicated instruction
    }
      
  \endcode

  Notice that the callback retrieves the value of the stack pointer by name.  Using this
  value, the string pointer is retrieved, then the data for the actual string is retrieved.
  After dumping the string to standard out, the return address is recovered and the \e return
  instruction is emulated by explicitly setting the next execution address to be the return value.

  \section emu_finalsetup Running the Emulator
  Here is an example of instantiating an EmulatePcodeCache object. A breakpoint is also instantiated
  and registered with the BreakTable.  

  \code
    ...
    Sleigh trans(&loader,&context);    // Instantiate the translator
    ...
    MemoryState memstate(&trans);      // Instantiate the memory state
    ...
    BreakTableCallBack breaktable(&trans);  // Instantiate a breakpoint table
    EmulatePcodeCache emulator(&trans,&memstate,&breaktable);  // Instantiate the emulator

    // Set up the initial stack pointer
    memstate.setValue("ESP",0xbffffffc);
    emulator.setExecuteAddress(Address(trans.getDefaultSpace(),0x1D00114));  // Initial execution address
    
    PutsCallBack putscallback;
    breaktable.registerAddressCallback(Address(trans.getDefaultSpace(),0x1D00130),&putscallback);

    AssemblyRaw assememit;
    for(;;) {
      Address addr = emulator.getExecuteAddress();
      trans.printAssembly(assememit,addr);
      emulator.executeInstruction();
    }

  \endcode

  Notice how the initial stack pointer and initial execute address is set up.  The breakpoint
  is registered with the BreakTable, giving it a specific address.  The executeInstruction method
  is called inside the loop, to actually run the emulator.  Notice that a disassembly of each
  instruction is printed after each step of the emulator.

  Other information can be examined from within this execution loop or in other tailored breakpoints.
  In particular, the Emulate::getCurrentOp() method can be used to retrieve the an instance
  of the currently executing pcode operation. From this starting point, you can examine the
  low-level objects:
    - PcodeOpRaw   and
    - VarnodeData
 */
