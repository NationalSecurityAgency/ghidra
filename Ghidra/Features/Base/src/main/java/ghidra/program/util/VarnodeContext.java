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
import java.util.Map.Entry;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.disassemble.DisassemblerContextImpl;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.pcode.VarnodeTranslator;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.util.Msg;
import ghidra.util.exception.*;

public class VarnodeContext implements ProcessorContext {

	public Address BAD_ADDRESS = null;

	public static final int BAD_SPACE_ID_VALUE = 0xffff;

	protected DisassemblerContextImpl offsetContext;
	protected DisassemblerContextImpl spaceContext;

	// holds temp memory values for computation
	protected Stack<HashMap<Varnode, Varnode>> memoryVals = new Stack<HashMap<Varnode, Varnode>>();

	// holds temp values for computation
	private HashMap<Varnode, Varnode> tempVals = new HashMap<>();
	protected HashMap<Varnode, Varnode> tempUniqueVals = new HashMap<>();
	protected boolean keepTempUniqueValues = false;

	protected HashSet<Varnode> clearVals = new HashSet<>();

	// locations where registers were last set to a constant value
	protected HashMap<Varnode, Address> lastSet = new HashMap<>();

	// all locations where a register was last explicitly set to a value, not just has the value
	protected HashMap<Varnode, AddressSet> allLastSet = new HashMap<>();

	protected Program program;
	protected VarnodeTranslator trans;  // translator for varnodes<-->registers

	protected Varnode[] retVarnodes = null;		// varnodes used to return values
	protected Varnode stackVarnode = null;    // varnode that represents the stack
	protected Register stackReg = null;
	private HashSet<String> validSymbolicStackNames = new HashSet<>(); // list of stack related register names

	protected static final NotFoundException notFoundExc = new NotFoundException();

	protected boolean hitDest = false;

	protected AddressFactory addrFactory = null;

	protected ProgramContext programContext;
	protected Address currentAddress;

	protected Instruction currentInstruction = null;

	public boolean debug = false;

	public VarnodeContext(Program program, ProgramContext programContext,
			ProgramContext spaceProgramContext) {
		this.program = program;

		// make a copy, because we could be making new spaces.
		this.addrFactory = new OffsetAddressFactory(program);

		BAD_ADDRESS = addrFactory.getAddress(getAddressSpace("BAD_ADDRESS_SPACE"), 0);

		this.programContext = programContext;

		offsetContext = new DisassemblerContextImpl(programContext);
		spaceContext = new DisassemblerContextImpl(spaceProgramContext);

		memoryVals.push(new HashMap<Varnode, Varnode>());

		setupValidSymbolicStackNames(program);

		// get the return value location for functions
		trans = new VarnodeTranslator(program);

		Language language = program.getLanguage();
		if (language instanceof SleighLanguage) {
			// Must preserve temp values if named pcode sections exist (i.e., cross-builds are used)
			keepTempUniqueValues = ((SleighLanguage) language).numSections() != 0;
		}
	}

	public void setDebug(boolean debugOn) {
		debug = debugOn;
	}

	public boolean getDebug() {
		return debug;
	}

	// Set the instruction to use for the current context
	public void setCurrentInstruction(Instruction instr) {
		currentInstruction = instr;
	}

	// get the current instruction, lookup it up if not set, just in case.
	public Instruction getCurrentInstruction(Address addr) {
		// if the current Instruction is set, assume that it is good
		if (currentInstruction != null) {
			return currentInstruction;
		}

		//   If not set, then look it up by address.
		currentInstruction = program.getListing().getInstructionContaining(addr);
		return currentInstruction;
	}

	@Override
	public Register getBaseContextRegister() {
		// Not applicable
		return null;
	}

	public void flowEnd(Address address) {
		offsetContext.flowEnd(address);
		spaceContext.flowEnd(address);
		currentAddress = null;
	}

	public void flowToAddress(Address fromAddr, Address toAddr) {
		// make sure address in same space as from, might be in an overlay
		toAddr = fromAddr.getAddressSpace().getOverlayAddress(toAddr);

		currentAddress = toAddr;
		offsetContext.flowToAddress(fromAddr, toAddr);
		spaceContext.flowToAddress(fromAddr, toAddr);
	}

	// return any known flowAddresses to the toAddr
	public Address[] getKnownFlowToAddresses(Address toAddr) {
		return offsetContext.getKnownFlowToAddresses(toAddr);
	}

	public void flowStart(Address fromAddr, Address toAddr) {
		// make sure address in same space as from, might be in an overlay
		toAddr = fromAddr.getAddressSpace().getOverlayAddress(toAddr);

		currentAddress = toAddr;

		this.lastSet = new HashMap<>();  // clear out any interim last sets...  rely on allLastSet now

		offsetContext.flowStart(fromAddr, toAddr);
		spaceContext.flowStart(fromAddr, toAddr);
	}

	public void copyToFutureFlowState(Address fromAddr, Address toAddr) {
		// make sure address in same space as from, might be in an overlay
		toAddr = fromAddr.getAddressSpace().getOverlayAddress(toAddr);

		offsetContext.copyToFutureFlowState(fromAddr, toAddr);
		spaceContext.copyToFutureFlowState(fromAddr, toAddr);
	}

	public boolean mergeToFutureFlowState(Address fromAddr, Address toAddr) {
		if (toAddr == null) {
			return false;
		}

		// make sure address in same space as from, might be in an overlay
		toAddr = fromAddr.getAddressSpace().getOverlayAddress(toAddr);

		ArrayList<RegisterValue> conflicts = offsetContext.mergeToFutureFlowState(fromAddr, toAddr);
		ArrayList<RegisterValue> spaceConflicts =
			spaceContext.mergeToFutureFlowState(fromAddr, toAddr);
		conflicts.addAll(spaceConflicts);

		if (conflicts.size() == 0) {
			return false;
		}

		// TODO: check if any of the conflicting values have a constant in them.
		//   if they do, continue processing this flow, if not, then no-need.
		//   someone else will pick up the constant value and flow it.
		boolean isWorthContinueing = false;
		for (RegisterValue registerValue : spaceConflicts) {
			if (!registerValue.hasValue()) {
				continue;
			}
			registerValue.getUnsignedValue();
			if (BigInteger.ZERO.equals(registerValue.getUnsignedValue())) {
				isWorthContinueing = true;
			}
		}

		// TODO: HACK alert.  If the size of the instruction is 1, can't really detect a flow conflict.
		//       This is the root of all evil with this storage tracking mechanism.
// TODO: for instruction size one, should we set flow context, now that contexts are stored
//       in separate states?
//		if (program.getLanguage().getInstructionAlignment() == 1) {
//			// only do on unalligned processors (x86)
//			Instruction instr = program.getListing().getInstructionAt(toAddr);
//			if (instr != null && instr.getLength() == 1) {
//				return false;
//			}
//		}
//		for (Iterator<Register> iterator = conflicts.iterator(); iterator.hasNext();) {
//
// TODO: do not use reg which appears same as initial input state 
//			Register reg = iterator.next();
//			offsetContext.setValue(reg, address, BigInteger.valueOf(reg.getOffset()));
//			spaceContext.setValue(reg, address,
//				BigInteger.valueOf(reg.getAddressSpace().getUniqueSpaceID()));
//		}
		return isWorthContinueing;
	}

	public void setFutureRegisterValue(Address address, RegisterValue regVal) {
		offsetContext.setFutureRegisterValue(address, regVal);
		// Don't set the space ID, since no spaceID means constant.
	}

	/**
	 * 
	 * @param targetFunc function to get a returning varnode for
	 * 
	 * NOTE: this only gets one, unless there is custom storage on the called function
	 *    there may be bonded ones in the default convention!
	 * 
	 * @return varnode that represents where functions place their return value
	 */
	public Varnode[] getReturnVarnode(Function targetFunc) {
		// TODO: This doesn't handle full bonded yet!
		PrototypeModel defaultCallingConvention =
			program.getCompilerSpec().getDefaultCallingConvention();

		if (targetFunc != null) {
			Varnode[] varnodes = null;
			if (targetFunc.hasCustomVariableStorage()) {
				Parameter retStorage = targetFunc.getReturn();
				varnodes = retStorage.getVariableStorage().getVarnodes();
				return varnodes;
			}
			PrototypeModel callingConvention = targetFunc.getCallingConvention();
			if (callingConvention != null && callingConvention != defaultCallingConvention) {
				int pointerSize = program.getDefaultPointerSize();
				DataType undefinedDataType = Undefined.getUndefinedDataType(pointerSize);
				VariableStorage retStorage =
					callingConvention.getReturnLocation(undefinedDataType, program);
				if (retStorage != null && retStorage.isValid()) {
					return retStorage.getVarnodes();
				}
			}
		}

		// no function, so get the default convention and use that.
		if (retVarnodes != null) {
			return retVarnodes;
		}

		// figure out which default register is used for return values, it must be assumed to be unknown upon return.
		// TODO: handle multiple bonded return values in default convention.  There is no way to do this now.
		DataType undefDT = Undefined.getUndefinedDataType(program.getDefaultPointerSize());
		VariableStorage retStore = defaultCallingConvention.getReturnLocation(undefDT, program);
		if (retStore != null && retStore.isValid()) {
			retVarnodes = retStore.getVarnodes();
		}
		else {
			retVarnodes = new Varnode[0];
		}
		return retVarnodes;
	}

	/**
	 * 
	 * @return Varnode that represents the stack register
	 */
	public Varnode getStackVarnode() {
		if (stackVarnode != null) {
			return stackVarnode;
		}

		Register stackRegister = getStackRegister();
		if (stackRegister == null) {
			return null;
		}

		stackVarnode = trans.getVarnode(stackRegister);
		return stackVarnode;
	}

	/**
	 * Sets up the valid names for stack register based spaces.
	 *   The symbolic stack spaces are named based on the register used to store things
	 *   into the symbolic space.
	 */
	private void setupValidSymbolicStackNames(Program program) {
		// figure out what register is used for stack values
		Register stackRegister = getStackRegister();

		validSymbolicStackNames.add(stackRegister.getName());
		List<Register> childRegisters = stackRegister.getChildRegisters();
		for (Register register : childRegisters) {
			validSymbolicStackNames.add(register.getName());
		}
	}

	/**
	 * Return true if this varnode is stored in the symbolic stack space
	 */
	public boolean isStackSymbolicSpace(Varnode varnode) {
		// symbolic spaces are off of a register, find the space
		AddressSpace regSpace = addrFactory.getAddressSpace(varnode.getSpace());

		return validSymbolicStackNames.contains(regSpace.getName());
	}

	/**
	 * 
	 * @return Register that represents the stack register
	 */
	public Register getStackRegister() {
		if (stackReg != null) {
			return stackReg;
		}

		// figure out what register is used for return values, it must be assumed to be unknown upon return.
		stackReg = program.getCompilerSpec().getStackPointer();
		if (stackReg == null) {
			return null;
		}
		Register stackBaseReg = stackReg.getParentRegister();
		if (stackBaseReg != null && stackBaseReg.getChildRegisters().size() == 1) {
			stackReg = stackBaseReg;
		}
		return stackReg;
	}

	public Varnode getValue(Varnode varnode, ContextEvaluator evaluator) throws NotFoundException {
		return getValue(varnode, false, evaluator);
	}

	public Varnode getValue(Varnode varnode, boolean signed, ContextEvaluator evaluator)
			throws NotFoundException {
		// for constant, return the constant value
		if (varnode.isConstant()) {
			return varnode;
		}
		Varnode rvnode = null;
		if (varnode.isUnique()) {
			rvnode = tempUniqueVals.get(varnode);
		}
		else {
			rvnode = tempVals.get(varnode);
		}
		if (rvnode != null) {
			if (debug) {
				Msg.info(this, "     Tmp " + varnode + "  =  " + rvnode);
			}
			if (rvnode.getAddress().equals(BAD_ADDRESS)) {
				throw notFoundExc;
			}
			return rvnode;
		}

		if (isRegister(varnode)) {
			Register reg = trans.getRegister(varnode);
			if (reg != null) {
				BigInteger bigVal = offsetContext.getValue(reg, signed);
				if (bigVal != null) {

					BigInteger spaceVal = getTranslatedSpaceValue(reg);
					rvnode = createVarnode(bigVal, spaceVal, varnode.getSize());
					if (rvnode == null) {
						throw notFoundExc;
					}
					if (!rvnode.getAddress().equals(BAD_ADDRESS)) {
						if (debug) {
							Msg.info(this, "  " + reg.getName() + " = " + print(rvnode));
						}

					}
					return rvnode;
				}
			}

			// TODO: should this return a new space at offset 0?
			return varnode;   // just return the register then, someone else will deal with it...
		}

		boolean isAddr = varnode.isAddress();
		boolean isSymbolicAddr = isSymbolicSpace(varnode.getSpace());
		if (isAddr || isSymbolicAddr) {
			// don't ever trust a load from memory location 0/-1 even if we wrote it, could be a null/flag
			// We can put references to that location, but don't trust values there even if we wrote them
			long varnodeOffset = varnode.getOffset();
			if (isAddr &&
				(varnodeOffset == 0 || varnodeOffset == 0xffffffff || varnodeOffset == -1L)) {
				throw notFoundExc;
			}

			// see if we wrote a value to memory here
			Varnode lvalue = getMemoryValue(varnode);
			if (lvalue != null) {
				if (debug) {
					Msg.info(this, "   " + varnode + " = " + print(lvalue));
				}
				if (isSymbolicSpace(lvalue.getSpace())) {
					if (debug) {
						Msg.info(this, "     out   " + varnode + " = " + print(lvalue));
					}
					throw notFoundExc;
				}
				// if this is an offset reference, ONLY allow it to be offset into the stack, no other register offset.
				// can't count on the offset staying the same.
				if (isSymbolicAddr) {
					// symbolic spaces are off of a register, find the space.
					AddressSpace regSpace = addrFactory.getAddressSpace(varnode.getSpace());
					// figure out what register is used for stack values 
					Register stackRegister = getStackRegister();
					if (!isStackSymbolicSpace(varnode)) {
						if (debug) {
							Msg.info(this,
								"Don't Trust value from  " + varnode + " = " + print(lvalue));
						}
						throw notFoundExc;
					}
					// don't allow a zero constant pulled from a symbolic space.
					if (lvalue.isConstant() && lvalue.getOffset() == 0) {
						throw notFoundExc;
					}
				}
				return lvalue;
			}

			// get the value from memory
			Address addr = varnode.getAddress();

			// if this reference belongs in this address space, must re-map it
			if (this.spaceContext.getAddress().getAddressSpace().isOverlaySpace()) {
				addr = this.spaceContext.getAddress().getAddressSpace().getOverlayAddress(addr);
			}

			if (isSymbolicAddr) {
				throw notFoundExc;
			}
			// if this is an offset address, find out if we can assume an address into memory			
//			if ( evaluator != null && isSymbolicSpacevarnode.getSpace()) ) {
//				Instruction instr = program.getListing().getInstructionContaining(offsetContext.getAddress());
//				Long lval = evaluator.unknownValue(this, instr, varnode);
//				if (lval != null) {
//					addr = this.program.getMinAddress().getNewAddress(lval.longValue()+varnode.getOffset());
//				}
//			}

			if (this.program.getListing().getInstructionContaining(addr) != null) {
				hitDest = true;
			}

			// don't trust any place that has an external reference off of it
			Reference[] refsFrom = program.getReferenceManager().getReferencesFrom(addr);
			if (refsFrom.length > 0 && refsFrom[0].isExternalReference()) {
				return varnode;
				// TODO: External address space is not a space yet!
				//Address external = refsFrom[0].getToAddress();
				//return createVarnode(external.getOffset(), external.getAddressSpace().getBaseSpaceID(), 0);
			}

			// If the memory is Writeable, then maybe don't trust it
			if (!isReadOnly(addr)) {
				// don't try to see how far away if it is in a different space.
				if (addr.getAddressSpace()
						.equals(this.spaceContext.getAddress().getAddressSpace())) {
					long diff = addr.subtract(this.spaceContext.getAddress());
					// if the value loaded is too far away, ask the evaluator if it should be trusted.
					if (diff < 0 || diff > 4096) {
						if (evaluator != null && !evaluator.allowAccess(this, addr)) {
							throw notFoundExc;
						}
					}
				}
			}
			int size = varnode.getSize();
			try {
				long value = 0;
				switch (size) {
					case 1:
						value = this.program.getMemory().getByte(addr) & 0xff;
						break;
					case 2:
						value = this.program.getMemory().getShort(addr) & 0xffff;
						break;
					case 4:
						value = this.program.getMemory().getInt(addr) & 0xffffffff;
						break;
					case 8:
						value = this.program.getMemory().getLong(addr);
						break;
					default:
						throw notFoundExc;
				}

				// Don't trust zero values loaded out of memory, even if it is read-only memory.
				if (value == 0) {
					throw notFoundExc;
				}

				if (signed) {
					value = (value << 8 * (8 - size)) >> 8 * (8 - size);
				}

				return createConstantVarnode(value, size);

			}
			catch (MemoryAccessException e) {
				// Don't care
			}
		}

		// is there an assumed value that should be returned for any unknown value?
		if (evaluator != null && !varnode.isAddress()) {
			Instruction instr = getCurrentInstruction(offsetContext.getAddress());
			Long lval = evaluator.unknownValue(this, instr, varnode);
			if (lval == null && !varnode.isUnique()) {
				return varnode;
			}
		}
		throw notFoundExc;
	}

	/**
	 * Search the value state stack for the first occurence of the set value
	 * 
	 * @param varnode varnode to search for a value
	 * @return first value found on stack, null otherwise
	 */
	protected Varnode getMemoryValue(Varnode varnode) {
		// traverse pushed memory value states until find value
		// if don't find, return null
		for (int i = memoryVals.size() - 1; i >= 0; i--) {
			HashMap<Varnode, Varnode> stateLayer = memoryVals.get(i);
			Varnode value = stateLayer.get(varnode);
			if (value != null) {
				return value;
			}
		}
		return null;
	}

	/**
	 * Put the value for the varnode on the top of the memory state stack
	 * 
	 * @param out varnode for the value
	 * @param value value to store for the varnode
	 */
	protected void putMemoryValue(Varnode out, Varnode value) {
		// put the value in the top memory value states
		memoryVals.peek().put(out, value);
	}

	/**
	 * get the translated stored space value.
	 * SpaceID is stored invert'ed so that the constants for subpieces will blend,
	 * but no other space will.
	 * 
	 * @return null space for constant space, real spaceID otherwise.
	 */
	private BigInteger getTranslatedSpaceValue(Register reg) {
		BigInteger spaceVal = spaceContext.getValue(reg, true);
		if (spaceVal != null) {
			spaceVal = spaceVal.not();  // only flip space bits that are non-zero
		}
		if (spaceVal != null && BigInteger.ZERO.equals(spaceVal)) {
			return null;
		}
		return spaceVal;
	}

	/**
	 * get the translated stored space value.
	 * SpaceID is stored invert'ed so that the constants for subpieces will blend,
	 * but no other space will.
	 * 
	 * @return null space for constant space, real spaceID otherwise.
	 */
	private BigInteger getTranslatedSpaceValue(Register reg, Address fromAddr, Address toAddr) {
		BigInteger spaceVal = spaceContext.getValue(reg, fromAddr, toAddr, true);
		if (spaceVal != null) {
			spaceVal = spaceVal.not();  // only flip space bits that are non-zero
		}
		if (spaceVal != null && BigInteger.ZERO.equals(spaceVal)) {
			return null;
		}
		return spaceVal;
	}

	/**
	 * Check if the symbol at the address is read_only.
	 * 
	 * @param addr - address of the symbol
	 * 
	 * @return true if the block is read_only, and there are no write references.
	 */
	protected boolean isReadOnly(Address addr) {
		boolean readonly = false;
		MemoryBlock block = program.getMemory().getBlock(addr);
		if (block != null) {
			readonly = !block.isWrite();
			// if the block says read-only, check the refs to the variable
			if (readonly) {
				ReferenceIterator refIter = program.getReferenceManager().getReferencesTo(addr);
				int count = 0;
				while (refIter.hasNext() && count < 100) {
					Reference ref = refIter.next();
					if (ref.getReferenceType().isWrite()) {
						readonly = false;
						break;
					}
					count++;
				}
			}
		}
		return readonly;
	}

	public Varnode createVarnode(long value, int spaceID, int size) {
		if (spaceID == 0) {
			return createConstantVarnode(value, size);
		}

		AddressSpace spc = addrFactory.getAddressSpace(spaceID);
		Address addr = null;

		if (spaceID == BAD_SPACE_ID_VALUE || spc == null ||
			spc.equals(BAD_ADDRESS.getAddressSpace())) {
			addr = BAD_ADDRESS;
		}
		else {
			addr = spc.getTruncatedAddress(value, true);
		}

		return new Varnode(addr, size);
	}

	public Varnode createConstantVarnode(long value, int size) {
		AddressSpace spc = addrFactory.getConstantSpace();
		Address addr = spc.getAddress(value);
		return new Varnode(addr, size);
	}

	public Varnode createBadVarnode() {
		return new Varnode(BAD_ADDRESS, 0);
	}

	public Varnode createVarnode(BigInteger bigVal, BigInteger spaceVal, int size) {
		if (size > 8) {
			return null; // varnodes only suport long offsets.
		}
		// no space, assume a constant
		if (spaceVal == null) {
			return createConstantVarnode(bigVal.longValue(), size);
		}

		// spaceID is only an int.  If we have a bigger value, then bad space...
		long spaceID = spaceVal.longValue();
		int intSpaceID = (int) spaceID;
		if (intSpaceID != spaceID) {
			return null;
		}
		return createVarnode(bigVal.longValue(), spaceVal.intValue(), size);

	}

	public void putValue(Varnode out, Varnode result, boolean mustClear) {
		if (out == null) {
			return;
		}

		if (out.isAddress() || isSymbolicSpace(out.getSpace())) {
			if (!isRegister(out)) {
				if (debug) {
					Msg.info(this, "      " + print(out) + " <- " + print(result) + " at " +
						offsetContext.getAddress());
				}

				Address location = offsetContext.getAddress();

				// put the location on both the lastSet, and all locations set
				addSetVarnodeToLastSetLocations(out, location);

				putMemoryValue(out, result);
				return;
			}
		}
		// don't ever store an unknown unique into a location
		if (result != null && result.isUnique()) {
			result = null;
		}
		if (out.isUnique()) {
			tempUniqueVals.put(out, result);
		}
		else {
			tempVals.put(out, result);
		}

		if (debug) {
			Msg.info(this, "      " + print(out) + " <- " + print(result) + " at " +
				offsetContext.getAddress());
		}
		if (mustClear) {
			clearVals.add(out);
		}
	}

	public boolean readExecutableCode() {
		return hitDest;
	}

	public void setReadExecutableCode() {
		hitDest = true;
	}

	public void clearReadExecutableCode() {
		hitDest = false;
	}

	/**
	 * Propogate any results that are in the value cache.
	 * 
	 * @param clearContext  true if the cache should be cleared.
	 *                      The propogation could be for flow purposes, and the
	 *                      processing of the instruction is finished, so it's effects should be kept.
	 */
	public void propogateResults(boolean clearContext) {
		Iterator<Entry<Varnode, Varnode>> iter = tempVals.entrySet().iterator();

		while (iter.hasNext()) {
			Entry<Varnode, Varnode> element = iter.next();

			Varnode node = element.getKey();
			if (!isRegister(node)) {
				continue;
			}

			Register reg = trans.getRegister(node);
			if (reg == null) {
				continue;
			}
			Varnode val = element.getValue();

			// if we must clear the values that should be unknown because of a decision stmt
			if (clearVals.contains(node)) {
				val = null;
			}
			if (val != null) {
				propogateValue(reg, node, val, offsetContext.getAddress());
			}
			else {
				if (debug) {
					Msg.info(this, "      " + reg.getName() + "<-" + " Clear");
				}
				clearRegister(reg);
			}
		}
		if (clearContext) {
			if (!keepTempUniqueValues) {
				tempUniqueVals = new HashMap<>();
			}
			tempVals = new HashMap<>();
			clearVals = new HashSet<>();
		}
	}

	public void propogateValue(Register reg, Varnode node, Varnode val, Address address) {
		if (debug) {
			Msg.info(this, "   " + reg.getName() + "<-" + val.toString() + " at " +
				offsetContext.getAddress());
		}

		addSetVarnodeToLastSetLocations(node, address);

		offsetContext.setValue(reg, BigInteger.valueOf(val.getOffset()));

		// set lastSet for any children locations
		List<Register> childRegisters = reg.getChildRegisters();
		for (Register register : childRegisters) {
			if (register.getMinimumByteSize() >= program.getDefaultPointerSize()) {
				node = getRegisterVarnode(register);

				addSetVarnodeToLastSetLocations(node, address);
			}
		}

		// use zero for constants, so space will blend!
		BigInteger bigSpaceID = BigInteger.ZERO;
		if (!val.isConstant()) {
			int spaceID = val.getSpace();
			bigSpaceID = BigInteger.valueOf(spaceID);
		}
		//   Otherwise, invert so they won't blend
		bigSpaceID = bigSpaceID.not();  // only flip space bits that are non-zero
		spaceContext.setValue(reg, bigSpaceID);
	}

	private void addSetVarnodeToLastSetLocations(Varnode node, Address address) {
		lastSet.put(node, address);
		AddressSet addressSet = allLastSet.get(node);
		if (addressSet == null) {
			addressSet = new AddressSet();
			allLastSet.put(node, addressSet);
		}
		addressSet.add(address);
	}

	/**
	 * return the location that this register was last set
	 * This is a transient thing, so it should only be used as a particular flow is being processed...
	 * 
	 * @param reg register to find last set location
	 * @param bval value to look for to differentiate set locations, null if don't care
	 * 
	 * @return address that the register was set.
	 */
	public Address getLastSetLocation(Register reg, BigInteger bval) {
		Varnode rvar = trans.getVarnode(reg);

		// lastSet is a set of single addresses, and gets overwritten each time the value is set
		Address lastSetAddr = lastSet.get(rvar);
		if (lastSetAddr != null) {
			return lastSetAddr;
		}

		// allLastSet is all the locations set for a given variable
		//   So that if the value isn't found in the lastSet, it can be quickly found
		AddressSet addressSet = allLastSet.get(rvar);
		if (addressSet == null) {
			return lastSetAddr;
		}

		AddressIterator addresses = addressSet.getAddresses(true);
		while (addresses.hasNext()) {
			Address address = addresses.next();

			RegisterValue rval = getRegisterValue(reg, Address.NO_ADDRESS, address);

			if (rval == null) {
				continue;
			}
			BigInteger rbval = rval.getUnsignedValue();
			if (bval.equals(rbval)) {
				lastSetAddr = address;
				break;
			}
		}
		return lastSetAddr;
	}

	// TODO unused parameter bval
	/**
	 * return the location that this varnode was last set
	 * This is a transient thing, so it should only be used as a particular flow is being processed...
	 * 
	 * @param rvar the register varnode
	 * @param bval this parameter is unused.
	 * @return address that the register was set.
	 */
	public Address getLastSetLocation(Varnode rvar, BigInteger bval) {

		Address lastSetAddr = lastSet.get(rvar);
		if (lastSetAddr != null) {
			return lastSetAddr;
		}

		return lastSetAddr;
	}

	public Varnode getVarnode(int spaceID, long offset, int size) {
		AddressSpace space = addrFactory.getAddressSpace(spaceID);
		Address target = space.getTruncatedAddress(offset, true);
		Varnode vt = new Varnode(target, size);
		return vt;
	}

	public long getConstant(Varnode vnode, ContextEvaluator evaluator) throws NotFoundException {
		if (!vnode.isConstant()) {
			if (evaluator == null) {
				throw notFoundExc;
			}

			// is there an assumed value that should be returned for any unknown value?
			Instruction instr = getCurrentInstruction(offsetContext.getAddress());
			Long lval = evaluator.unknownValue(this, instr, vnode);
			if (lval != null) {
				return lval.longValue();
			}
			throw notFoundExc;
		}

		return vnode.getOffset();
	}

	public Varnode getVarnode(Varnode space, Varnode offset, int size, ContextEvaluator evaluator)
			throws NotFoundException {
		int spaceID = offset.getSpace();
		long valbase = 0;
		if (isRegister(offset)) {
			Register reg = trans.getRegister(offset);
			if (reg == null) {
				throw notFoundExc;
			}
			spaceID = getAddressSpace(reg.getName());
			valbase = 0;
		}
		else if (offset.isConstant()) {
			valbase = offset.getOffset();
			spaceID = (int) space.getOffset();
		}
		else if (OffsetAddressFactory.isSymbolSpace(spaceID)) {
			if (evaluator == null) {
				throw notFoundExc;
			}

			// is there an assumed value that should be returned for any unknown value?
			Instruction instr = getCurrentInstruction(offsetContext.getAddress());
			Long lval = evaluator.unknownValue(this, instr, offset);
			valbase = offset.getOffset();
			if (lval != null) {
				spaceID = (int) space.getOffset();
				valbase += lval.longValue();
			}
		}
		else {
			throw notFoundExc;
		}
		return getVarnode(spaceID, valbase, size);
	}

	/**
	 * get the value of a register as a varnode (value, space, size)
	 * 
	 * @param reg  register to get value for
	 * @param fromAddr  from address
	 * @param toAddr to address
	 * @param signed  true if signed
	 * @return the register value or null
	 */
	public Varnode getRegisterVarnodeValue(Register reg, Address fromAddr, Address toAddr,
			boolean signed) {
		Varnode rvnode = null;

		if (reg == null) {
			return null;
		}

		BigInteger bigVal = offsetContext.getValue(reg, fromAddr, toAddr, signed);
		if (bigVal == null) {
			return null;
		}

		BigInteger spaceVal = getTranslatedSpaceValue(reg, fromAddr, toAddr);
		rvnode = createVarnode(bigVal, spaceVal, reg.getMinimumByteSize());
		if (rvnode == null) {
			return null;
		}
		if (!rvnode.getAddress().equals(BAD_ADDRESS)) {
			if (debug) {
				Msg.info(this, "     " + reg.getName() + " = " + print(rvnode));
			}
			return rvnode;
		}
		return null;
	}

	protected String print(Varnode rvnode) {
		if (rvnode == null) {
			return "<null>";
		}
		if (rvnode.isRegister()) {
			Register reg = this.trans.getRegister(rvnode);
			return (reg == null ? "<bad reg " + rvnode.getOffset() + ">" : reg.getName());
		}
		return rvnode.toString();
	}

// TODO: these are vague.  Should they be using context?
	public RegisterValue getRegisterValue(Register reg, Address toAddr) {
		return getRegisterValue(reg, Address.NO_ADDRESS, toAddr);
	}

	public RegisterValue getRegisterValue(Register reg, Address fromAddr, Address toAddr) {
		// only return constants
		RegisterValue regVal = offsetContext.getRegisterValue(reg, fromAddr, toAddr);
		if (regVal == null) {
			return null;
		}
		BigInteger spaceVal = getTranslatedSpaceValue(reg, fromAddr, toAddr);
		if (spaceVal != null) {
			if (addrFactory.getConstantSpace().getSpaceID() != spaceVal.intValue()) {
				return null;
			}
		}
		return regVal;
	}

	public AddressRangeIterator getRegisterValueAddressRanges(Register reg) {
		return programContext.getRegisterValueAddressRanges(reg);
	}

	public boolean hasValueOverRange(Register reg, BigInteger bval, AddressSet set) {
		return programContext.hasValueOverRange(reg, bval, set);
	}

	/**
	 * Copy the varnode with as little manipulation as possible.
	 * Try to keep whatever partical state there is intact if a real value isn't required.
	 * 
	 * @param out varnode to put it in
	 * @param in varnode to copy from.
	 * @param evaluator 
	 * @throws NotFoundException 
	 */
	public void copy(Varnode out, Varnode in, boolean mustClearAll, ContextEvaluator evaluator)
			throws NotFoundException {
		Varnode val1 = null;
		if (!in.isRegister() || !out.isRegister()) {
			// normal case easy get value, put value
			val1 = getValue(in, evaluator);
			putValue(out, val1, mustClearAll);
			return;
		}
		if (mustClearAll) {
			clearVals.add(out);
		}

		val1 = getValue(in, evaluator);
		putValue(out, val1, mustClearAll);
	}

	/**
	 * Add two varnodes together to get a new value
	 * This could create a new space and return a varnode pointed into that space
	 * 
	 * @param val1 first value
	 * @param val2 second value
	 * @return varnode that could be a constant, or an offset into a space
	 * 
	 * @throws NotFoundException if any constant is needed not known
	 */
	public Varnode add(Varnode val1, Varnode val2, ContextEvaluator evaluator)
			throws NotFoundException {

		// try to make the constant value the addend.
		if (val1.isConstant() || val1.isAddress()) {
			Varnode swap = val1;
			val1 = val2;
			val2 = swap;
		}
		int spaceID = val1.getSpace();
		long valbase = 0;
		if (isRegister(val1) && val1.equals(val2)) {
			// if both are registers, don't need to do extra
			// checking, adding a register and a register will fail.
		}
		else if (isRegister(val1)) {
			Register reg = trans.getRegister(val1);
			if (reg == null) {
				throw notFoundExc;
			}
			spaceID = getAddressSpace(reg.getName());
			valbase = 0;
			// check if evaluator wants to override unknown
			Instruction instr = getCurrentInstruction(offsetContext.getAddress());
			if (evaluator != null) {
				Long uval = evaluator.unknownValue(this, instr, val1);
				if (uval != null) {
					// 2nd value could be a constant, or a register, which would create an offset from reg
					valbase = uval.longValue();
					spaceID = val2.getSpace();
				}
			}
		}
		else if (val1.getAddress() == BAD_ADDRESS) {
// FIXME: Why both a "(bad address)" space and a "BAD_ADDRESS_SPACE" ?
			spaceID = getAddressSpace("(bad address)");
			valbase = 0;
			// check if evaluator wants to override unknown
			Instruction instr = getCurrentInstruction(offsetContext.getAddress());
			if (evaluator != null) {
				Long uval = evaluator.unknownValue(this, instr, val1);
				if (uval != null) {
					// 2nd value could be a constant, or a register, which would create an offset from reg
					valbase = uval.longValue();
					spaceID = val2.getSpace();
				}
			}
		}
		else if (val1.isConstant()) {
			valbase = val1.getOffset();
		}
		else if (isSymbolicSpace(spaceID)) {
			Instruction instr = getCurrentInstruction(offsetContext.getAddress());
			valbase = val1.getOffset();
			if (evaluator != null) {
				Long uval = evaluator.unknownValue(this, instr, val1);
				if (uval != null) {
//					if (val2.isRegister() && spaceID == getSymbolSpaceID(val2)) {
//						valbase += uval.longValue() * 2;
//						return createVarnode(valbase, val1.getSize());
//					}
//					else {
//						valbase = uval.longValue();
////    				valbase += uval.longValue();
////					spaceID = val2.getSpace();
//						return add(createVarnode(valbase, val1.getSize()), val2, evaluator);
//					}

					if (val2.isRegister()) {
						String spaceName = addrFactory.getAddressSpace(spaceID).getName();
						Register reg2 = trans.getRegister(val2);
						if (spaceName.equals(reg2.getName()) ||
							spaceName.startsWith(reg2.getName() + "-")) {
							// since this is essentially a multiply by two, and it is the same register
							//   just multiply the current offset by 2, since we really don't know
							//   the base register anyway...
							valbase += uval.longValue() * 2;
							return createConstantVarnode(valbase, val1.getSize());
						}
					}
					valbase = uval.longValue();
//    				valbase += uval.longValue();
//					spaceID = val2.getSpace();
					return add(createConstantVarnode(valbase, val1.getSize()), val2, evaluator);

				}
			}

		}
		else {
			throw notFoundExc;
		}
		long result = (valbase + getConstant(val2, null)) &
			(0xffffffffffffffffL >>> ((8 - val1.getSize()) * 8));
		return createVarnode(result, spaceID, val1.getSize());
	}

	protected boolean isRegister(Varnode varnode) {
		return varnode.isRegister() || trans.getRegister(varnode) != null;
	}

	public Varnode and(Varnode val1, Varnode val2, ContextEvaluator evaluator)
			throws NotFoundException {
		if (val1.equals(val2)) {
			return val1;
		}
		if (val1.isConstant() || val1.isAddress()) {
			Varnode swap = val1;
			val1 = val2;
			val2 = swap;
		}
		int spaceID = val1.getSpace();
		long valbase = 0;
		if (isRegister(val1)) {
			Register reg = trans.getRegister(val1);
			if (reg == null) {
				throw notFoundExc;
			}
			spaceID = getAddressSpace(reg.getName());
			valbase = 0;
		}
		else if (val1.isConstant()) {
			valbase = val1.getOffset();
		}
		else if (isSymbolicSpace(spaceID)) {
			valbase = val1.getOffset();
			if (val2.isConstant()) {
				long val2Const = getConstant(val2, null);
				// check if the value could be an alignment mask from an unknown register
				if (((val2Const >> 1) << 1) != val2Const && ((val2Const >> 2) << 2) != val2Const) {
					throw notFoundExc;
				}
			}
		}
		else {
			throw notFoundExc;
		}
		long result = (valbase & getConstant(val2, null)) &
			(0xffffffffffffffffL >>> ((8 - val1.getSize()) * 8));
		return createVarnode(result, spaceID, val1.getSize());
	}

	public Varnode or(Varnode val1, Varnode val2, ContextEvaluator evaluator)
			throws NotFoundException {
		if (val1.equals(val2)) {
			return val1;
		}

		if (val1.isConstant() || val1.isAddress()) {
			Varnode swap = val1;
			val1 = val2;
			val2 = swap;
		}
		long val2Const = getConstant(val2, null);
		if (val2Const == 0) {
			return val1;
		}
		long lresult = getConstant(val1, evaluator) | val2Const;
		return createConstantVarnode(lresult, val1.getSize());
	}

	public Varnode left(Varnode val1, Varnode val2, ContextEvaluator evaluator)
			throws NotFoundException {
		long lresult = getConstant(val1, evaluator) << getConstant(val2, evaluator);
		lresult = lresult & (0xffffffffffffffffL >>> ((8 - val1.getSize()) * 8));
		Varnode result = createConstantVarnode(lresult, val1.getSize());
		return result;
	}

	// This is bad since registers could have multiple associated spaces 
//	private int getSymbolSpaceID(Varnode val) {
//		Register reg = trans.getRegister(val);
//		if (reg == null) {
//			return -1;
//		}
//		return getAddressSpace(reg.getName());
//	}

	public int getAddressSpace(String name) {
		int spaceID;
		AddressSpace regSpace = addrFactory.getAddressSpace(name);
		if (regSpace == null) {
			regSpace = ((OffsetAddressFactory) addrFactory).createNewOffsetSpace(name);
		}
		spaceID = regSpace.getSpaceID();
		return spaceID;
	}

	/**
	 * Subtract two varnodes to get a new value
	 * This could create a new space and return a varnode pointed into that space
	 * 
	 * @param val1 first value
	 * @param val2 second value
	 * @return varnode that could be a constant, or an offset into a space
	 * 
	 * @throws NotFoundException if any constant is needed not known
	 */
	public Varnode subtract(Varnode val1, Varnode val2, ContextEvaluator evaluator)
			throws NotFoundException {
		// degenerate case, don't need to know the value
		if (val1.equals(val2)) {
			return createVarnode(0, addrFactory.getConstantSpace().getSpaceID(), val1.getSize());
		}
		int spaceID = val1.getSpace();
		long valbase = 0;
		if (val1.isConstant()) {
			valbase = val1.getOffset();
		}
		else if (isRegister(val1)) {
			Register reg = trans.getRegister(val1);
			if (reg == null) {
				throw notFoundExc;
			}
			spaceID = getAddressSpace(reg.getName());
			valbase = 0;
		}
		else if (isSymbolicSpace(spaceID)) {
			Instruction instr = getCurrentInstruction(offsetContext.getAddress());
			valbase = val1.getOffset();
			if (evaluator != null) {
				Long uval = evaluator.unknownValue(this, instr, val1);
				if (uval != null) {
					valbase = uval.longValue();
//					valbase += uval.longValue();
//					spaceID = val2.getSpace();
					return add(createConstantVarnode(valbase, val1.getSize()), val2, evaluator);
				}
			}

		}
		else {
			throw notFoundExc;
		}
		long result = (valbase - getConstant(val2, null)) &
			(0xffffffffffffffffL >>> ((8 - val1.getSize()) * 8));
		return createVarnode(result, spaceID, val1.getSize());
	}

	/**
	 * Extend a constant value if it can be extended.
	 * 
	 * @param out varnode to extend into (for size)
	 * @param in varnode value to extend the size
	 * @return
	 * @throws NotFoundException
	 */
	public Varnode extendValue(Varnode out, Varnode[] in, boolean signExtend,
			ContextEvaluator evaluator) throws NotFoundException {
		Varnode vnodeVal;

		vnodeVal = getValue(in[0], signExtend, evaluator);

		if (vnodeVal.isConstant() && in[0].getSize() < out.getSize()) {
// TODO: Is there a better way to do this - it was not sign-extending temp values before
			if (vnodeVal.getSize() <= 8) {
				Scalar sVal = new Scalar(8 * vnodeVal.getSize(), vnodeVal.getOffset(), signExtend);
				vnodeVal = createConstantVarnode(sVal.getValue(), out.getSize());
			}
			else {
				// too big anyway,already extended as far as it will go.
				vnodeVal = createConstantVarnode(vnodeVal.getOffset(), out.getSize());
			}
		}
		else if (vnodeVal.isRegister() && vnodeVal.getSize() < out.getSize()) {
			Register reg = getRegister(vnodeVal);
			if (reg == null) {
				throw notFoundExc;
			}
			int spaceID = getAddressSpace(reg.getName());
			vnodeVal = createVarnode(0, spaceID, out.getSize());
		}
		return vnodeVal;
	}

	@Override
	public void clearRegister(Register reg) {
		if (reg == null) {
			return;
		}
		// set the register to some other value to flush it, then clear it!
//		 BigInteger cval;
//		 cval = offsetContext.getValue(reg, false);
//		 if (cval != null) {
//			 offsetContext.setValue(reg, cval.negate());
//			 cval = spaceContext.getValue(reg, false);
//			 if (cval != null) {
//				 spaceContext.setValue(reg, cval.negate());
//			 }
//		 }
//		 offsetContext.clearRegister(reg);
//		 spaceContext.clearRegister(reg);
//		 offsetContext.setValue(reg, BigInteger.valueOf(Address.NO_ADDRESS.getOffset()));
//		 spaceContext.setValue(reg, BigInteger.valueOf(Address.NO_ADDRESS.getAddressSpace().getUniqueSpaceID()));

		// Start new register space
		String spaceName = reg.getName() + "-" + currentAddress;
		int spaceId = getAddressSpace(spaceName);
		offsetContext.setValue(reg, BigInteger.ZERO);
		// bad value space bits need to be flipped
		BigInteger bigSpaceID = BigInteger.valueOf(spaceId).not();
		spaceContext.setValue(reg, bigSpaceID);
	}

	@Override
	public Register getRegister(String name) {
		return offsetContext.getRegister(name);
	}

	@Override
	public RegisterValue getRegisterValue(Register register) {
		Varnode regVnode = trans.getVarnode(register);
		try {
			Varnode value = this.getValue(regVnode, false, null);
			if (value.isConstant()) {
				return new RegisterValue(register, BigInteger.valueOf(value.getOffset()));
			}
		}
		catch (NotFoundException e) {
			// Don't care, turn into a null register
		}
		return null;
	}

	public Varnode getRegisterVarnodeValue(Register register) {
		Varnode regVnode = trans.getVarnode(register);
		try {
			Varnode value = this.getValue(regVnode, false, null);
			return value;
		}
		catch (NotFoundException e) {
			// Don't care, turn into a null varnode.
		}
		return null;
	}

	public Varnode getRegisterVarnode(Register register) {
		return trans.getVarnode(register);
	}

	/**
	 * Return a register given a varnode
	 */
	public Register getRegister(Varnode vnode) {
		return trans.getRegister(vnode);
	}

	@Override
	public List<Register> getRegisters() {
		return offsetContext.getRegisters();
	}

	@Override
	public BigInteger getValue(Register register, boolean signed) {
		Varnode regVnode = trans.getVarnode(register);
		try {
			Varnode value = this.getValue(regVnode, signed, null);
			if (value.isConstant()) {
				return BigInteger.valueOf(value.getOffset());
			}
		}
		catch (NotFoundException e) {
			// Don't care, turn into a null value
		}
		return null;
	}

	@Override
	public boolean hasValue(Register register) {
		return offsetContext.hasValue(register);
	}

	@Override
	public void setRegisterValue(RegisterValue value) {
		setValue(value.getRegister(), value.getUnsignedValue());
	}

	@Override
	public void setValue(Register register, BigInteger value) {
		Varnode regVnode = trans.getVarnode(register);
		putValue(regVnode, createConstantVarnode(value.longValue(), regVnode.getSize()), false);
		propogateResults(false);
	}

	public boolean isSymbol(Varnode node) {
		return isSymbolicSpace(node.getAddress().getAddressSpace());
	}

	public boolean isSymbolicSpace(AddressSpace space) {
		int spaceID = space.getSpaceID();
		return OffsetAddressFactory.isSymbolSpace(spaceID);
	}

	public boolean isSymbolicSpace(int spaceID) {
		return OffsetAddressFactory.isSymbolSpace(spaceID);
	}

	public void pushMemState() {
		memoryVals.push(new HashMap<Varnode, Varnode>());
	}

	public void popMemState() {
		memoryVals.pop();
	}
}

class OffsetAddressFactory extends DefaultAddressFactory {

	OffsetAddressFactory(Program program) {
		// We are only calling super with the address spaces from the language first, and then
		// following up to explicitly add more spaces due to the treatment of memory address
		// spaces by DefaultAddressFactory when constructed vs. when added later.
		// If there is more than one memory address space (e.g., TYPE_RAM, TYPE_CODE, or
		// TYPE_OTHER), then addresses are output with the space name prefix, which we do not want.
		super(program.getLanguage().getAddressFactory().getAllAddressSpaces(),
			program.getLanguage().getAddressFactory().getDefaultAddressSpace());
		for (AddressSpace space : program.getAddressFactory().getAllAddressSpaces()) {
			if (space.isLoadedMemorySpace() && getAddressSpace(space.getName()) == null) {
				try {
					addAddressSpace(space);
				}
				catch (DuplicateNameException e) {
					throw new AssertException("Duplicate name should not occur.");
				}
			}
		}
	}

	private int getNextUniqueID() {
		int maxID = 0;
		AddressSpace[] spaces = getAllAddressSpaces();
		for (AddressSpace space : spaces) {
			maxID = Math.max(maxID, space.getUnique());
		}
		return maxID + 1;
	}

	public AddressSpace createNewOffsetSpace(String name) {
		AddressSpace space = null;
		try {
			space = new GenericAddressSpace(name, this.getConstantSpace().getSize(),
				AddressSpace.TYPE_SYMBOL, getNextUniqueID());
			super.addAddressSpace(space);
		}
		catch (DuplicateNameException e) {
			space = getAddressSpace(name);
		}
		return space;
	}

	public static boolean isSymbolSpace(int spaceID) {
		int type = AddressSpace.ID_TYPE_MASK & spaceID;
		return (type == AddressSpace.TYPE_SYMBOL);
	}

}
