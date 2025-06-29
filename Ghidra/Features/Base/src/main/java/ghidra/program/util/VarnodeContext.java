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

import javax.help.UnsupportedOperationException;

import org.apache.commons.lang3.ArrayUtils;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
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
import ghidra.util.exception.AssertException;
import ghidra.util.exception.DuplicateNameException;


public class VarnodeContext implements ProcessorContext {

	// trace stack for the saved states during forks of execution flow
	// the traces are poped off the stack to restart a previous flow
	protected Stack<Stack<HashMap<Address, Varnode>>> memTraces =
		new Stack<Stack<HashMap<Address, Varnode>>>();
	protected Stack<Stack<HashMap<Address, Varnode>>> regTraces =
		new Stack<Stack<HashMap<Address, Varnode>>>();
	protected Stack<Stack<HashMap<Address, Varnode>>> uniqueTraces =
			new Stack<Stack<HashMap<Address, Varnode>>>();
	protected Stack<HashMap<Varnode, Address>> lastSetSaves =
		new Stack<HashMap<Varnode, Address>>();

	HashMap<Address, ArrayList<Address>> flowToFromLists = new HashMap<>();
	
	//
	// Trace record used to keep access flow state stack at beginning and end of each instruction
	//
	record TraceDepthState(int depth, Stack<HashMap<Address, Varnode>> state) { }

	// references to stack based traces at the beginning and ending of each instruction
	HashMap <Address, TraceDepthState> addrStartState = new HashMap<>();
	HashMap <Address, TraceDepthState> addrEndState = new HashMap<>();

	// current flow memory values for computation
	protected Stack<HashMap<Address, Varnode>> memoryVals = new Stack<HashMap<Address, Varnode>>();

	// current flow register values for computation
	protected Stack<HashMap<Address, Varnode>> regVals = new Stack<HashMap<Address, Varnode>>();

	// current flow unique values for computation
	protected Stack<HashMap<Address, Varnode>> uniqueVals = new Stack<HashMap<Address, Varnode>>();
	
	// temp values for individual instruction computation before being merged into
	// the end flow state for an instruction
	private HashMap<Address, Varnode> tempVals = new HashMap<>();
	protected HashMap<Address, Varnode> tempUniqueVals = new HashMap<>();
	protected boolean keepTempUniqueValues = false;

	// Values that must be cleared from final instruction flow state
	protected HashSet<Varnode> clearVals = new HashSet<>();

	// locations where registers were last set to a constant value
	protected HashMap<Varnode, Address> lastSet = new HashMap<>();

	// all locations where a register was last explicitly set to a value, not just has the value
	protected HashMap<Varnode, AddressSet> allLastSet = new HashMap<>();

	protected Program program;
	protected VarnodeTranslator trans;  // translator for varnodes<-->registers

	protected Varnode[] retVarnodes = null;		// varnodes used to return values

	protected Varnode[] killedVarnodes = null;  // varnodes killed by default calling convention

	protected Varnode stackVarnode = null;    // varnode that represents the stack
	protected Register stackReg = null;
	private HashSet<String> validSymbolicStackNames = new HashSet<>(); // list of stack related register names

	public final Address BAD_ADDRESS;

	public final Varnode BAD_VARNODE;

	private final int BAD_OFFSET_SPACEID;   // address space for offsets from an unknown value;

	static final String SUSPECT_CONST_NAME = "SuspectConst";
	private final int SUSPECT_OFFSET_SPACEID;   // address space for suspect constant values
	public final Address SUSPECT_ZERO_ADDRESS;

	public final int BAD_SPACE_ID_VALUE;

	Varnode byteVarnodes[] = new Varnode[256];

	protected boolean hitDest = false;
	
	protected int pointerBitSize;

	protected AddressFactory addrFactory = null;

	protected ProgramContext programContext;
	protected Address currentAddress;

	protected Instruction currentInstruction = null;

	boolean isBE = false;
	
	boolean trackStartEndState = false;

	public boolean debug = false;

	public VarnodeContext(Program program, ProgramContext programContext,
			ProgramContext spaceProgramContext, boolean trackStartEndState) {
		this.program = program;
		this.isBE = program.getLanguage().isBigEndian();
		this.trackStartEndState = trackStartEndState;

		// make a copy, because we could be making new spaces.
		this.addrFactory = new OffsetAddressFactory(program);
		
		pointerBitSize = program.getDefaultPointerSize() * 8;

		BAD_ADDRESS = addrFactory.getAddress(getAddressSpace("BAD_ADDRESS_SPACE",pointerBitSize), 0);
		BAD_SPACE_ID_VALUE = BAD_ADDRESS.getAddressSpace().getSpaceID();

		BAD_OFFSET_SPACEID = getAddressSpace("(Bad Address Offset)",pointerBitSize);

		BAD_VARNODE = createBadVarnode();

		/* Suspect constants act like constants, but are in a SuspectConst
		 * address space instead of the constant space.
		 */
		SUSPECT_ZERO_ADDRESS = addrFactory.getAddress(getAddressSpace(SUSPECT_CONST_NAME,pointerBitSize), 0);
		SUSPECT_OFFSET_SPACEID = SUSPECT_ZERO_ADDRESS.getAddressSpace().getSpaceID();

		this.programContext = programContext;

		memoryVals.push(new HashMap<Address, Varnode>());
		regVals.push((new HashMap<Address, Varnode>()));
		uniqueVals.push(new HashMap<Address, Varnode>());

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

	// return any known flowAddresses to the toAddr
	static final Address[] emptyAddrArr = new Address[0];

	public Address[] getKnownFlowToAddresses(Address toAddr) {

		ArrayList<Address> arrayList = flowToFromLists.get(toAddr);
		if (arrayList == null) {
			return emptyAddrArr;
		}
		return arrayList.toArray(emptyAddrArr);
	}

	/**
	 * Records flow from/to basic blocks, or non-fallthru flow
	 */
	public void flowToAddress(Address fromAddr, Address toAddr) {
		// make sure address in same space as from, might be in an overlay
		toAddr = fromAddr.getAddressSpace().getOverlayAddress(toAddr);
		currentAddress = toAddr;

		ArrayList<Address> arrayList = flowToFromLists.get(toAddr);
		if (arrayList == null) {
			arrayList = new ArrayList<Address>();
			flowToFromLists.put(fromAddr, arrayList);
		}
		arrayList.add(fromAddr);
	}
	
	/**
	 * Start flow at an address, recording any initial state for the current instruction
	 */
	public void flowStart(Address toAddr) {
		currentAddress = toAddr;
		
		if (trackStartEndState) {
			addrStartState.put(toAddr,new TraceDepthState(regVals.size(),regVals));
			regVals.push(new HashMap<Address, Varnode>());
		}
	}
	
	/**
	 * End flow and save any necessary end flow state for the current instruction at address
	 */
	public void flowEnd(Address address) {
		if (trackStartEndState) {
			addrEndState.put(address,new TraceDepthState(regVals.size(),regVals));
		}
		currentAddress = null;
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
	 * @param targetFunc function to get killed varnodes for
	 * 
	 * NOTE: this removes the return varnodes so they aren't duplicated
	 * 
	 * @return varnode that represents where functions place their return value
	 */
	public Varnode[] getKilledVarnodes(Function targetFunc) {
		// TODO: This doesn't handle full bonded yet!
		PrototypeModel defaultCallingConvention =
			program.getCompilerSpec().getDefaultCallingConvention();

		if (targetFunc != null) {
			// TODO handle custom calling convention killed by call when supported
			PrototypeModel callingConvention = targetFunc.getCallingConvention();

			if (callingConvention != null) {
				return callingConvention.getKilledByCallList();
			}
		}

		// no function, so get the default convention and use that.
		if (killedVarnodes != null) {
			return killedVarnodes;
		}

		killedVarnodes = defaultCallingConvention.getKilledByCallList();

		// clean return varnodes out of list
		Varnode[] returnVarnodes = getReturnVarnode(null);
		ArrayList<Varnode> list = new ArrayList<Varnode>();
		for (Varnode varnode : killedVarnodes) {
			if (!ArrayUtils.contains(returnVarnodes, varnode)) {
				list.add(varnode);
			}
		}
		killedVarnodes = list.toArray(new Varnode[list.size()]);

		return killedVarnodes;
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
		if (stackRegister == null) {
			return;
		}

		validSymbolicStackNames.add(stackRegister.getName());
		List<Register> childRegisters = stackRegister.getChildRegisters();
		for (Register register : childRegisters) {
			validSymbolicStackNames.add(register.getName());
		}
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

		return stackReg;
	}

	public Varnode getValue(Varnode varnode, ContextEvaluator evaluator) {
		if (varnode == null) {
			return null;
		}
		return getValue(varnode, false, evaluator);
	}

	public Varnode getValue(Varnode varnode, boolean signed, ContextEvaluator evaluator) {
		if (varnode == null) {
			return null;
		}
		// for constant, return the constant value
		if (isConstant(varnode)) {
			return varnode;
		}
		Varnode rvnode = null;
		if (varnode.isUnique()) {
			rvnode = getMemoryValue(tempUniqueVals,varnode,signed);
			if (rvnode == null && keepTempUniqueValues) {
				rvnode = getMemoryValue(uniqueVals,0,varnode,signed);
			}
		}
		else {
			rvnode = getMemoryValue(tempVals, varnode, signed);
		}
		if (rvnode != null) {
			if (debug) {
				Msg.info(this, "     Tmp " + varnode + "  =  " + rvnode);
			}
			if (rvnode.getAddress().equals(BAD_ADDRESS)) {
				return null;
			}
			return rvnode;
		}

		if (isRegister(varnode)) {
			Varnode value = getMemoryValue(this.regVals, 0, varnode, signed);
			if (value != null) {
				int spaceVal = value.getSpace();

				if (value.isConstant()) {
					long lvalue = value.getOffset();
					int size = value.getSize();

					// -1 and zero constants pulled from a register are suspect
					if ((value.getOffset() == -1 || value.getOffset() == 0)) {
						spaceVal = SUSPECT_OFFSET_SPACEID;
						value = createVarnode(lvalue, spaceVal, size);
					}
					else if (signed) {
						lvalue = (lvalue << 8 * (8 - size)) >> 8 * (8 - size);
						value = createVarnode(lvalue, spaceVal, size);
					}
				}
				rvnode = value;

				if (debug) {
					Register reg = trans.getRegister(varnode);
					String name = (reg != null ? reg.getName() : varnode.toString());
					Msg.info(this, "  " + name + " = " + print(rvnode));
				}

				// value is bad, just return original, someone else will deal with it
				if (!rvnode.getAddress().equals(BAD_ADDRESS)) {
					return rvnode;
				}
			}

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
				return null;
			}

			// see if we wrote a value to memory here
			Varnode lvalue = getMemoryValue(varnode, signed);
			if (lvalue != null) {
				if (debug) {
					Msg.info(this, "   " + varnode + " = " + print(lvalue));
				}
				// if this is an offset reference, ONLY allow it to be offset into the stack, no other register offset.
				// can't count on the offset staying the same.
				if (isSymbolicAddr) {
					// don't allow a zero/-1 constant pulled from a symbolic space.
					if (isConstant(lvalue) &&
						(lvalue.getOffset() == 0 || lvalue.getOffset() == -1)) {
						return null;
					}
				}
				return lvalue;
			}

			// get the value from memory
			Address addr = varnode.getAddress();

			// if this reference belongs in this address space, must re-map it
			if (currentAddress.getAddressSpace().isOverlaySpace()) {
				addr = currentAddress.getAddressSpace().getOverlayAddress(addr);
			}

			if (isSymbolicAddr) {
				return null;
			}

			if (this.program.getListing().getInstructionContaining(addr) != null) {
				hitDest = true;
			}

			// don't trust any place that has an external reference off of it
			Reference[] refsFrom = program.getReferenceManager().getReferencesFrom(addr);
			if (refsFrom.length > 0 && refsFrom[0].isExternalReference()) {
				Address external = refsFrom[0].getToAddress();
				return createVarnode(external.getOffset(), external.getAddressSpace().getSpaceID(), 0);
			}

			// If the memory is Writeable, then maybe don't trust it
			boolean isReadOnly = isReadOnly(addr);
			if (!isReadOnly) {
				// don't try to see how far away if it is in a different space.
				if (addr.getAddressSpace()
						.equals(currentAddress.getAddressSpace())) {
					long diff = addr.subtract(currentAddress);
					// if the value loaded is too far away, ask the evaluator if it should be trusted.
					if (diff < 0 || diff > 4096) {
						if (evaluator != null && !evaluator.allowAccess(this, addr)) {
							return null;
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
						return null;
				}

				// Don't trust zero values loaded out of memory, even if it is read-only memory.
				if (value == 0) {
					return null;
				}

				if (signed) {
					value = (value << 8 * (8 - size)) >> 8 * (8 - size);
				}

				// constants pulled from memory are suspect
				// unless memory is readonly, or given access from evaluator (trustWriteAccess)
				int spaceId = SUSPECT_OFFSET_SPACEID;
				if (isReadOnly || (evaluator != null && evaluator.allowAccess(this, addr))) {
					spaceId = 0;
				}
				return createVarnode(value, spaceId, size);

			}
			catch (MemoryAccessException e) {
				// Don't care
			}
		}

		// is there an assumed value that should be returned for any unknown value?
		if (evaluator != null && !varnode.isAddress()) {
			Instruction instr = getCurrentInstruction(currentAddress);
			Long lval = evaluator.unknownValue(this, instr, varnode);
			if (lval == null && !varnode.isUnique()) {
				return varnode;
			}
		}
		return null;
	}

	/**
	 * Search the value state stack for the first occurrence of the set value
	 * 
	 * @param varnode varnode to search for a value
	 * @param signed true if retrieving a signed value
	 * @return first value found on stack, null otherwise
	 */
	protected Varnode getMemoryValue(Varnode varnode, boolean signed) {
		return getMemoryValue(memoryVals, 0, varnode, signed);
	}

	protected Varnode getMemoryValue(List<HashMap<Address, Varnode>> valStore, int backupDepth, Varnode varnode,
			boolean signed) {
		// traverse pushed memory value states until find value
		// if don't find, return null

		// build up an array entry for each byte, if any missing, return
		int size = varnode.getSize();
		Varnode split[] = new Varnode[size];
		Address addr = varnode.getAddress();

		for (int i = 0; i < size; i++) {
			// go to thru stack til hit for each i
			// accumulate each byte, if get to end, fail
			HashMap<Address, Varnode> stateLayer = null;
			int layer = valStore.size() - 1 - backupDepth;
			while (layer >= 0) {
				stateLayer = valStore.get(layer);
				if (stateLayer == null) {
					break;
				}

				Varnode value = stateLayer.get(addr.addWrapSpace(i));
				if (value != null) {
					split[i] = value;
					break;
				}
				stateLayer = null;
				layer--;
			}

			if (stateLayer == null) {
				return null;
			}
		}

		// no have an array, re-assemble
		// if const, then each must be a const byte
		// if symbolic, each must be same symbolic value of correct size
		long value = 0;
		Varnode type = split[0];
		int typesize = type.getSize();
		boolean isconst = type.isConstant();
		if (!isconst && (typesize != 0 && typesize != size)) {
			return null;
		}
		for (int i = 0; i < split.length; i++) {
			Varnode vb = split[i];
			if (vb.getSpace() != type.getSpace()) {
				return null;
			}
			if (isconst) {
				// assemble constant
				value |= (vb.getOffset() << (isBE ? (size - i - 1) : i) * 8);
			}
			else if (type != vb) {
				return null;
			}
		}

		if (isconst) {
			if (size != 0) {
				value = (!signed ? value : ((value << (8 - size) * 8)) >> ((8 - size) * 8));
			}
			return createConstantVarnode(value, size);
		}

		if (signed && typesize != 0 && typesize < 8) {
			value = type.getOffset();
			value = ((value << (8 - size) * 8)) >> ((8 - size) * 8);
			return createVarnode(value, type.getSpace(), type.getSize());
		}
		return type;
	}

	protected Varnode getMemoryValue(HashMap<Address, Varnode> valStore, Varnode varnode,
			boolean signed) {

		// build up an array entry for each byte, if any missing, return
		int size = varnode.getSize();
		Varnode split[] = new Varnode[size];
		Address addr = varnode.getAddress();
		for (int i = 0; i < size; i++) {
			// go thru stack til hit for each i
			// accumulate each byte, if get to end, fail
				Varnode value = valStore.get(addr.addWrapSpace(i));
				if (value == null) {
					return null;
				}
				split[i] = value;
		}

		// now have an array, re-assemble
		// if const, then each must be a const byte
		// if symbolic, each must be same symbolic value of correct size
		long value = 0;
		Varnode type = split[0];
		int typesize = type.getSize();
		boolean isconst = type.isConstant();
		if (!isconst && typesize != 0 && typesize != size) {
			return null;
		}
		for (int i = 0; i < split.length; i++) {
			Varnode vb = split[i];
			if (vb.getSpace() != type.getSpace()) {
				return null;
			}
			if (isconst) {
				// assemble constant
				value |= (vb.getOffset() << (isBE ? (size - i - 1) : i) * 8);
			}
			else if (type != vb) {
				return null;
			}
		}

		if (isconst) {
			if (size != 0) {
				value = (!signed ? value : ((value << (8 - size) * 8)) >> ((8 - size) * 8));
			}
			return createConstantVarnode(value, size);
		}

		if (signed && typesize != 0 && typesize < 8) {
			value = type.getOffset();
			value = ((value << (8 - size) * 8)) >> ((8 - size) * 8);
			return createVarnode(value, type.getSpace(), type.getSize());
		}
		return type;
	}

	/**
	 * Put the value for the varnode on the top of the memory state stack
	 * 
	 * @param out varnode for the value
	 * @param value value to store for the varnode
	 */
	protected void putMemoryValue(Varnode out, Varnode value) {
		putMemoryValue(memoryVals, out, value);

	}

	protected void putMemoryValue(Stack<HashMap<Address, Varnode>> valStore, Varnode out,
			Varnode value) {
		HashMap<Address, Varnode> top = valStore.peek();
		putMemoryValue(top, out, value);
	}

	private void putMemoryValue(HashMap<Address, Varnode> top, Varnode out, Varnode value) {
		// put the value in the top memory value states
		int len = out.getSize();
		Address addr = out.getAddress();
		if (len == 1) {
			top.put(addr, value);
			return;
		}
		// TODO: add a byte array value for Suspect constant bytes too
		if (!value.isConstant()) {
			for (int nodeOff = 0; nodeOff < len; nodeOff++) {
				top.put(addr.addWrapSpace(nodeOff), value);
			}
			return;
		}

		Varnode split[] = splitToBytes(value, out.getSize());
		// copy in partial values after
		for (int nodeOff = 0; nodeOff < len; nodeOff++) {
			if (split == null) {
				top.put(addr.addWrapSpace(nodeOff), BAD_VARNODE);
			}
			else {
				top.put(addr.addWrapSpace(nodeOff), split[nodeOff]);
			}
			// just put in either bad varnode, or partial varnode

			// TODO: if not constant, then is bad value
			//       Could just put a new const varnode for const of right size
			///      would make above easier, putting back together
			//     All const,, full value or vnode+offset, other bad
			//value = new Varnode(value.getAddress(),(nodeOff << 8) | value.getSize());
		}
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

		if (spaceID == BAD_SPACE_ID_VALUE || spc == null) {
			addr = BAD_ADDRESS;
		}
		else if (spaceID == BAD_OFFSET_SPACEID) {
			// special case of unknown value + constant
			addr = spc.getTruncatedAddress(value, true);
		}
		else {
			addr = spc.getTruncatedAddress(value, true);
		}

		return new Varnode(addr, size);
	}

	public Varnode createConstantVarnode(long value, int size) {
		if (size == 1) {
			byte b = (byte) value;
			final int offset = 128;
			Varnode bv = byteVarnodes[b + offset];
			if (bv == null) {
				AddressSpace spc = addrFactory.getConstantSpace();
				Address addr = spc.getAddress(b & 0xff);
				bv = new Varnode(addr, size);
				byteVarnodes[b + offset] = bv;
			}
			return bv;
		}
		AddressSpace spc = addrFactory.getConstantSpace();
		Address addr = spc.getAddress(value);
		return new Varnode(addr, size);
	}

	public Varnode[] splitToBytes(Varnode v, int len) {
		if (!isConstant(v)) {
			return null;
		}
		
		Varnode split[] = new Varnode[len];
		long value = v.getOffset();
		if (isBE) {
			for (int i = 0; i < len; i++) {
				long subv = value >> (i * 8);
				split[len - i - 1] = createConstantVarnode(subv, 1);
			}
		}
		else {
			for (int i = 0; i < len; i++) {
				long subv = value >> (i * 8);
				split[i] = createConstantVarnode(subv, 1);
			}
		}
		return split;
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

		if (result == null) {
			putValue(out, BAD_VARNODE, false);
			return;
		}

		boolean isSymbolicAddr = isSymbolicSpace(out.getSpace());
		if (out.isAddress() || isSymbolicAddr) {
			if (!isRegister(out)) {
				if (debug) {
					Msg.info(this, "      " + print(out) + " <- " + print(result) + " at " +
						currentAddress);
				}

				// put the location on both the lastSet, and all locations set
				addSetVarnodeToLastSetLocations(out, currentAddress);

				// don't put a value into a bad address space
				// could get values pulled from a different badd address offset
				if (isSymbolicAddr &&
					out.getAddress().getAddressSpace().getSpaceID() == BAD_OFFSET_SPACEID) {
					return;
				}
				putMemoryValue(out, result);
				return;
			}
		}

		// don't ever store an unknown unique into a location
		if (result.isUnique()) {
			result = null;
		}
		if (out.isUnique()) {
			if (mustClear) {
				result = null;
			}
			putMemoryValue(tempUniqueVals, out, result);
		}
		else {
			// if storing a bad address, need to create a new register/address
			// relative symbolic space
			if (result != null) {
				if (result.getAddress() == BAD_ADDRESS) {
					String spaceName = out.getAddress().getAddressSpace().getName();
					Register register = getRegister(out);
					// if the register is worth tracking as a potential address space
					// with stores/loads of constants to it, create a fake address space for it
					if (shouldTrackRegister(register)) {
						spaceName = register.getName();
						int newRegSpaceID = getAddressSpace(spaceName + "-" + currentAddress, currentAddress.getSize());
						result = createVarnode(0, newRegSpaceID, out.getSize());
					}
				}
				addSetVarnodeToLastSetLocations(out, currentAddress);
			}
			putMemoryValue(tempVals, out, result);
		}

		if (debug) {
			Msg.info(this, "      " + print(out) + " <- " + print(result) + " at " +
				currentAddress);
		}
		if (mustClear) {
			clearVals.add(out);
		}
	}

	/**
	 * Check if the register should be tracked for symbolic offset tracking.
	 * A flag or register not likely to be used as an offset into a space to store/load
	 * constant values should not be tracked.
	 * 
	 * @param register the register
	 * @return true if register should be tracked symbolically, false otherwise
	 */
	private boolean shouldTrackRegister(Register register) {
		if (register == null) {
			return false;
		}
		// if the register is small, and not part of a larger register
		if (register.getBitLength() <= 8 && register.getParentRegister() == null) {
			return false;
		}
		return true;
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

		Iterator<Varnode> iterator = clearVals.iterator();
		while (iterator.hasNext()) {
			Varnode node = iterator.next();
			Register reg = trans.getRegister(node);
			if (reg == null) {
				continue;
			}
			if (debug) {
				Msg.info(this, "      " + reg.getName() + "<-" + " Clear");
			}
			clearRegister(reg);
		}

		// clone temp vals an put at address

		// merge tempvals to top of regVals
		regVals.peek().putAll(tempVals);

		if (keepTempUniqueValues) {
			uniqueVals.peek().putAll(tempUniqueVals);
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
				currentAddress);
		}

		addSetVarnodeToLastSetLocations(node, address);

		putMemoryValue(regVals, node, val);

		// set lastSet for any children locations
		List<Register> childRegisters = reg.getChildRegisters();
		for (Register register : childRegisters) {
			if (register.getMinimumByteSize() >= program.getDefaultPointerSize()) {
				node = getRegisterVarnode(register);

				addSetVarnodeToLastSetLocations(node, address);
			}
		}
	}

	private void addSetVarnodeToLastSetLocations(Varnode node, Address address) {
		lastSet.put(node, address);
		AddressSet addressSet = allLastSet.get(node);
		if (addressSet == null) {
			addressSet = new AddressSet();
			allLastSet.put(node, addressSet);
		}
		addressSet.add(address);

		// for registers with parent larger register, must store that they were
		// last set at this address as well.
		// Don't care about really large overlapping registers
		if (node.isRegister() && node.getSize() <= 8) {
			Register register = trans.getRegister(node);
			if (register == null) {
				return;
			}
			Register parentRegister = register.getParentRegister();
			// Don't care about really large overlapping registers
			if (parentRegister != null && parentRegister.getBitLength() <= 64) {
				node = trans.getVarnode(parentRegister);
				addSetVarnodeToLastSetLocations(node, address);
			}
		}
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
			if (bval == null || bval.equals(rbval)) {
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

	public Long getConstant(Varnode vnode, ContextEvaluator evaluator) {
		if (vnode == null) {
			return null;
		}

		if (!isConstant(vnode)) {
			if (evaluator == null) {
				return null;
			}

			// is there an assumed value that should be returned for any unknown value?
			Instruction instr = getCurrentInstruction(currentAddress);
			Long lval = evaluator.unknownValue(this, instr, vnode);
			if (lval != null) {
				return lval.longValue();
			}
			return null;
		}

		return vnode.getOffset();
	}

	public Varnode getVarnode(Varnode space, Varnode offset, int size, ContextEvaluator evaluator) {
		if (offset == null) {
			return null;
		}
		int spaceID = offset.getSpace();
		long valbase = 0;
		if (isRegister(offset)) {
			Register reg = trans.getRegister(offset);
			if (reg == null) {
				return null;
			}
			spaceID = getAddressSpace(reg.getName(),reg.getBitLength());
			valbase = 0;
		}
		else if (offset.isConstant()) {
			valbase = offset.getOffset();
			spaceID = (int) space.getOffset();
		}
		else if (isSuspectConstant(offset)) {
			// constant suspicious don't let if fall into symbolic
			// handle same as normal constant but keep suspicious space
			valbase = offset.getOffset();
			spaceID = (int) space.getOffset();
		}
		else if (OffsetAddressFactory.isSymbolSpace(spaceID)) {
			if (evaluator == null) {
				return null;
			}

			// is there an assumed value that should be returned for any unknown value?
			Instruction instr = getCurrentInstruction(currentAddress);
			Long lval = evaluator.unknownValue(this, instr, offset);
			valbase = offset.getOffset();
			if (lval != null) {
				spaceID = (int) space.getOffset();
				valbase += lval.longValue();
			}
		}
		else {
			return null;
		}
		return getVarnode(spaceID, valbase, size);
	}

	/**
	 * Get the value (value, space, size) of a register at the start of the last execution
	 * flow taken for the instruction at toAddr.
	 * 
	 * @param reg register to retrieve the start value
	 * @param fromAddr flow from address (not used currently, future use to retrieve multiple flows)
	 * @param toAddr address of instruction to retrieve the register flow state
	 * @param signed true if value is signed, will sext the top bit based on value size
	 * 
	 * @return instruction start state value for register, or null if no known state
	 * 
	 */
	public Varnode getRegisterVarnodeValue(Register reg, Address fromAddr, Address toAddr,
			boolean signed) {

		if (reg == null) {
			return null;
		}
		Varnode rvnode = trans.getVarnode(reg);
		
		// use current regVals;
		int backupDepth = 0;
		Stack<HashMap<Address, Varnode>> state = regVals;
		
		// if has a stored stack state, setup to use that state
		TraceDepthState traceDepthState = addrStartState.get(toAddr);
		if (traceDepthState != null) {	
			state= traceDepthState.state();
			backupDepth = state.size() - traceDepthState.depth();
		}
		
		Varnode value = getMemoryValue(state, backupDepth, rvnode, signed);

		int sizeNeeded = reg.getBitLength() / 8;

		// lucky, got location and full size looking for
		if (value != null && (value.getSize() == sizeNeeded || value.getSize() == 0)) {
			return value;
		}

		return null;
	}
	

	/**
	 * Get the value (value, space, size) of a register at the end of the last execution
	 * flow taken for the instruction at toAddr.
	 *
	 * Note: This can only be called if trackStartEndState flag is true.
	 * 
	 * @param reg register to retrieve the end value
	 * @param fromAddr flow from address (not used currently, future use to retrieve multiple flows)
	 * @param toAddr address of instruction to retrieve the register flow state
	 * @param signed is the value signed or unsigned, will sext the top bit based on value size
	 * 
	 * @return instruction end state value for register, or null if no known state
	 * 
	 * @throws UnsupportedOperationException trackStartEndState == false at construction
	 */
	public Varnode getEndRegisterVarnodeValue(Register reg, Address fromAddr, Address toAddr,
			boolean signed) {
		
		if (!trackStartEndState) {
			throw new UnsupportedOperationException("Must construct class with trackStartEndState == true");
		}
		
		if (reg == null) {
			return null;
		}

		Varnode rvnode = trans.getVarnode(reg);
		
		TraceDepthState traceDepthState = addrEndState.get(toAddr);
		if (traceDepthState == null) {
			return null;
		}
		
		Stack<HashMap<Address, Varnode>> state = traceDepthState.state();
		int backupDepth = state.size() - traceDepthState.depth();
		
		Varnode value = getMemoryValue(state, backupDepth, rvnode, signed);

		int sizeNeeded = reg.getBitLength() / 8;

		// lucky, got location and full size looking for
		if (value != null && (value.getSize() == sizeNeeded || value.getSize() == 0)) {
			return value;
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

	/**
	 * Get the current value of the register at the address.
	 * Note: If trackStartEndState flag is false, then this will return the current value.
	 * 
	 * @param reg value of register to get
	 * @param toAddr value of register at a location
	 * 
	 * @return value of register or null
	 */
	public RegisterValue getRegisterValue(Register reg, Address toAddr) {
		return getRegisterValue(reg, Address.NO_ADDRESS, toAddr);
	}

	/**
	 * Get the value of a register that was set coming from an address to an
	 * another address.
	 * Note: If trackStartEndState flag is false, then this will return the current value.
	 * 
	 * @param reg value of register to get
	 * @param fromAddr location the value came from
	 * @param toAddr location to get the value of the register coming from fromAddr
	 * 
	 * @return value of register or null
	 */
	public RegisterValue getRegisterValue(Register reg, Address fromAddr, Address toAddr) {
		
		Varnode rvnode = getRegisterVarnodeValue(reg, fromAddr, toAddr, false);
		if (rvnode == null) {
			return null;
		}

		int spaceID = rvnode.getSpace();

		// check normal constant and suspect constants
		if (spaceID != addrFactory.getConstantSpace().getSpaceID() &&
			spaceID != SUSPECT_OFFSET_SPACEID) {
			return null;
		}

		return new RegisterValue(reg, BigInteger.valueOf(rvnode.getOffset()));
	}

	public AddressRangeIterator getRegisterValueAddressRanges(Register reg) {
		return programContext.getRegisterValueAddressRanges(reg);
	}

	public boolean hasValueOverRange(Register reg, BigInteger bval, AddressSet set) {
		return programContext.hasValueOverRange(reg, bval, set);
	}

	/**
	 * Copy the varnode with as little manipulation as possible.
	 * Try to keep whatever partial state there is intact if a real value isn't required.
	 * 
	 * @param out varnode to put it in
	 * @param in varnode to copy from.
	 * @param mustClearAll true if must clear if value is not unique
	 * @param evaluator user provided evaluator if needed
	 */
	public void copy(Varnode out, Varnode in, boolean mustClearAll, ContextEvaluator evaluator) {
		Varnode val1 = null;
		// if just a copy of itself, do nothing
		if (out.equals(in)) {
			return;
		}
		val1 = getValue(in, evaluator);
		// if truncating a constant get a new constant of the proper size
		if (val1 != null && in.getSize() > out.getSize()) {
			if (isConstant(val1)) {
				val1 = createVarnode(val1.getOffset(), val1.getSpace(), out.getSize());
			}
		}

		if (!in.isRegister() || !out.isRegister()) {
			// normal case easy get value, put value
			putValue(out, val1, mustClearAll);
			return;
		}
		if (mustClearAll) {
			clearVals.add(out);
		}

		putValue(out, val1, mustClearAll);
	}

	/**
	 * Add two varnodes together to get a new value
	 * This could create a new space and return a varnode pointed into that space
	 * 
	 * @param val1 first value
	 * @param val2 second value
	 * @return varnode that could be a constant, or an offset into a space, or null
	 */
	public Varnode add(Varnode val1, Varnode val2, ContextEvaluator evaluator) {
		if (val1 == null || val2 == null) {
			return null;
		}
		// try to make the constant value the addend.
		if (isConstant(val1) || val1.isAddress()) {
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
				return null;
			}
			spaceID = getAddressSpace(reg.getName(),reg.getBitLength());
			valbase = 0;
			// check if evaluator wants to override unknown
			Instruction instr = getCurrentInstruction(currentAddress);
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
			// use bad address offset space, allows offsets to unknown things to continue
			// TODO: Investigate if the source of the BAD_ADDRESS can be known
			spaceID = BAD_OFFSET_SPACEID;
			valbase = 0;
			// check if evaluator wants to override unknown
			Instruction instr = getCurrentInstruction(currentAddress);
			if (evaluator != null) {
				Long uval = evaluator.unknownValue(this, instr, val1);
				if (uval != null) {
					// 2nd value could be a constant, or a register, which would create an offset from reg
					valbase = uval.longValue();
					spaceID = val2.getSpace();
				}
			}
		}
		else if (isConstant(val1)) {
			valbase = val1.getOffset();
			if (!isSuspectConstant(val1)) {
				spaceID = val2.getSpace();
			}
		}
		else if (isSymbolicSpace(spaceID)) {
			Instruction instr = getCurrentInstruction(currentAddress);
			valbase = val1.getOffset();
			if (evaluator != null) {
				Long uval = evaluator.unknownValue(this, instr, val1);
				if (uval != null) {
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
					return add(createConstantVarnode(valbase, val1.getSize()), val2, evaluator);

				}
			}
		}
		else {
			return null;
		}

		// create a new varnode with the correct space and offset
		// note: if spaceID is a bad space, createVarnode will create a new BAD_ADDRESS
		Long val2Const = getConstant(val2, null);
		if (val2Const == null) {
			return null;
		}
		long result = (valbase + val2Const) &
			(0xffffffffffffffffL >>> ((8 - val1.getSize()) * 8));
		return createVarnode(result, spaceID, val1.getSize());
	}

	public Varnode and(Varnode val1, Varnode val2, ContextEvaluator evaluator) {
		if (val1 == null || val2 == null) {
			return null;
		}
		if (val1.equals(val2)) {
			return val1;
		}
		if (isConstant(val1) || val1.isAddress()) {
			Varnode swap = val1;
			val1 = val2;
			val2 = swap;
		}
		int spaceID = val1.getSpace();
		long valbase = 0;
		if (isRegister(val1)) {
			Register reg = trans.getRegister(val1);
			if (reg == null) {
				return null;
			}
			spaceID = getAddressSpace(reg.getName(),reg.getBitLength());
			valbase = 0;
		}
		else if (val1.isConstant()) {
			valbase = val1.getOffset();
			if (!isSuspectConstant(val1)) {
				spaceID = val2.getSpace();
			}
		}
		else if (isSymbolicSpace(spaceID)) {
			valbase = val1.getOffset();
			if (val2.isConstant()) {
				Long val2Const = getConstant(val2, null);
				if (val2Const == null) {
					return null;
				}
				// check if the value could be an alignment mask from an unknown register
				if (((val2Const >> 1) << 1) != val2Const && ((val2Const >> 2) << 2) != val2Const) {
					return null;
				}
			}
		}
		else if (isExternalSpace(spaceID)) {
			return (val1); // can't mess with an external address
		}
		else {
			return null;
		}
		Long val2Const = getConstant(val2, null);
		if (val2Const == null) {
			return null;
		}
		long result = (valbase & val2Const) &
			(0xffffffffffffffffL >>> ((8 - val1.getSize()) * 8));
		return createVarnode(result, spaceID, val1.getSize());
	}

	public Varnode or(Varnode val1, Varnode val2, ContextEvaluator evaluator) {
		if (val1 == null || val2 == null) {
			return null;
		}
		if (val1.equals(val2)) {
			return val1;
		}

		if (isConstant(val1) || val1.isAddress()) {
			Varnode swap = val1;
			val1 = val2;
			val2 = swap;
		}
		int spaceID = val1.getSpace();
		Long val2Const = getConstant(val2, null);
		if (val2Const == null) {
			return null;
		}
		// got a constant from val2, (value | 0) == value, so just return value
		if (val2Const == 0) {
			if (!isSuspectConstant(val2)) {
				return val1;
			}
			spaceID = val2.getSpace();
		}
		Long val1Const = getConstant(val1, evaluator);
		if (val1Const == null) {
			return null;
		}
		long lresult = val1Const | val2Const;
		return createVarnode(lresult, spaceID, val1.getSize());
	}

	public Varnode left(Varnode val1, Varnode val2, ContextEvaluator evaluator) {
		if (val1 == null || val2 == null) {
			return null;
		}
		Long val1Const = getConstant(val1, evaluator);
		if (val1Const == null)
			return null;
		Long val2Const = getConstant(val2, evaluator);
		if (val2Const == null)
			return null;
		long lresult = val1Const << val2Const;
		lresult = lresult & (0xffffffffffffffffL >>> ((8 - val1.getSize()) * 8));
		Varnode result = createVarnode(lresult, val1.getSpace(), val1.getSize());
		return result;
	}

	// flag running out of address spaces, so error only printed once
	private boolean hitMaxAddressSpaces = false;

	public int getAddressSpace(String name,int bitSize) {
		int spaceID;
		AddressSpace regSpace = addrFactory.getAddressSpace(name);
		if (regSpace == null) {
			// don't allow symbolic spaces smaller than a pointer so the offset value can hold a pointer
			// TODO: This probably isn't quite right, the offset address space in theory should only be
			//       the size of the register that is getting an offset.  The register could be a
			//       small 8-bit register used as an offset from a larger value to get a pointer.
			int spaceBitSize = bitSize < pointerBitSize ? pointerBitSize : bitSize;
			regSpace = ((OffsetAddressFactory) addrFactory).createNewOffsetSpace(name,spaceBitSize);
		}
		if (regSpace == null) {
			if (!hitMaxAddressSpaces) {
				Msg.error(this, "VarnodeContext: out of address spaces at @" + currentAddress +
					" for: " + name);
				hitMaxAddressSpaces = true;
			}
			return BAD_SPACE_ID_VALUE;
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
	 */
	public Varnode subtract(Varnode val1, Varnode val2, ContextEvaluator evaluator) {
		if (val1 == null || val2 == null) {
			return null;
		}

		// degenerate case, don't need to know the value
		if (val1.equals(val2)) {
			if (isBadAddress(val1)) {
				return val1;
			}
			int size = val1.getSize();
			size = size > 0 ? size : 1; // turning into constant, make sure has a size
			return createVarnode(0, addrFactory.getConstantSpace().getSpaceID(), size);
		}
		int spaceID = val1.getSpace();
		long valbase = 0;
		if (isConstant(val1)) {
			valbase = val1.getOffset();
			if (!isSuspectConstant(val1)) {
				spaceID = val2.getSpace();
			}
		}
		else if (isRegister(val1)) {
			Register reg = trans.getRegister(val1);
			if (reg == null) {
				return null;
			}
			spaceID = getAddressSpace(reg.getName(),reg.getBitLength());
			valbase = 0;
		}
		else if (isSymbolicSpace(spaceID)) {
			Instruction instr = getCurrentInstruction(currentAddress);
			valbase = val1.getOffset();
			if (evaluator != null) {
				Long uval = evaluator.unknownValue(this, instr, val1);
				if (uval != null) {
					valbase = uval.longValue();
					return add(createConstantVarnode(valbase, val1.getSize()), val2, evaluator);
				}
			}
		}
		else {
			return null;
		}
		Long val2Const = getConstant(val2, null);
		if (val2Const == null) {
			return null;
		}
		long result = (valbase - val2Const) &
			(0xffffffffffffffffL >>> ((8 - val1.getSize()) * 8));
		return createVarnode(result, spaceID, val1.getSize());
	}

	/**
	 * Extend a constant value if it can be extended.
	 * 
	 * @param out varnode to extend into (for size)
	 * @param in varnode value to extend the size
	 * @return new sign extended varnode
	 */
	public Varnode extendValue(Varnode out, Varnode[] in, boolean signExtend,
			ContextEvaluator evaluator) {
		Varnode vnodeVal;

		vnodeVal = getValue(in[0], signExtend, evaluator);
		if (vnodeVal == null) {
			return null;
		}

		if (isConstant(vnodeVal) && in[0].getSize() < out.getSize()) {
			if (vnodeVal.getSize() <= 8) {
				Scalar sVal = new Scalar(8 * vnodeVal.getSize(), vnodeVal.getOffset(), signExtend);
				vnodeVal = createVarnode(sVal.getValue(), vnodeVal.getSpace(), out.getSize());
			}
			else {
				// too big anyway,already extended as far as it will go.
				vnodeVal = createVarnode(vnodeVal.getOffset(), vnodeVal.getSpace(), out.getSize());
			}
		}
		else if (vnodeVal.isRegister() && vnodeVal.getSize() < out.getSize()) {
			Register reg = getRegister(vnodeVal);
			if (reg == null) {
				return null;
			}
			int spaceID = getAddressSpace(reg.getName(),reg.getBitLength());
			vnodeVal = createVarnode(0, spaceID, out.getSize());
		}
		return vnodeVal;
	}

	@Override
	public void clearRegister(Register reg) {
		if (reg == null) {
			return;
		}

		// Start new register space
		String spaceName = reg.getName() + "-" + currentAddress;
		int spaceId = getAddressSpace(spaceName,reg.getBitLength());

		Varnode registerVarnode = getRegisterVarnode(reg);
		putMemoryValue(this.regVals, registerVarnode,
			createVarnode(0, spaceId, registerVarnode.getSize()));
	}

	@Override
	public Register getRegister(String name) {
		return trans.getRegister(name);
	}

	@Override
	public RegisterValue getRegisterValue(Register register) {
		Varnode regVnode = trans.getVarnode(register);
		Varnode value = this.getValue(regVnode, false, null);
		if (value != null && isConstant(value)) {
			return new RegisterValue(register, BigInteger.valueOf(value.getOffset()));
		}
		return null;
	}

	public Varnode getRegisterVarnodeValue(Register register) {
		Varnode regVnode = trans.getVarnode(register);

		Varnode value = this.getValue(regVnode, false, null);
		return value;
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
		return trans.getRegisters();
	}

	@Override
	public BigInteger getValue(Register register, boolean signed) {
		Varnode regVnode = trans.getVarnode(register);

		Varnode value = this.getValue(regVnode, signed, null);
		if (value == null) {
			return null;
		}
		if (isConstant(value)) {
			return BigInteger.valueOf(value.getOffset());
		}
		return null;
	}

	@Override
	public boolean hasValue(Register register) {
		Varnode rvnode = getRegisterVarnodeValue(register);
		return rvnode != null;
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

	/**
	 * Check if the varnode is associated with a Symbolic location
	 * 
	 * @param varnode to check
	 * @return true if  the varnode is a symbolic location
	 */
	public boolean isSymbol(Varnode varnode) {
		if (varnode == null) {
			return false;
		}
		return isSymbolicSpace(varnode.getAddress().getAddressSpace());
	}

	/**
	 * Check if the varnode is associated with a register.
	 * 
	 * @param varnode to check
	 * @return true if the varnode is associated with a register
	 */
	public boolean isRegister(Varnode varnode) {
		if (varnode == null) {
			return false;
		}
		return varnode.isRegister() || trans.getRegister(varnode) != null;
	}

	/**
	 * Check if this is a constant, or a suspect constant
	 * 
	 * @param varnode to check
	 * @return true if should be treated as a constant for most purposes
	 */
	public boolean isConstant(Varnode varnode) {
		if (varnode == null) {
			return false;
		}
		if (varnode.isConstant()) {
			return true;
		}
		return isSuspectConstant(varnode);
	}

	/**
	 * Check if this is a bad address, or offset from a bad address
	 * 
	 * @param v to check
	 * @return true if should be treated as a constant for most purposes
	 */
	public boolean isBadAddress(Varnode v) {
		if (v == null) {
			return false;
		}
		return v.getAddress().equals(BAD_ADDRESS) || v.getSpace() == BAD_OFFSET_SPACEID;
	}

	/**
	 * Check if the constant is a suspect constant
	 * It shouldn't be trusted in certain cases.
	 * Suspect constants act like constants, but are in a Suspicious
	 * address space instead of the constant space.
	 * 
	 * @param varnode varnode to check
	 * @return true if varnode is a suspect constant
	 */
	public boolean isSuspectConstant(Varnode varnode) {
		if (varnode == null) {
			return false;
		}
		return varnode.getSpace() == SUSPECT_OFFSET_SPACEID;
	}

	/**
	 * Check if varnode is in the stack space
	 * 
	 * @param varnode varnode to check
	 * 
	 * @return true if this varnode is stored in the symbolic stack space
	 */
	public boolean isStackSymbolicSpace(Varnode varnode) {
		if (varnode == null) {
			return false;
		}
		// symbolic spaces are off of a register, find the space
		AddressSpace regSpace = addrFactory.getAddressSpace(varnode.getSpace());

		return isStackSpaceName(regSpace.getName());
	}

	/**
	 * Check if spaceName is associated with the stack
	 * 
	 * @param spaceName of address space to check
	 * @return true if spaceName is associated with the stack space
	 */
	public boolean isStackSpaceName(String spaceName) {
		return validSymbolicStackNames.contains(spaceName);
	}

	/**
	 * Check if the space name is a symbolic space.
	 * A symbolic space is a space named after a register/unknown value and
	 * an offset into that symbolic space.
	 * 
	 * Symbolic spaces come from the OffsetAddressFactory
	 * 
	 * @param space the address space
	 * @return true if is a symbolic space
	 */
	public boolean isSymbolicSpace(AddressSpace space) {
		int spaceID = space.getSpaceID();
		return OffsetAddressFactory.isSymbolSpace(spaceID);
	}

	/**
	 * Check if the space ID is a symbolic space.
	 * A symbolic space is a space named after a register/unknown value and
	 * an offset into that symbolic space.
	 * 
	 * Symbolic spaces come from the OffsetAddressFactory
	 * 
	 * @param spaceID the ID of the space
	 * @return true if is a symbolic space
	 */
	public boolean isSymbolicSpace(int spaceID) {
		return OffsetAddressFactory.isSymbolSpace(spaceID);
	}

	/**
	 * Check if the space ID is an external space.
	 * 
	 * External spaces are single locations that have no size
	 * normally associated with a location in another program.
	 * 
	 * @param spaceID the ID of the space
	 * @return true if is a symbolic space
	 */
	public boolean isExternalSpace(int spaceID) {
		return spaceID == AddressSpace.EXTERNAL_SPACE.getSpaceID();
	}

	/**
	 * Save the current memory state
	 */
	public void pushMemState() {
		Stack<HashMap<Address, Varnode>> newRegValsTrace =
			(Stack<HashMap<Address, Varnode>>) regVals.clone();
		regTraces.push(newRegValsTrace);
		regVals.push(new HashMap<Address, Varnode>());
		
// TODO: only save if need to
		Stack<HashMap<Address, Varnode>> newUniqueValsTrace =
				(Stack<HashMap<Address, Varnode>>) uniqueVals.clone();
		uniqueTraces.push(newUniqueValsTrace);
		uniqueVals.push(new HashMap<Address, Varnode>());
		
		Stack<HashMap<Address, Varnode>> newMemValsTrace =
			(Stack<HashMap<Address, Varnode>>) memoryVals.clone();
		newMemValsTrace.push(new HashMap<Address, Varnode>());
		memTraces.push(newMemValsTrace);
		memoryVals.push(new HashMap<Address, Varnode>());

		lastSetSaves.push((HashMap<Varnode, Address>) lastSet.clone());
	}

	/**
	 * restore a previously saved memory state
	 */
	public void popMemState() {
		regVals = regTraces.pop();
		memoryVals = memTraces.pop();
		
// TODO: only save if need to
		uniqueVals = uniqueTraces.pop();
		
		lastSet = lastSetSaves.pop();

		tempVals = new HashMap<>();
		clearVals = new HashSet<>();
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
		try {
			// Use JOIN type space for suspect constants, it is used by the decompiler, so can
			// be repurposed for this algorithm.
			// Hack for current storage allows suspect constants to fit in a byte. The current
			// algorithm is sensitive to the space ID value and must be less than 0x7f.  Only types that are
			// between 0-16 will work correctly because of how the spaceID is calculated based on the space type.
			// The spaceID is computed using the type.
			AddressSpace suspectConstspc =
				new GenericAddressSpace(VarnodeContext.SUSPECT_CONST_NAME, 64,
					AddressSpace.TYPE_JOIN, 0);
			addAddressSpace(suspectConstspc);
		}
		catch (DuplicateNameException e) {
			throw new AssertException("Duplicate name should not occur.");
		}
		try {
			addAddressSpace(AddressSpace.EXTERNAL_SPACE);
		}
		catch (DuplicateNameException e) {
			throw new AssertException("Duplicate name should not occur.");
		}
	}

	// Maximum space ID used to create spaces
	private int curMaxID = 0;

	private int getNextUniqueID() {
		if (curMaxID == 0) {
			AddressSpace[] spaces = getAllAddressSpaces();
			for (AddressSpace space : spaces) {
				curMaxID = Math.max(curMaxID, space.getUnique());
			}
		}
		curMaxID += 1;
		return curMaxID;
	}

	/**
	 * Create a new address space
	 * 
	 * @param name of address space
	 * @return new address space, or null if no spaces left to allocate
	 */
	public AddressSpace createNewOffsetSpace(String name, int bitSize) {
		AddressSpace space = null;
		try {
			if (bitSize > 64) {
				bitSize = 64;
			}
			if (bitSize < 8) {
				bitSize = 8;
			}
			space = new OffsetAddressSpace(name, bitSize,
				AddressSpace.TYPE_SYMBOL, getNextUniqueID());
			super.addAddressSpace(space);
		}
		catch (IllegalArgumentException e) {
			return null; // out of address spaces
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

class OffsetAddressSpace extends GenericAddressSpace {

	public OffsetAddressSpace(String name, int size, int type, int unique) {
		super(name, size, type, unique);
	}

	@Override
	public int compareTo(AddressSpace space) {
		int c = getSpaceID() - space.getSpaceID();
		return c;
	}
}
