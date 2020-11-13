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

import java.math.BigInteger;
import java.util.*;

import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.mem.*;
import ghidra.program.model.pcode.*;
import ghidra.util.Msg;
import ghidra.util.NumericUtilities;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

public class ContextState {

	private static boolean DEBUG = false;

	private static final long[] VALUE_MASK = new long[] { 0x0, 0x0ff, 0x0ffff, 0x0ffffff,
		0x0ffffffffL, 0x0ffffffffffL, 0x0ffffffffffffL, 0x0ffffffffffffffL, -1 };

	private static final long[] SIGN_BIT = new long[] { 0x0, 0x080, 0x08000, 0x0800000,
		0x080000000L, 0x08000000000L, 0x0800000000000L, 0x080000000000000L };

// TODO: How do we store a partial values (i.e., unknown bits) - we need a special varnode or operation

// TODO: Make sure that ALL constant values are sign-extended for consistency

	private final Program program;
	private final Language language;
	private final AddressFactory addrFactory;
	private final SequenceNumber pcodeEntry;
	//private SequenceNumber pcodeExit;
	private SequenceRange sequenceRange;
	private final HashSet<SequenceNumber> flowFrom = new HashSet<SequenceNumber>();
	private final ContextState previousState;
	//private boolean stackPointerIsValid;
	private final Memory memory;

	private HashMap<Address, Varnode> memoryMap = new HashMap<Address, Varnode>();
	private HashMap<String, HashMap<Long, Varnode>> frameMaps;
	private HashMap<Long, Varnode> uniqueMap;

	private int cachedSpaceId;
	private Varnode cachedLocation;
	private Varnode cachedValue;

	private boolean locked = false;

	private Varnode debugVarnode;

	/**
	 * Constructs an empty state.
	 * @param entryPt the entry point for the context state
	 * @param program the program
	 */
	public ContextState(Address entryPt, Program program) {
		this(entryPt, program.getProgramContext(), program);
	}

	/**
	 * Constructs an empty state.
	 * @param entryPt the entry point for the context state
	 * @param programCtx initial program context or null
	 * @param program the program
	 */
	public ContextState(Address entryPt, ProgramContext programCtx, Program program) {
		this.program = program;
		this.previousState = null;
		this.memory = program.getMemory();
		this.pcodeEntry = new SequenceNumber(entryPt, 0);
		this.language = program.getLanguage();
		this.addrFactory = program.getAddressFactory();
//		this.stackPointerIsValid = true;
		if (programCtx != null) {
			copyEntryContext(pcodeEntry.getTarget(), programCtx);
		}
	}

	/**
	 * Derive a new context state from an initial state
	 * @param pcodeEntry the pcode entry sequence number
	 * @param previousState previous context state flowing into the specified pcode location
	 */
	public ContextState(SequenceNumber pcodeEntry, ContextState previousState) {
		this.pcodeEntry = pcodeEntry;
		this.previousState = previousState;
		this.program = previousState.program;
		this.memory = previousState.memory;
		this.language = previousState.language;
		this.addrFactory = program.getAddressFactory();
		this.debugVarnode = previousState.debugVarnode;
//		this.stackPointerIsValid = previousState.stackPointerIsValid;
	}

	/**
	 * Returns program associated with this context state
	 */
	public Program getProgram() {
		return program;
	}

	/**
	 * Returns previous ContextState which flowed into this one.
	 */
	public ContextState getPreviousContextState() {
		return previousState;
	}

	public boolean isFlowFrom(SequenceNumber seq) {
		return flowFrom.contains(seq);
	}

	void addFlowFrom(SequenceNumber seq) {
		if (seq != null) {
			flowFrom.add(seq);
		}
	}

	public Set<SequenceNumber> getFlowFroms() {
		return flowFrom;
	}

	void setExitPoint(SequenceNumber end) {
		sequenceRange = new SequenceRange(pcodeEntry, end);
	}

	public SequenceNumber getExitPoint() {
		if (sequenceRange != null) {
			return sequenceRange.getEnd();
		}
		return null;
	}

	public SequenceRange getSequenceRange() {
		return sequenceRange;
	}

	/**
	 * Set a varnode to be debugged.  This will be passed to any states 
	 * derived from this state.
	 * @param varnode varnode to be debugged
	 */
	public void setDebugVarnod(Varnode varnode) {
		debugVarnode = varnode;
	}

	/**
	 * Branch the current state.  The current state should be associated with
	 * branch target, the returned state should be used for the fall-through flow.
	 * @return
	 */
	public ContextState branchState(SequenceNumber pcodeEntry) {
		ContextState newState = new ContextState(pcodeEntry, this);
		newState.uniqueMap = uniqueMap;
		if (uniqueMap != null) {
			uniqueMap.clear();
		}
		return newState;
	}

	private void copyEntryContext(Address entryAddr, ProgramContext entryContext) {
		for (Register reg : entryContext.getRegistersWithValues()) {
			RegisterValue regValue = entryContext.getRegisterValue(reg, entryAddr);
			// TODO: Not sure how to handle partial values or bit registers
			if (regValue != null) {
				if (reg.isProcessorContext()) {
					storeRegisterValue(reg, regValue.getUnsignedValueIgnoreMask());
				}
				else if (regValue.hasValue()) {
					storeRegisterValue(reg, regValue.getUnsignedValue());
				}
			}
		}
	}

	private void storeRegisterValue(Register reg, BigInteger unsignedValue) {

		byte[] bytes = unsignedValue.toByteArray(); // most-significant-byte is in 0th element
		int bytesIndex = 0;
		if (bytes[0] == 0) {
			bytesIndex = 1;
		}
		Address baseAddr = reg.getAddress();
		int size = reg.getMinimumByteSize();
		byte signextend = (byte) ((unsignedValue.signum() < 0) ? -1 : 0);
		int lengthDiff = size - bytes.length + bytesIndex;

		for (int i = 0; i < size; i++) {
			byte val;
			if (lengthDiff > 0) {
				val = signextend;
				--lengthDiff;
			}
			else {
				val = bytes[bytesIndex++];
			}
			Varnode byteValue = new Varnode(addrFactory.getConstantAddress(val), 1);
			byteValue.trim();
			long byteOffset = language.isBigEndian() ? i : (size - i - 1);
			memoryMap.put(baseAddr.addWrap(byteOffset), byteValue);
		}
	}

	/**
	 * Returns the point at which the state was instantiated.
	 */
	public SequenceNumber getEntryPoint() {
		return pcodeEntry;
	}

	/**
	 * When done processing a particular instruction, this method should be invoked to 
	 * clear any unique Varnode state.
	 * @return previous unique state
	 */
	public HashMap<Long, Varnode> clearUniqueState() {
		HashMap<Long, Varnode> oldMap = uniqueMap;
		if (uniqueMap != null) {
			uniqueMap = new HashMap<Long, Varnode>();
		}
		return oldMap;
	}

	/**
	 * When no longer updating this state, this method should be invoked to
	 * cleanup resources no longer needed (e.g., uniqueState no longer 
	 * maintained).
	 */
	public void lock() {
		uniqueMap = null;
		locked = true;
	}

	private String getFrameMapName(String spaceName, Varnode framePointer) {
		if (framePointer.isUnique() || framePointer.isConstant()) {
// TODO: May need to handle VarnodeOperation for more complicated access
			throw new IllegalArgumentException("Invalid frame pointer");
		}
// TODO: Map name needs to factor in current value assigned to framePointer
		return spaceName + "/" + framePointer.getAddress().toString(true);
	}

	private HashMap<Long, Varnode> getFrameMap(String frameMapName, boolean forUpdate) {

		HashMap<Long, Varnode> map = null;
		if (frameMaps == null) {
			if (!forUpdate) {
				return null;
			}
			frameMaps = new HashMap<String, HashMap<Long, Varnode>>();
		}
		else {
			map = frameMaps.get(frameMapName);
		}
		if (map == null && forUpdate) {
			map = new HashMap<Long, Varnode>();
			frameMaps.put(frameMapName, map);
		}
		return map;
	}

	private VarnodeOperation getOperation(Address addr, int opcode, Varnode[] inputs, Varnode output) {
		if (addr == null) {
			// TODO: We should probably require an address
			addr = Address.NO_ADDRESS;
		}
		return new VarnodeOperation(new PcodeOp(addr, -1, opcode, inputs, output), inputs);
	}

	/**
	 * Get a new varnode which corresponds to the specified bytePos within the specified varnode.
	 * @param varnode
	 * @param bytePos
	 * @return
	 */
	private Varnode getVarnodeByte(Varnode varnode, int bytePos) {
		if (varnode instanceof VarnodeOperation) {
			return new MaskedVarnodeOperation((VarnodeOperation) varnode, bytePos, 1);
		}
		if (varnode.isConstant()) {
			long val = (varnode.getOffset() >>> (8 * bytePos)) & 0xff;
			return new Varnode(addrFactory.getConstantAddress(val), 1);
		}
		long offset = language.isBigEndian() ? varnode.getSize() - bytePos - 1 : bytePos;
		Address addr = varnode.getAddress().addWrap(offset);
		return new Varnode(addr, 1);
	}

	static class FrameNode {
		private long frameOffset;
		private Varnode framePointer;
		private Language language;

		FrameNode(Varnode framePointer, long frameOffset, Language language) {
			this.framePointer = framePointer;
			this.frameOffset = frameOffset;
			this.language = language;
		}

		@Override
		public String toString() {
			return framePointer.toString(language) + "[" +
				NumericUtilities.toSignedHexString(frameOffset) + "]";
		}

		Varnode getFramePointer() {
			return framePointer;
		}

		long getFrameOffset() {
			return frameOffset;
		}
	}

	static FrameNode getFrameNode(Varnode offsetValue, Language language) {
		long frameOffset = 0;
		Varnode framePointer;
		if (offsetValue instanceof VarnodeOperation) {
			VarnodeOperation op = (VarnodeOperation) offsetValue;
			int opCode = op.getPCodeOp().getOpcode();
			if (opCode != PcodeOp.INT_ADD && opCode != PcodeOp.INT_SUB) {
				return null; // unsupported offsetValue operation
			}
			Varnode[] inputValues = op.getInputValues();
			if (inputValues[0].isConstant()) {
				frameOffset = ResultsState.getSignedOffset(inputValues[0]);
				framePointer = inputValues[1];
			}
			else if (inputValues[1].isConstant()) {
				frameOffset = ResultsState.getSignedOffset(inputValues[1]);
				framePointer = inputValues[0];
			}
			else {
				return null; // only INT_ADD and INT_SUB with constant is supported
			}
			if (opCode == PcodeOp.INT_SUB) {
				frameOffset = -frameOffset;
			}
		}
		else {
			// address, register or unique
			framePointer = offsetValue;
		}
		return new FrameNode(framePointer, frameOffset, language);
	}

	public boolean store(int spaceID, Varnode offsetValue, Varnode storedValue, int size) {

		if (locked) {
			throw new IllegalStateException("State is locked");
		}

		AddressSpace addressSpace = addrFactory.getAddressSpace(spaceID);
		if (addressSpace == null) {
			throw new IllegalArgumentException("Unknown spaceID");
		}

		if (storedValue.isConstant() && storedValue.getSize() == 0) {
			// Morph unsized constant
			storedValue =
				new Varnode(addrFactory.getConstantAddress(storedValue.getOffset()), size);
		}
		else if (size != storedValue.getSize()) {
			throw new IllegalArgumentException("storeValue size mismatch");
		}

		cachedLocation = null;
		cachedValue = null;

		if (offsetValue.isConstant()) {
			try {
				Address addr = addressSpace.getAddress(offsetValue.getOffset(), true);
				store(new Varnode(addr, size), storedValue);
				return true;
			}
			catch (AddressOutOfBoundsException e) {
			}
			// TODO: what should we invalidate ?
			if (DEBUG)
				Msg.debug(this, " Store failed: spaceID=" + spaceID + ", offsetValue: " +
					offsetValue.getOffset());
			return false;
		}

		// Handle relative offsets (limited support)
		FrameNode frameNode = getFrameNode(offsetValue, language);
		if (frameNode == null) {
			// TODO: what should we invalidate ?
			if (DEBUG)
				Msg.debug(this, " Store failed: spaceID=" + spaceID + ", offsetValue: " +
					offsetValue.toString(language));
			return false;
		}

		if (debugVarnode == null || frameNode.framePointer.equals(debugVarnode)) {
			if (DEBUG)
				Msg.debug(this, " Store: " + frameNode + " <- " + storedValue.toString(language));
		}

// TODO: Frame reference callback (write) ??

		String frameMapName = getFrameMapName(addressSpace.getName(), frameNode.framePointer);
		HashMap<Long, Varnode> frameMap = getFrameMap(frameMapName, true);
		if (size == 1) {
			frameMap.put(frameNode.frameOffset, storedValue);
		}
		else {
			long baseOffset = frameNode.frameOffset;
			for (int i = 0; i < size; i++) {
				Varnode byteValue = getVarnodeByte(storedValue, i);
				long byteOffset = language.isBigEndian() ? (size - i - 1) : i;
				frameMap.put(baseOffset + byteOffset, byteValue);
			}
		}
		return true;
	}

	/**
	 * Store a value.  Unique varnodes not permitted once locked.
	 * @param addressVarnode identifies storage (address, register or unique)
	 * @param storedValue constant or OperationVarnode
	 */
	public void store(Varnode addressVarnode, Varnode storedValue) {
		if (addressVarnode instanceof VarnodeOperation || addressVarnode.isConstant()) {
			throw new IllegalArgumentException("May not store value to constant varnode");
		}
		if (locked) {
			throw new IllegalStateException("State is locked");
		}
		int size = addressVarnode.getSize();
		if (storedValue.getSize() != size) {
			throw new IllegalArgumentException("Argument size mismatch");
		}
		cachedLocation = null;
		cachedValue = null;
		if (debugVarnode == null || addressVarnode.equals(debugVarnode)) {
			if (DEBUG)
				Msg.debug(this, " Store: " + addressVarnode.toString(language) + " <- " +
					storedValue.toString(language));
		}
		if (addressVarnode.isUnique()) {
			if (uniqueMap == null) {
				uniqueMap = new HashMap<Long, Varnode>();
			}
			uniqueMap.put(addressVarnode.getOffset(), storedValue);
			return;
		}
		if (addressVarnode.equals(storedValue)) {
			if (DEBUG)
				Msg.debug(this, "Location value restored: " + addressVarnode.toString(language));
		}
		if (size == 1) {
			memoryMap.put(addressVarnode.getAddress(), storedValue);
		}
		else {
			Address baseAddr = addressVarnode.getAddress();
			for (int i = 0; i < size; i++) {
				Varnode byteValue = getVarnodeByte(storedValue, i);
				long byteOffset = language.isBigEndian() ? (size - i - 1) : i;
				memoryMap.put(baseAddr.addWrap(byteOffset), byteValue);
			}
		}
	}

	/**
	 * Retrieve the value/operation stored within the specified space using an offset
	 * identified by a value/operation.
	 * @param spaceID
	 * @param offsetValue
	 * @param size
	 * @return stored value/operation or null or DUMMY_BYTE_VARNODE
	 */
	public Varnode get(int spaceID, Varnode offsetValue, int size) {
		try {
			return get(spaceID, offsetValue, size, TaskMonitorAdapter.DUMMY_MONITOR);
		}
		catch (CancelledException e) {
			throw new AssertException(e); // unexpected
		}
	}

	/**
	 * Retrieve the value/operation stored within the specified space using an offset
	 * identified by a value/operation.
	 * @param spaceID
	 * @param offsetValue
	 * @param size
	 * @return stored value/operation or null or DUMMY_BYTE_VARNODE
	 */
	public Varnode get(int spaceID, Varnode offsetValue, int size, TaskMonitor monitor)
			throws CancelledException {
		AddressSpace addressSpace = addrFactory.getAddressSpace(spaceID);
		if (addressSpace == null) {
			throw new IllegalArgumentException("Unknown spaceID: " + spaceID);
		}
		if (spaceID == cachedSpaceId && offsetValue.equals(cachedLocation) &&
			(cachedValue == null || cachedValue.getSize() == size)) {
			return cachedValue;
		}
		cachedSpaceId = spaceID;
		cachedLocation = offsetValue;
		if (offsetValue.isConstant()) {
			try {
				Address addr = addressSpace.getAddress(offsetValue.getOffset());
				Varnode value = get(new Varnode(addr, size), monitor);
				cachedValue = value;
				return value;
			}
			catch (AddressOutOfBoundsException e) {
			}
			if (DEBUG)
				Msg.debug(this,
					" Get failed: spaceID=" + spaceID + ", offsetValue: " + offsetValue.getOffset());
			cachedValue = null;
			return null;
		}

		FrameNode frameNode = getFrameNode(offsetValue, language);
		if (frameNode == null) {
			if (DEBUG)
				Msg.debug(
					this,
					" Get failed: spaceID=" + spaceID + ", offsetValue: " +
						offsetValue.toString(language));
			cachedValue = null;
			return null;
		}

// TODO: Frame reference callback (read) ??

		String frameMapName = getFrameMapName(addressSpace.getName(), frameNode.framePointer);
		Varnode[] bytes = new Varnode[size];
		long baseOffset = frameNode.frameOffset;
		for (int i = 0; i < size; i++) {
			int bytePos = language.isBigEndian() ? (size - i - 1) : i;
			bytes[bytePos] = getByte(frameMapName, baseOffset + i);
			if (bytes[bytePos] == null) {
				// TODO: partial values are unsupported
				if (debugVarnode == null || frameNode.framePointer.equals(debugVarnode)) {
					if (DEBUG)
						Msg.debug(this, " Get failed: " + frameNode + " has unknown bytes");
				}
				cachedValue = null;
				return null;
			}
		}

		Varnode returnVal = combineByteValues(bytes, monitor);
		if (debugVarnode == null || frameNode.framePointer.equals(debugVarnode)) {
			if (DEBUG)
				Msg.debug(this,
					" Get: " + frameNode + " [" + size + "] is " + returnVal.toString(language));
		}
		cachedValue = returnVal;
		return returnVal;
	}

	/**
	 * Retrieve the value/operation stored in the specified addressable location (address or register varnode).
	 * If varnode is a constant, the input argument will be returned.
	 * Unique varnodes not permitted once locked.
	 * @param varnode identifies constant or storage (constant, address, register or unique), if VarnodeOperation
	 * specified null will always be returned.
	 * @return stored value/operation
	 */
	public Varnode get(Varnode varnode) {
		try {
			return get(varnode, TaskMonitorAdapter.DUMMY_MONITOR);
		}
		catch (CancelledException e) {
			throw new AssertException(e); // unexpected
		}
	}

	/**
	 * Retrieve the value/operation stored in the specified addressable location (address or register varnode).
	 * If varnode is a constant, the input argument will be returned.
	 * Unique varnodes not permitted once locked.
	 * @param varnode identifies constant or storage (constant, address, register or unique), if VarnodeOperation
	 * specified null will always be returned.
	 * @return stored value/operation
	 */
	public Varnode get(Varnode varnode, TaskMonitor monitor) throws CancelledException {
		if (varnode instanceof VarnodeOperation) {
			// Values not stored at expression without space-id
			return null;
		}
		if (varnode.isConstant()) {
			return varnode;
		}
		if (varnode.isUnique()) {
			if (uniqueMap == null) {
				return null;
			}
			return uniqueMap.get(varnode.getOffset());
		}
		if (cachedSpaceId == -1 && varnode.equals(cachedLocation)) {
			return cachedValue;
		}

		cachedSpaceId = -1;
		cachedLocation = varnode;

		Address baseAddr = varnode.getAddress();
		int size = varnode.getSize();

		int zeroMemoryByteCnt = 0;
		Varnode[] bytes = new Varnode[size]; // least-significant-byte stored in 0th element
		try {
			for (int i = 0; i < size; i++) {
				int bytePos = language.isBigEndian() ? (size - i - 1) : i;
				bytes[bytePos] = getByte(baseAddr.add(i));
				if (bytes[bytePos] == null) {
					bytes = null;
					break;
				}
				else if ((bytes[bytePos] instanceof MemoryByteVarnode) &&
					bytes[bytePos].getOffset() == 0) {
					++zeroMemoryByteCnt;
				}
			}
		}
		catch (MemoryAccessException e) {
			bytes = null;
		}
		catch (AddressOutOfBoundsException e) {
			bytes = null;
		}
		if (bytes == null || zeroMemoryByteCnt == bytes.length) {
			// one or mores bytes could not be read or all bytes are zero memory bytes
			if (varnode.isAddress()) {
				cachedValue = varnode;
				return varnode;
			}
			cachedValue = null;
			return null;
		}
		Varnode returnVal = combineByteValues(bytes, monitor);
		if (debugVarnode == null || varnode.equals(debugVarnode)) {
			String str = varnode.toString(language);
			if (str.indexOf(':') < 0) {
				str += ":" + varnode.getSize();
			}
			if (DEBUG)
				Msg.debug(this, " Get: " + str + " is " + returnVal.toString(language));
		}
		cachedValue = returnVal;
		return returnVal;
	}

	/**
	 * MaskedVarnodeOperation provides a wrapper for VarnodeOperation objects
	 * to specify an affective mask/shift of a larger-than-byte operation.
	 * The object are not intended for internal use only and must not be used
	 * as a key value.
	 */
	private static class MaskedVarnodeOperation extends Varnode {
		private final VarnodeOperation op;
		private final int byteShift;

		MaskedVarnodeOperation(VarnodeOperation op, int byteShift, int size) {
			super(op.getAddress(), size);
			this.op = op;
			this.byteShift = byteShift;
		}

		@Override
		public String toString() {
			return "MaskedVarnodeOperation(" + byteShift + ", " + getSize() + "):" + op.toString();
		}
	}

	/**
	 * Combine byte values into a single varnode value.
	 * @param byteValues bytes stored with LSB in bytes[0] and MSB in bytes[bytes.length-1] with correct endianess.
	 * @return varnode or null
	 */
	private Varnode combineByteValues(Varnode[] byteValues, TaskMonitor monitor)
			throws CancelledException {

		ArrayList<Varnode> resultList = new ArrayList<Varnode>();
		Varnode v = byteValues[0];
		int nextIndex = 1;
		int size = 1;
		while (nextIndex < byteValues.length) {
			Varnode result = combineValues(byteValues[nextIndex], v);
			if (result == null) {
				resultList.add(v);
				v = byteValues[nextIndex++];
				size = 1;
			}
			else {
				v = result;
				++nextIndex;
				++size;
			}
		}
		resultList.add(v);

		// TODO: not all bytes are known - should we specify a mask of known bits/bytes

		Varnode result = resultList.get(0);
		int cnt = resultList.size();
		if (cnt == 1 || result == null) {
			return normalizeExpression(result, byteValues.length);
		}
		result = leftShiftExpression(result, 0, result.getSize(), monitor);
		for (int i = 1; i < cnt; i++) {
			Varnode next = resultList.get(i);
			if (next == null) {
				return null;
			}
			size = result.getSize() + next.getSize();
			next = leftShiftExpression(next, result.getSize(), size, monitor);

			Varnode[] inputs = new Varnode[] { zeroExtendExpression(result, size), next };
			PcodeOp op =
				new PcodeOp(Address.NO_ADDRESS, -1, PcodeOp.INT_ADD, inputs, new Varnode(
					Address.NO_ADDRESS, size));
			result = ResultsState.simplify(op, inputs, addrFactory, monitor);
			if (result == null) {
				result = new VarnodeOperation(op, inputs);
			}
		}
		return result;
	}

	private Varnode zeroExtendExpression(Varnode v, int size) {
		if (v.isConstant()) {
			return new Varnode(addrFactory.getConstantAddress(v.getOffset()), size);
		}
		if (v instanceof MaskedVarnodeOperation) {
			MaskedVarnodeOperation mvOp = (MaskedVarnodeOperation) v;
			return new MaskedVarnodeOperation(mvOp.op, mvOp.byteShift, size);
		}
		Varnode[] inputs;
		inputs = new Varnode[] { v };
		return getOperation(Address.NO_ADDRESS, PcodeOp.INT_ZEXT, inputs, new Varnode(
			Address.NO_ADDRESS, size));
	}

	private Varnode leftShiftExpression(Varnode v, int byteShift, int size, TaskMonitor monitor)
			throws CancelledException {
		if (size <= byteShift) {
			return new Varnode(addrFactory.getConstantAddress(0), size);
		}
		if (v instanceof MaskedVarnodeOperation) {
			// remove MaskedVarnodeOperation
			MaskedVarnodeOperation mvOp = (MaskedVarnodeOperation) v;
			if (byteShift == mvOp.byteShift && mvOp.op.getSize() <= 8) {
				long mask = VALUE_MASK[mvOp.op.getSize()] & ~VALUE_MASK[byteShift];
				Varnode[] inputs;
				inputs =
					new Varnode[] { mvOp.op,
						new Varnode(addrFactory.getConstantAddress(mask), mvOp.op.getSize()) };

				PcodeOp op =
					new PcodeOp(Address.NO_ADDRESS, -1, PcodeOp.INT_AND, inputs, new Varnode(
						Address.NO_ADDRESS, size));

				v = ResultsState.simplify(op, inputs, addrFactory, monitor);
				if (v == null) {
					v = new VarnodeOperation(op, inputs);
				}

				if (v.getSize() != size) {
					v = zeroExtendExpression(v, size);
				}
				return v;
			}
			v = normalizeExpression(v, size);
		}
		if (v.isConstant()) {
			return new Varnode(addrFactory.getConstantAddress(v.getOffset() << (byteShift * 8)),
				size);
		}
		if (v.getSize() != size) {
			v = zeroExtendExpression(v, size);
		}
		if (byteShift == 0) {
			return v;
		}
		Varnode[] inputs;
		inputs = new Varnode[] { v, new Varnode(addrFactory.getConstantAddress(byteShift * 8), 1) };
		return getOperation(Address.NO_ADDRESS, PcodeOp.INT_LEFT, inputs, new Varnode(
			Address.NO_ADDRESS, size));
	}

	private Varnode combineValues(Varnode leftValue, Varnode rightValue) {
		if (leftValue == null || rightValue == null) {
			return null; // can't combine - missing value
		}
		if (leftValue instanceof MaskedVarnodeOperation) {
			if (rightValue instanceof MaskedVarnodeOperation) {
				MaskedVarnodeOperation leftOp = (MaskedVarnodeOperation) leftValue;
				MaskedVarnodeOperation rightOp = (MaskedVarnodeOperation) rightValue;
				if (leftOp.op == rightOp.op &&
					leftOp.byteShift == (rightOp.getSize() + rightOp.byteShift)) {
					int size = leftOp.getSize() + rightOp.getSize();
					if (rightOp.byteShift == 0 && size == rightOp.op.getSize()) {
						return rightOp.op;
					}
					return new MaskedVarnodeOperation(rightOp.op, rightOp.byteShift, size);
				}
			}
			return null;  // can't combine
		}
		if (leftValue.isConstant()) {
			if (rightValue.isConstant()) {
				// Combine constant values
				int leftShift = rightValue.getSize() * 8;
				long rightMask = (1L << leftShift) - 1;
				long val =
					(rightValue.getOffset() & rightMask) + (leftValue.getOffset() << leftShift);
				return new Varnode(addrFactory.getConstantAddress(val), leftValue.getSize() +
					rightValue.getSize());
			}
			return null;  // can't combine
		}

		// Combine adjacent address/register nodes 
		Address addr;
		if (leftValue.getSpace() != rightValue.getSpace()) {
			return null;  // can't combine
		}
		if (language.isBigEndian()) {
			if (rightValue.getOffset() != (leftValue.getOffset() + leftValue.getSize())) {
				return null;  // can't combine
			}
			addr = leftValue.getAddress();
		}
		else {
			if (leftValue.getOffset() != (rightValue.getOffset() + rightValue.getSize())) {
				return null;  // can't combine
			}
			addr = rightValue.getAddress();
		}
		return new Varnode(addr, leftValue.getSize() + rightValue.getSize());
	}

	/**
	 * Normalizes varnode expression by removing use of MaskedVarnodeOperation if present and ensure that
	 * returned varnode has a size of targetSize.
	 * @param v
	 * @param targetSize
	 * @return
	 */
	private Varnode normalizeExpression(Varnode v, int targetSize) {
		Varnode result = v;
		if (v instanceof MaskedVarnodeOperation) {
			MaskedVarnodeOperation maskedOp = (MaskedVarnodeOperation) v;
			result = maskedOp.op;
			int opcode = maskedOp.op.getPCodeOp().getOpcode();
			Varnode[] opInputs = maskedOp.op.getInputValues();
			if (maskedOp.byteShift == 0) {
				if ((opcode == PcodeOp.INT_ZEXT || opcode == PcodeOp.INT_SEXT) &&
					opInputs[0].getSize() >= targetSize) {
					result = opInputs[0];
				}
			}
			else {
				// Apply byte-shift
				if (opcode == PcodeOp.INT_ZEXT && opInputs[0].getSize() <= maskedOp.byteShift) {
					return new Varnode(addrFactory.getConstantAddress(0), targetSize); // return zero value
				}
				Varnode mask =
					new Varnode(addrFactory.getConstantAddress(-(1L << (8 * maskedOp.byteShift))),
						result.getSize());
				mask.trim();
				Varnode[] inputs = new Varnode[] { result, mask };
				result =
					getOperation(result.getAddress(), PcodeOp.INT_AND, inputs, new Varnode(
						Address.NO_ADDRESS, result.getSize()));
			}
		}
		if (result != null) {
			if (result.isConstant()) {
				if (result.getSize() != targetSize) {
					long val = result.getOffset();
					result = new Varnode(addrFactory.getConstantAddress(val), targetSize);
				}
			}
			else if (result.getSize() < targetSize) {
				Varnode[] inputs = new Varnode[] { result };
				result =
					getOperation(Address.NO_ADDRESS, PcodeOp.INT_ZEXT, inputs, new Varnode(
						Address.NO_ADDRESS, targetSize));
			}
			else if (result.getSize() > targetSize) {
				Varnode[] inputs =
					new Varnode[] { result,
						new Varnode(addrFactory.getConstantAddress(targetSize), 1) };
				result =
					getOperation(Address.NO_ADDRESS, PcodeOp.SUBPIECE, inputs, new Varnode(
						Address.NO_ADDRESS, targetSize));
			}
		}
		return result;
	}

	private Varnode getByte(String frameMapName, long offset) {
		HashMap<Long, Varnode> frameMap = getFrameMap(frameMapName, false);
		if (frameMap != null) {
			Varnode v = frameMap.get(offset);
			if (v != null) {
				return v;
			}
		}
		if (previousState != null) {
			return previousState.getByte(frameMapName, offset);
		}
		return null;
	}

	private Varnode getByte(Address address) throws MemoryAccessException {
		Varnode value = memoryMap.get(address);
		if (value != null) {
			return value;
		}
		if (previousState != null) {
			return previousState.getByte(address);
		}
		if (address.isMemoryAddress()) {
			if (memory == null) {
				throw new MemoryAccessException("No memory found for " + address);
			}
			MemoryBlock block = memory.getBlock(address);
			if (block != null && block.isInitialized() && !block.isVolatile()) {
				byte val = block.getByte(address);
				return new MemoryByteVarnode(val);
			}
		}
		return null;
	}

	/**
	 * MemoryByteVarnode provides an indication that this
	 * constant varnode was speculatively loaded from program memory.
	 */
	private class MemoryByteVarnode extends Varnode {
		public MemoryByteVarnode(byte val) {
			super(addrFactory.getConstantAddress(val), 1);
		}
	}

	public List<Register> getDifferingRegisters(ContextState other) {
		List<Register> regList = null;
		for (Register reg : language.getRegisters()) {
			if (reg.isProcessorContext() || reg.isProgramCounter()) {
				continue;
			}
			Varnode v = new Varnode(reg.getAddress(), reg.getMinimumByteSize());
			Varnode val1 = get(v);
			Varnode val2 = other.get(v);
			if (val1 != null && val2 != null && !val1.equals(val2)) {
				if (regList == null) {
					regList = new ArrayList<Register>();
				}
				regList.add(reg);
			}
		}
		return regList;
	}

	public boolean hasDifferingRegisters(ContextState other) {
		for (Register reg : language.getRegisters()) {
			if (reg.isProcessorContext() || reg.isProgramCounter()) {
				continue;
			}
			Varnode v = new Varnode(reg.getAddress(), reg.getMinimumByteSize());
			Varnode val1 = get(v);
			Varnode val2 = other.get(v);
			if (val1 != null && val2 != null && !val1.equals(val2)) {
				return true;
			}
		}
		return false;
	}

//	public boolean isStackPointerValid() {
//		if (!stackPointerIsValid) {
//			return false;
//		}
//		if (previousState != null) {
//			return previousState.isStackPointerValid();
//		}
//		return stackPointerIsValid;
//	}
//	
//	public void invalidateStackPointer() {
//		stackPointerIsValid = false;
//	}

}
