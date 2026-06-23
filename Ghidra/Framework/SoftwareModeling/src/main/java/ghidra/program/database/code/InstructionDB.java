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
package ghidra.program.database.code;

import java.util.*;

import db.DBRecord;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.program.util.ProgramEvent;
import ghidra.util.Lock.Closeable;
import ghidra.util.Msg;
import ghidra.util.exception.NoValueException;

/**
 * Database implementation for an Instruction.
 */
public class InstructionDB extends CodeUnitDB implements Instruction, InstructionContext {

	private static final byte FALLTHROUGH_SET_MASK = 0x01;
	private static final byte FALLTHROUGH_CLEAR_MASK = ~FALLTHROUGH_SET_MASK;

	private static final byte FLOW_OVERRIDE_SET_MASK = 0x0e;
	private static final byte FLOW_OVERRIDE_CLEAR_MASK = ~FLOW_OVERRIDE_SET_MASK;
	private static final int FLOW_OVERRIDE_SHIFT = 1;

	private static final byte LENGTH_OVERRIDE_SET_MASK = 0x70;
	private static final byte LENGTH_OVERRIDE_CLEAR_MASK = ~LENGTH_OVERRIDE_SET_MASK;
	private static final int LENGTH_OVERRIDE_SHIFT = 4;

	private InstructionPrototype proto;
	private byte flags;
	private FlowOverride flowOverride;
	private int lengthOverride;
	private final static Address[] EMPTY_ADDR_ARRAY = new Address[0];
	private final static Object[] EMPTY_OBJ_ARRAY = new Object[0];
	private volatile boolean clearingFallThroughs = false;

	private ParserContext parserContext;	// uses lazy initialization
	private String mnemonicString;			// uses lazy initialization

	/**
	 * Construct a new InstructionDB.
	 * @param codeMgr code manager
	 * @param address min address of this instruction
	 * @param addr database key
	 * @param proto instruction prototype
	 * @param flags flow override flags
	 */
	InstructionDB(CodeManager codeMgr, Address address, long addr, InstructionPrototype proto,
			byte flags) {
		super(codeMgr, addr, address, addr, proto.getLength());
		this.proto = proto;
		this.flags = flags;
		flowOverride =
			FlowOverride.getFlowOverride((flags & FLOW_OVERRIDE_SET_MASK) >> FLOW_OVERRIDE_SHIFT);
		refreshLength();
	}

	@Override
	protected boolean refresh(DBRecord record) {
		parserContext = null;
		mnemonicString = null;
		return super.refresh(record);
	}

	@Override
	protected int getPreferredCacheLength() {
		// cache the first delay slot if present
		return proto.hasDelaySlots() ? (length * 2) : length;
	}

	private void refreshLength() {
		length = proto.getLength();
		lengthOverride = (flags & LENGTH_OVERRIDE_SET_MASK) >> LENGTH_OVERRIDE_SHIFT;
		if (lengthOverride != 0 && lengthOverride < length) {
			length = lengthOverride;
		}
		else {
			lengthOverride = 0;
		}
	}

	/**
	 * Get the instruction code unit length based upon its prototype and flags 
	 * which will be used to check for a length-override condition.
	 * @param proto instruction prototype
	 * @param flags instruction flags
	 * @return instruction code unit length
	 */
	static int getLength(InstructionPrototype proto, byte flags) {
		int length = proto.getLength();
		int lengthOverride = (flags & LENGTH_OVERRIDE_SET_MASK) >> LENGTH_OVERRIDE_SHIFT;
		if (lengthOverride != 0 && lengthOverride < length) {
			length = lengthOverride;
		}
		else {
			lengthOverride = 0;
		}
		return length;
	}

	@Override
	protected boolean hasBeenDeleted(DBRecord rec) {
		if (rec == null) {
			rec = codeMgr.getInstructionRecord(addr);
			if (rec == null) {
				return true;
			}
		}
		// ensure that record provided corresponds to a DataDB record
		// since following an undo/redo the record could correspond to
		// a different type of code unit (hopefully with a different record schema)
		else if (!rec.hasSameSchema(InstDBAdapter.INSTRUCTION_SCHEMA)) {
			return true;
		}
		int newProtoID = rec.getIntValue(InstDBAdapter.PROTO_ID_COL);
		InstructionPrototype newProto = codeMgr.getInstructionPrototype(newProtoID);
		if (newProto == null) {
			Msg.error(this, "Instruction found but prototype missing at " + address);
			return true;
		}
		if (!newProto.equals(proto)) {
			return true;
		}

		flags = rec.getByteValue(InstDBAdapter.FLAGS_COL);
		flowOverride =
			FlowOverride.getFlowOverride((flags & FLOW_OVERRIDE_SET_MASK) >> FLOW_OVERRIDE_SHIFT);
		refreshLength();
		return false;
	}

	@Override
	public int getDelaySlotDepth() {
		if (!proto.hasDelaySlots()) {
			return 0;
		}
		try (Closeable c = lock.read()) {
			return proto.getDelaySlotDepth(this);
		}
	}

	/**
	 * Get the original context used to establish the shared prototype
	 * @param baseContextReg is a context register
	 * @return prototype context value
	 */
	public RegisterValue getOriginalPrototypeContext(Register baseContextReg) {
		try {
			return codeMgr.getOriginalPrototypeContext(proto, baseContextReg);
		}
		catch (NoValueException e) {
			Msg.error(this, "Unexpected Error", e);
		}
		return null;
	}

	@Override
	public int getParsedLength() {
		return isLengthOverridden() ? proto.getLength() : getLength();
	}

	@Override
	public byte[] getParsedBytes() throws MemoryAccessException {
		if (!isLengthOverridden()) {
			return getBytes();
		}
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			int len = proto.getLength();
			byte[] b = new byte[len];
			if (len != getMemory().getBytes(address, b)) {
				throw new MemoryAccessException("Failed to read " + len + " bytes at " + address);
			}
			return b;
		}
	}

	@Override
	public Address getFallFrom() {
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			// check if the instruction before this is in a delay slot
			// If it is then back up until hit an instruction that claims
			// to be a delay slot instruction that is not in a delay slot
			// itself.
			Instruction instr = this;
			int alignment = program.getLanguage().getInstructionAlignment();
			if (alignment < 1) {
				alignment = 1;
			}

			do {
				// skip past delay slot instructions which satisfy specific conditions
				try {
					instr = program.getListing()
							.getInstructionContaining(
								instr.getMinAddress().subtractNoWrap(alignment));
				}
				catch (AddressOverflowException e) {
					return null;
				}
			}
			// Continue walking instructions backwards if a delay-slot instruction is found and 
			// either the delay slot instruction does not fallthrough or it does not have a 
			// ref or label on it.
			while (instr != null && instr.isInDelaySlot() && (!instr.hasFallthrough() ||
				!program.getSymbolTable().hasSymbol(instr.getMinAddress())));

			if (instr == null) {
				return null;
			}

			if (isInDelaySlot()) {
				// If this instruction is within delay-slot, return a null fall-from address if 
				// previous instruction (i.e., instruction with delay slot, found above)
				// does not have a fallthrough and this instruction has a ref or label on it.
				if (!instr.hasFallthrough() &&
					program.getSymbolTable().hasSymbol(getMinAddress())) {
					return null;
				}
				// Return previous instruction's address (i.e., instruction with delay slot, found above)
				return instr.getMinAddress();
			}

			// No delay-slot, but check if the instruction falls into this one.
			Address fallAddr = instr.getFallThrough();
			if (fallAddr != null && fallAddr.equals(address)) {
				return instr.getMinAddress();
			}

			return null;
		}
	}

	private Address getFallThroughReference() {
		for (Reference ref : refMgr.getReferencesFrom(address)) {
			if (ref.getReferenceType().isFallthrough() && ref.getToAddress().isMemoryAddress()) {
				return ref.getToAddress();
			}
		}
		return null;
	}

	@Override
	public Address getFallThrough() {
		if (isFallThroughOverridden()) {
			return getFallThroughReference();
		}
		return getDefaultFallThrough();
	}

	@Override
	public Address[] getFlows() {
		validate(lock);
		Reference[] refs = refMgr.getFlowReferencesFrom(address);
		if (refs.length == 0) {
			return EMPTY_ADDR_ARRAY;
		}

		Set<Address> list = new HashSet<>();
		for (Reference ref : refs) {
			if (!ref.getReferenceType().isIndirect()) {
				list.add(ref.getToAddress());
			}
		}

		if (flowOverride == FlowOverride.RETURN && list.size() == 1) {
			return EMPTY_ADDR_ARRAY;
		}

		return list.toArray(new Address[list.size()]);
	}

	@Override
	public Address[] getDefaultFlows() {
		validate(lock);
		Address[] flows = proto.getFlows(this);
		if (flowOverride == FlowOverride.RETURN && flows.length == 1) {
			return EMPTY_ADDR_ARRAY;
		}
		return flows;
	}

	@Override
	public FlowType getFlowType() {
		validate(lock);
		return FlowOverride.getModifiedFlowType(proto.getFlowType(this), flowOverride);
	}

	@Override
	public Instruction getNext() {
		validate(lock);
		return codeMgr.getInstructionAfter(address);
	}

	@Override
	public RefType getOperandRefType(int opIndex) {

		if (opIndex < 0 || opIndex >= getNumOperands()) {
			return null;
		}

		// always reflects current flowOverride
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			return proto.getOperandRefType(opIndex, this, new InstructionPcodeOverride(this));
		}
	}

	@Override
	public String getSeparator(int opIndex) {
		return proto.getSeparator(opIndex);
	}

	@Override
	public String getDefaultOperandRepresentation(int opIndex) {
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			List<Object> opList = getDefaultOperandRepresentationList(opIndex);
			if (opList == null) {
				return "<UNSUPPORTED>";
			}
			StringBuffer strBuf = new StringBuffer();
			for (Object opElem : opList) {
				if (opElem instanceof Address) {
					Address opAddr = (Address) opElem;
					strBuf.append("0x");
					strBuf.append(opAddr.toString(false));
//					long offset = opAddr.getOffset() / opAddr.getAddressSpace().getAddressableUnitSize();
//					strBuf.append("0x");
//					strBuf.append(Long.toHexString(offset));
				}
				else {
					strBuf.append(opElem.toString());
				}
			}
			return strBuf.toString();
		}
	}

	@Override
	public List<Object> getDefaultOperandRepresentationList(int opIndex) {
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			return proto.getOpRepresentationList(opIndex, this);
		}
	}

	@Override
	public int getOperandType(int opIndex) {
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			int optype = proto.getOpType(opIndex, this);

			Reference ref = getPrimaryReference(opIndex);
			if (ref instanceof StackReference) {
				optype |= OperandType.ADDRESS;
				return optype;
			}
			else if (ref instanceof ExternalReference) {
				optype |= OperandType.ADDRESS;
			}
			else if (ref != null && ref.getToAddress().isMemoryAddress()) {
				optype |= OperandType.ADDRESS;
			}
			return optype;
		}
	}

	@Override
	public Object[] getOpObjects(int opIndex) {

		if (opIndex < 0 || opIndex >= getNumOperands()) {
			return EMPTY_OBJ_ARRAY;
		}

		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			return proto.getOpObjects(opIndex, this);
		}
	}

	@Override
	public Instruction getPrevious() {
		validate(lock);
		return codeMgr.getInstructionBefore(address);
	}

	@Override
	public InstructionPrototype getPrototype() {
		return proto;
	}

	@Override
	public Register getRegister(int opIndex) {

		if (opIndex < 0 || opIndex >= getNumOperands()) {
			return null;
		}

		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			return proto.getRegister(opIndex, this);
		}
	}

	@Override
	public Object[] getInputObjects() {
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			return proto.getInputObjects(this);
		}
	}

	@Override
	public Object[] getResultObjects() {
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			return proto.getResultObjects(this);
		}
	}

	@Override
	public boolean isInDelaySlot() {
		return proto.isInDelaySlot();
	}

	@Override
	public Address getAddress(int opIndex) {

		if (opIndex < 0 || opIndex >= getNumOperands()) {
			return null;
		}

		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			Reference ref = refMgr.getPrimaryReferenceFrom(address, opIndex);
			if (ref != null) {
				return ref.getToAddress();
			}

			int opType = proto.getOpType(opIndex, this);

			if (OperandType.isAddress(opType)) {
				return proto.getAddress(opIndex, this);
			}

			return null;
		}
	}

	@Override
	public String toString() {
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			StringBuffer stringBuffer = new StringBuffer();
			stringBuffer.append(getMnemonicString());

			int n = getNumOperands();
			String sep = getSeparator(0);
			if (sep != null || n != 0) {
				stringBuffer.append(' ');
			}
			if (sep != null) {
				stringBuffer.append(sep);
			}

			for (int i = 0; i < n; i++) {
				stringBuffer.append(getDefaultOperandRepresentation(i));
				sep = getSeparator(i + 1);
				if (sep != null) {
					stringBuffer.append(sep);
				}
			}
			return stringBuffer.toString();
		}
	}

	@Override
	public String getMnemonicString() {
		validate(lock);
		String curMnemonic = mnemonicString;
		if (curMnemonic != null) {
			return curMnemonic;
		}
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			mnemonicString = proto.getMnemonic(this);
			return mnemonicString;
		}
	}

	@Override
	public int getNumOperands() {
		return proto.getNumOperands();
	}

	@Override
	public Scalar getScalar(int opIndex) {

		if (opIndex < 0 || opIndex >= getNumOperands()) {
			return null;
		}

		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			return proto.getScalar(opIndex, this);
		}
	}

	/**
	 *
	 * Return true if obj is equal to this.
	 */
	@Override
	public boolean equals(Object obj) {
		if (!super.equals(obj)) {
			return false;
		}
		InstructionDB inst = (InstructionDB) obj;
		return proto.equals(inst.proto);
	}

	@Override
	public FlowOverride getFlowOverride() {
		return flowOverride;
	}

	@Override
	public void setFlowOverride(FlowOverride flow) {
		if (flow == null) {
			flow = FlowOverride.NONE;
		}
		try (Closeable c = lock.write()) {
			checkDeleted();
			if (flow == flowOverride) {
				return;
			}
			FlowType origFlowType = getFlowType();

			flags &= FLOW_OVERRIDE_CLEAR_MASK;
			flags |= (flow.ordinal() << FLOW_OVERRIDE_SHIFT);
			codeMgr.setFlags(addr, flags);
			flowOverride = flow;

			// Update flow references
			for (Reference ref : refMgr.getFlowReferencesFrom(getAddress())) {
				if (!ref.getReferenceType().isFlow()) {
					continue;
				}

				if (!isSameFlowType(origFlowType, ref.getReferenceType())) {
					continue;
				}
				RefType refType = RefTypeFactory.getDefaultMemoryRefType(this,
					ref.getOperandIndex(), ref.getToAddress(), true);
				if (!refType.isFlow() || ref.getReferenceType() == refType) {
					continue;
				}
				refMgr.delete(ref);
				Reference newRef = refMgr.addMemoryReference(ref.getFromAddress(),
					ref.getToAddress(), refType, ref.getSource(), ref.getOperandIndex());
				if (ref.isPrimary()) {
					refMgr.setPrimary(newRef, true);
				}
			}
		}
		program.setChanged(ProgramEvent.FLOW_OVERRIDE_CHANGED, address, address, null, null);
	}

	private boolean isSameFlowType(FlowType origFlowType, RefType referenceType) {
		if (origFlowType.isCall() && referenceType.isCall()) {
			return true;
		}
		if (origFlowType.isJump() && referenceType.isJump()) {
			return true;
		}
		if (origFlowType.isTerminal() && referenceType.isTerminal()) {
			return true;
		}
		return false;
	}

	@Override
	public PcodeOp[] getPcode() {
		return getPcode(false);
	}

	@Override
	public PcodeOp[] getPcode(boolean includeOverrides) {
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			if (!includeOverrides) {
				return proto.getPcode(this, null);
			}
			return proto.getPcode(this, new InstructionPcodeOverride(this));
		}
	}

	@Override
	public PcodeOp[] getPcode(int opIndex) {
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			// assumes operand pcode not affected by flow override
			return proto.getPcode(this, opIndex);
		}
	}

	@Override
	public boolean isFallThroughOverridden() {
		validate(lock);
		return (flags & FALLTHROUGH_SET_MASK) != 0;
	}

	/**
	 * Clear all existing fall-through references from address.
	 * @param keepFallThroughAddr if not null, corresponding fall-through reference will be 
	 * preserved. 
	 */
	private void clearFallThroughRefs(Address keepFallThroughAddr) {
		if (clearingFallThroughs) {
			return;
		}
		validate(lock);
		clearingFallThroughs = true;
		try {
			boolean fallThroughPreserved = false;
			for (Reference ref : refMgr.getReferencesFrom(address)) {
				if (ref.getReferenceType() == RefType.FALL_THROUGH) {
					if (!fallThroughPreserved && ref.getToAddress().equals(keepFallThroughAddr)) {
						fallThroughPreserved = true; // only preserve one
					}
					else {
						refMgr.delete(ref);
					}
				}
			}
		}
		finally {
			clearingFallThroughs = false;
		}
	}

	void fallThroughChanged(Reference fallThroughRef) {
		if (!clearingFallThroughs) {
			Address fallThroughAddr = fallThroughRef != null ? fallThroughRef.getToAddress() : null;
			clearFallThroughRefs(fallThroughAddr); // ensure there is only one fallthrough ref
			if (fallThroughAddr == null) { // fallthrough ref removed
				setFallthroughOverride(false);
				addLengthOverrideFallthroughRef(); // restore length-override fallthrough if needed
			}
			else {
				// enable fallthrough-override if fallThroughRef does not match length-override fallthrough 
				setFallthroughOverride(!fallThroughAddr.equals(getLengthOverrideFallThrough()));
			}
		}
	}

	private void setFallthroughOverride(boolean state) {
		if (state != isFallThroughOverridden()) {
			if (state) {
				flags |= FALLTHROUGH_SET_MASK;
			}
			else {
				flags &= FALLTHROUGH_CLEAR_MASK;
			}
			codeMgr.setFlags(addr, flags);
			program.setChanged(ProgramEvent.FALLTHROUGH_CHANGED, address, address, null, null);
		}
	}

	@Override
	public void clearFallThroughOverride() {
		try (Closeable c = lock.write()) {
			checkDeleted();
			if (!isFallThroughOverridden()) {
				return;
			}
			// clear fall-through override
			clearFallThroughRefs(null);
			setFallthroughOverride(false);
			addLengthOverrideFallthroughRef(); // restore length-override fallthrough if needed
		}

	}

	@Override
	public void setFallThrough(Address fallThroughAddr) {
		try (Closeable c = lock.write()) {
			checkDeleted();
			Address defaultFallThrough = proto.getFallThrough(this);
			if (addrsEqual(fallThroughAddr, defaultFallThrough)) {
				clearFallThroughOverride();
				return;
			}
			if (fallThroughAddr == null) {
				// Fall-through eliminated (i.e., terminal flow) - no reference added
				clearFallThroughRefs(null);
				setFallthroughOverride(true);
			}
			else {
				// Adding fallthough ref will trigger override flag on callback
				refMgr.addMemoryReference(address, fallThroughAddr, RefType.FALL_THROUGH,
					SourceType.USER_DEFINED, Reference.MNEMONIC);
			}
		}
	}

	@Override
	public void setLengthOverride(int len) throws CodeUnitInsertionException {
		try (Closeable c = lock.write()) {
			checkDeleted();
			if (doSetLengthOverride(len)) {
				program.setChanged(ProgramEvent.LENGTH_OVERRIDE_CHANGED, address, address, null,
					null);
			}
		}
	}

	/**
	 * Check and revise a specified {@code length} to arrive at a suitable length-override value.
	 * @param length instruction byte-length (must be in the range 0..{@code prototype-length}).
	 * If smaller than the prototype length it must have a value no greater than 7, otherwise
	 * an error will be thrown.  A value of 0 or greater-than-or-equal the prototype length
	 * will be ignored and not impose and override length.  The length value must be a multiple 
	 * of the {@link Language#getInstructionAlignment() instruction alignment} .
	 * @param prototype instruction prototype
	 * @return length-override value (0 = disable length-override) 
	 * @throws CodeUnitInsertionException thrown if the new Instruction would overlap and 
	 * existing {@link CodeUnit} or the specified {@code length} is unsupported.
	 * @throws IllegalArgumentException if a negative {@code length} is specified.
	 */
	public static int checkLengthOverride(int length, InstructionPrototype prototype)
			throws IllegalArgumentException, CodeUnitInsertionException {
		if (length < 0) {
			throw new IllegalArgumentException("Negative length not permitted");
		}
		int instrProtoLength = prototype.getLength();
		if (length == 0 || length == instrProtoLength) {
			return 0;
		}
		if (length > instrProtoLength) {
			return 0;
		}

		int align = prototype.getLanguage().getInstructionAlignment();
		if (length % align != 0) {
			throw new CodeUnitInsertionException(
				"Length(" + length + ") override must be a multiple of " + align + " bytes");
		}

		if (length > MAX_LENGTH_OVERRIDE) {
			throw new CodeUnitInsertionException("Unsupported length override: " + length);
		}
		return length;
	}

	boolean doSetLengthOverride(int len) throws CodeUnitInsertionException {

		int protoLength = proto.getLength();
		len = checkLengthOverride(len, proto);
		if (len == lengthOverride) {
			return false; // no change
		}

		int instrLength = len != 0 ? len : protoLength;
		if (instrLength > getLength()) {
			Address newEndAddr = address.add(instrLength - 1);
			Address nextCodeUnitAddr = codeMgr.getDefinedAddressAfter(address);
			if (nextCodeUnitAddr != null && nextCodeUnitAddr.compareTo(newEndAddr) <= 0) {
				throw new CodeUnitInsertionException("Length override of " + instrLength +
					" conflicts with code unit at " + nextCodeUnitAddr);
			}
		}

		flags &= LENGTH_OVERRIDE_CLEAR_MASK;
		flags |= (len << LENGTH_OVERRIDE_SHIFT);
		codeMgr.setFlags(addr, flags);

		endAddr = null;
		refreshLength();

		addLengthOverrideFallthroughRef();

		return true;
	}

	private void addLengthOverrideFallthroughRef() {
		if (isLengthOverridden() && !isFallThroughOverridden()) {
			// length-override always uses default fall-through address
			Address defaultFallThrough = getDefaultFallThrough();
			if (defaultFallThrough != null) {
				refMgr.addMemoryReference(address, defaultFallThrough, RefType.FALL_THROUGH,
					SourceType.USER_DEFINED, Reference.MNEMONIC);
			}
		}
	}

	@Override
	public boolean isLengthOverridden() {
		validate(lock);
		return lengthOverride != 0;
	}

	private Address getLengthOverrideFallThrough() {
		return isLengthOverridden() ? getDefaultFallThrough() : null;
	}

	private boolean addrsEqual(Address addr1, Address addr2) {
		if (addr1 == null) {
			return addr2 == null;
		}
		return addr1.equals(addr2);
	}

	@Override
	public Address getDefaultFallThrough() {
		FlowType myFlowType = getFlowType(); // getFlowType will validate
		if (myFlowType.hasFallthrough()) {
			try {
				return address.addNoWrap(getDefaultFallThroughOffset());
			}
			catch (AddressOverflowException e) {
				// ignore
			}
		}
		return null;
	}

	@Override
	public int getDefaultFallThroughOffset() {
		if (proto.getDelaySlotByteCount() <= 0) {
			return proto.getLength();
		}
		try (Closeable c = lock.read()) {
			refreshIfNeeded();
			return proto.getFallThroughOffset(this);
		}
	}

	@Override
	public boolean hasFallthrough() {
		if (isFallThroughOverridden()) {
			return getFallThrough() != null; // fall-through destination stored as reference
		}
		return getFlowType().hasFallthrough();
	}

	@Override
	public boolean isFallthrough() {
		if (!getFlowType().isFallthrough()) {
			return false;
		}
		return hasFallthrough();
	}

	@Override
	public ProcessorContextView getProcessorContext() {
		return this;
	}

	@Override
	public MemBuffer getMemBuffer() {
		return this;
	}

	@Override
	public ParserContext getParserContext() throws MemoryAccessException {
		// NOTE: It is assumed this is invoked and used within a locked block
		if (parserContext == null) {
			parserContext = proto.getParserContext(this, this);
		}
		return parserContext;
	}

	@Override
	public InstructionContext getInstructionContext() {
		return this;
	}

	@Override
	public ParserContext getParserContext(Address instructionAddress)
			throws UnknownContextException, MemoryAccessException {
		if (address.equals(instructionAddress)) {
			return getParserContext();
		}
		InstructionDB instr = (InstructionDB) codeMgr.getInstructionAt(instructionAddress);
		if (instr == null) {
			throw new UnknownContextException(
				"Program does not contain referenced instruction: " + instructionAddress);
		}
		// Ensure that prototype is same implementation
		InstructionPrototype otherProto = instr.getPrototype();
		if (!otherProto.getClass().equals(proto.getClass())) {
			throw new UnknownContextException(
				"Instruction has incompatible prototype at: " + instructionAddress);
		}
		return instr.getParserContext();
	}
}
