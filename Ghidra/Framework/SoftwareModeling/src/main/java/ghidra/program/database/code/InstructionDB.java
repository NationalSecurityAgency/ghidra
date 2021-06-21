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

import java.util.ArrayList;
import java.util.List;

import db.DBRecord;
import ghidra.program.database.DBObjectCache;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.program.util.ChangeManager;
import ghidra.util.Msg;
import ghidra.util.exception.NoValueException;

/**
 * Database implementation for an Instruction.
 */
public class InstructionDB extends CodeUnitDB implements Instruction, InstructionContext {

	private static byte FALLTHROUGH_SET_MASK = (byte) 0x01;
	private static byte FALLTHROUGH_CLEAR_MASK = (byte) 0xfe;

	private static byte FLOWOVERRIDE_MASK = (byte) 0x0e;
	private static byte FLOWOVERRIDE_CLEAR_MASK = (byte) 0xf1;
	private static int FLOWOVERRIDE_SHIFT = 1;

	private InstructionPrototype proto;
	private byte flags;
	private FlowOverride flowOverride;
	private final static Address[] EMPTY_ADDR_ARRAY = new Address[0];
	private volatile boolean clearingFallThroughs = false;

	private ParserContext parserContext;

	/**
	 * Construct a new InstructionDB.
	 * @param codeMgr code manager
	 * @param cache code unit cache
	 * @param address min address of this instruction
	 * @param addr database key
	 * @param proto instruction prototype
	 * @param flags flow override flags
	 */
	public InstructionDB(CodeManager codeMgr, DBObjectCache<? extends CodeUnitDB> cache,
			Address address, long addr, InstructionPrototype proto, byte flags) {
		super(codeMgr, cache, addr, address, addr, proto.getLength());
		this.proto = proto;
		this.flags = flags;
		flowOverride =
			FlowOverride.getFlowOverride((flags & FLOWOVERRIDE_MASK) >> FLOWOVERRIDE_SHIFT);
	}

	@Override
	protected boolean refresh(DBRecord record) {
		parserContext = null;
		return super.refresh(record);
	}

	@Override
	protected int getPreferredCacheLength() {
		// cache the first delay slot if present
		return proto.hasDelaySlots() ? (length * 2) : length;
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
		length = proto.getLength();
		flags = rec.getByteValue(InstDBAdapter.FLAGS_COL);
		flowOverride =
			FlowOverride.getFlowOverride((flags & FLOWOVERRIDE_MASK) >> FLOWOVERRIDE_SHIFT);
		return false;
	}

	@Override
	public int getDelaySlotDepth() {
		if (!proto.hasDelaySlots()) {
			return 0;
		}
		lock.acquire();
		try {
			return proto.getDelaySlotDepth(this);
		}
		finally {
			lock.release();
		}
	}

	/**
	 * Get the original context used to establish the shared prototype
	 * @param baseContextReg
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
	public Address getFallFrom() {
		lock.acquire();
		try {
			checkIsValid();
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
				// skip past delay slot instructions
				try {
					instr = program.getListing().getInstructionContaining(
						instr.getMinAddress().subtractNoWrap(alignment));
				}
				catch (AddressOverflowException e) {
					return null;
				}
			}
			while (instr != null && instr.isInDelaySlot());
			if (instr == null) {
				return null;
			}

			// If this instruction is in a delay slot,
			// it is assumed to always fall from the delay-slotted
			// instruction regardless of its fall-through
			if (this.isInDelaySlot()) {
				return instr.getMinAddress();
			}

			// No delay slot, but check if the instruction falls into this one.
			Address fallAddr = instr.getFallThrough();
			if (fallAddr != null && fallAddr.equals(address)) {
				return instr.getMinAddress();
			}

			return null;
		}
		finally {
			lock.release();
		}
	}

	@Override
	public Address getFallThrough() {
		lock.acquire();
		try {
			checkIsValid();
			if (isFallThroughOverridden()) {
				for (Reference ref : refMgr.getReferencesFrom(address)) {
					if (ref.getReferenceType().isFallthrough() &&
						ref.getToAddress().isMemoryAddress()) {
						return ref.getToAddress();
					}
				}
				return null;
			}
			return getDefaultFallThrough();
		}
		finally {
			lock.release();
		}
	}

	@Override
	public Address[] getFlows() {
		refreshIfNeeded();
		Reference[] refs = refMgr.getFlowReferencesFrom(address);
		if (refs.length == 0) {
			return EMPTY_ADDR_ARRAY;
		}

		ArrayList<Address> list = new ArrayList<Address>();
		for (int i = 0; i < refs.length; ++i) {
			if (!refs[i].getReferenceType().isIndirect()) {
				list.add(refs[i].getToAddress());
			}
		}

		if (flowOverride == FlowOverride.RETURN && list.size() == 1) {
			return EMPTY_ADDR_ARRAY;
		}

		Address[] addrs = new Address[list.size()];
		return list.toArray(addrs);
	}

	@Override
	public Address[] getDefaultFlows() {
		Address[] flows = proto.getFlows(this);
		if (flowOverride == FlowOverride.RETURN && flows.length == 1) {
			return EMPTY_ADDR_ARRAY;
		}
		return flows;
	}

	@Override
	public FlowType getFlowType() {
		return FlowOverride.getModifiedFlowType(proto.getFlowType(this), flowOverride);
	}

	@Override
	public Instruction getNext() {
		refreshIfNeeded();
		return codeMgr.getInstructionAfter(address);
	}

	@Override
	public RefType getOperandRefType(int opIndex) {
		// always reflects current flowOverride
		lock.acquire();
		try {
			checkIsValid();
			return proto.getOperandRefType(opIndex, this, new InstructionPcodeOverride(this),
				new UniqueAddressFactory(program.getAddressFactory(), program.getLanguage()));
		}
		finally {
			lock.release();
		}
	}

	@Override
	public String getSeparator(int opIndex) {
		lock.acquire();
		try {
			return proto.getSeparator(opIndex, this);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public String getDefaultOperandRepresentation(int opIndex) {
		lock.acquire();
		try {
			checkIsValid();
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
		finally {
			lock.release();
		}
	}

	@Override
	public List<Object> getDefaultOperandRepresentationList(int opIndex) {
		lock.acquire();
		try {
			checkIsValid();
			return proto.getOpRepresentationList(opIndex, this);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public int getOperandType(int opIndex) {
		lock.acquire();
		try {
			checkIsValid();
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
		finally {
			lock.release();
		}
	}

	@Override
	public Object[] getOpObjects(int opIndex) {
		lock.acquire();
		try {
			checkIsValid();
			if (opIndex < 0 || opIndex >= getNumOperands()) {
				return new Object[0];
			}
			return proto.getOpObjects(opIndex, this);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public Instruction getPrevious() {
		refreshIfNeeded();
		return codeMgr.getInstructionBefore(address);
	}

	@Override
	public InstructionPrototype getPrototype() {
		return proto;
	}

	@Override
	public Register getRegister(int opIndex) {
		lock.acquire();
		try {
			checkIsValid();
			if (opIndex < 0) {
				return null;
			}
			return proto.getRegister(opIndex, this);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public Object[] getInputObjects() {
		lock.acquire();
		try {
			checkIsValid();
			return proto.getInputObjects(this);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public Object[] getResultObjects() {
		lock.acquire();
		try {
			checkIsValid();
			return proto.getResultObjects(this);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public boolean isInDelaySlot() {
		return proto.isInDelaySlot();
	}

	@Override
	public Address getAddress(int opIndex) {
		lock.acquire();
		try {
			checkIsValid();
			Reference ref = refMgr.getPrimaryReferenceFrom(address, opIndex);
			if (ref != null) {
				return ref.getToAddress();
			}
			if (opIndex < 0) {
				return null;
			}
			int opType = proto.getOpType(opIndex, this);

			if (OperandType.isAddress(opType)) {
				return proto.getAddress(opIndex, this);
			}

			return null;
		}
		finally {
			lock.release();
		}
	}

	@Override
	public String toString() {
		lock.acquire();
		try {
			checkIsValid();
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
		finally {
			lock.release();
		}
	}

	@Override
	public String getMnemonicString() {
		lock.acquire();
		try {
			checkIsValid();
			return proto.getMnemonic(this);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public int getNumOperands() {
		return proto.getNumOperands();
	}

	@Override
	public Scalar getScalar(int opIndex) {
		lock.acquire();
		try {
			checkIsValid();
			if (opIndex < 0) {
				return null;
			}
			return proto.getScalar(opIndex, this);
		}
		finally {
			lock.release();
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
		lock.acquire();
		try {
			checkDeleted();
			if (flow == flowOverride) {
				return;
			}
			FlowType origFlowType = getFlowType();

			flags &= FLOWOVERRIDE_CLEAR_MASK;
			flags |= (flow.ordinal() << FLOWOVERRIDE_SHIFT);
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
		finally {
			lock.release();
		}
		program.setChanged(ChangeManager.DOCR_FLOWOVERRIDE_CHANGED, address, address, null, null);
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
		lock.acquire();
		try {
			checkIsValid();
			if (!includeOverrides) {
				return proto.getPcode(this, null, null);
			}
			return proto.getPcode(this, new InstructionPcodeOverride(this),
				new UniqueAddressFactory(program.getAddressFactory(), program.getLanguage()));
		}
		finally {
			lock.release();
		}
	}

	@Override
	public PcodeOp[] getPcode(int opIndex) {
		lock.acquire();
		try {
			checkIsValid();
			// assumes operand pcode not affected by flow override
			return proto.getPcode(this, opIndex);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public boolean isFallThroughOverridden() {
		return (flags & FALLTHROUGH_SET_MASK) != 0;
	}

	/**
	 * Clear all existing fall-through references from address.
	 * @param keepFallThroughRef if not null, corresponding fall-through reference will be preserved
	 */
	private void clearFallThroughRefs(Reference keepFallThroughRef) {
		if (clearingFallThroughs) {
			return;
		}
		refreshIfNeeded();
		clearingFallThroughs = true;
		try {
			for (Reference ref : refMgr.getReferencesFrom(address)) {
				if (ref.getReferenceType() == RefType.FALL_THROUGH &&
					!ref.equals(keepFallThroughRef)) {
					refMgr.delete(ref);
				}
			}
		}
		finally {
			clearingFallThroughs = false;
		}
	}

	void fallThroughChanged(Reference fallThroughRef) {
		if (!clearingFallThroughs) {
			clearFallThroughRefs(fallThroughRef);
			setFallthroughOverride(fallThroughRef != null &&
				fallThroughRef.getReferenceType() == RefType.FALL_THROUGH);
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
		}
		program.setChanged(ChangeManager.DOCR_FALLTHROUGH_CHANGED, address, address, null, null);
	}

	@Override
	public void clearFallThroughOverride() {
		lock.acquire();
		try {
			checkDeleted();
			if (!isFallThroughOverridden()) {
				return;
			}
			clearFallThroughRefs(null);
			setFallthroughOverride(false);
		}
		finally {
			lock.release();
		}

	}

	@Override
	public void setFallThrough(Address fallThroughAddr) {
		lock.acquire();
		try {
			checkDeleted();
			Address defaultFallThrough = proto.getFallThrough(this);
			if (addrsEqual(fallThroughAddr, defaultFallThrough)) {
				clearFallThroughOverride();
				return;
			}
			if (fallThroughAddr == null) {
				// Fall-through eliminated - no reference added
				clearFallThroughRefs(null);
				setFallthroughOverride(true);
			}
			else {
				refMgr.addMemoryReference(address, fallThroughAddr, RefType.FALL_THROUGH,
					SourceType.USER_DEFINED, Reference.MNEMONIC);
			}
		}
		finally {
			lock.release();
		}

	}

	private boolean addrsEqual(Address addr1, Address addr2) {
		if (addr1 == null) {
			return addr2 == null;
		}
		return addr1.equals(addr2);
	}

	@Override
	public Address getDefaultFallThrough() {
		lock.acquire();
		try {
			// TODO: This used to be in proto.  We need to override the proto's flowtype.
			//       This could be pushed back into the proto if we could override the flowType there.
			FlowType myFlowType = getFlowType();
			if (myFlowType.hasFallthrough()) {
				try {
					return getAddress().addNoWrap(proto.getFallThroughOffset(this));
				}
				catch (AddressOverflowException e) {
					// ignore
				}
			}
			return null;
		}
		finally {
			lock.release();
		}
	}

	@Override
	public int getDefaultFallThroughOffset() {
		lock.acquire();
		try {
			return proto.getFallThroughOffset(this);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public boolean hasFallthrough() {
		lock.acquire();
		try {
			checkIsValid();
			if (isFallThroughOverridden()) {
				return getFallThrough() != null; // fall-through destination stored as reference
			}
			return getFlowType().hasFallthrough();
		}
		finally {
			lock.release();
		}
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
