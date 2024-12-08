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
package ghidra.trace.database.listing;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.*;

import db.DBRecord;
import ghidra.program.database.code.InstructionDB;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.trace.database.DBTrace;
import ghidra.trace.database.DBTraceUtils;
import ghidra.trace.database.context.DBTraceRegisterContextManager;
import ghidra.trace.database.context.DBTraceRegisterContextSpace;
import ghidra.trace.database.guest.DBTraceGuestPlatform.DBTraceGuestLanguage;
import ghidra.trace.database.guest.InternalTracePlatform;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree;
import ghidra.trace.database.symbol.DBTraceReference;
import ghidra.trace.database.symbol.DBTraceReferenceSpace;
import ghidra.trace.model.*;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.listing.TraceInstruction;
import ghidra.trace.model.symbol.TraceReference;
import ghidra.trace.util.*;
import ghidra.util.LockHold;
import ghidra.util.Msg;
import ghidra.util.database.DBCachedObjectStore;
import ghidra.util.database.DBObjectColumn;
import ghidra.util.database.annot.*;

/**
 * The implementation of {@link TraceInstruction} for {@link DBTrace}
 */
@DBAnnotatedObjectInfo(version = 0)
public class DBTraceInstruction extends AbstractDBTraceCodeUnit<DBTraceInstruction>
		implements TraceInstruction, InstructionAdapterFromPrototype, InstructionContext {
	private static final Address[] EMPTY_ADDRESS_ARRAY = new Address[] {};
	private static final String TABLE_NAME = "Instructions";

	private static final byte FALLTHROUGH_SET_MASK = 0x01;
	private static final byte FALLTHROUGH_CLEAR_MASK = ~FALLTHROUGH_SET_MASK;

	private static final byte FLOW_OVERRIDE_SET_MASK = 0x0e;
	private static final byte FLOW_OVERRIDE_CLEAR_MASK = ~FLOW_OVERRIDE_SET_MASK;
	private static final int FLOW_OVERRIDE_SHIFT = 1;

	private static final byte LENGTH_OVERRIDE_SET_MASK = 0x70;
	private static final byte LENGTH_OVERRIDE_CLEAR_MASK = ~LENGTH_OVERRIDE_SET_MASK;
	private static final int LENGTH_OVERRIDE_SHIFT = 4;

	static final String PLATFORM_COLUMN_NAME = "Platform";
	static final String PROTOTYPE_COLUMN_NAME = "Prototype";
	static final String FLAGS_COLUMN_NAME = "Flags";

	@DBAnnotatedColumn(PLATFORM_COLUMN_NAME)
	static DBObjectColumn PLATFORM_COLUMN;
	@DBAnnotatedColumn(PROTOTYPE_COLUMN_NAME)
	static DBObjectColumn PROTOTYPE_COLUMN;
	@DBAnnotatedColumn(FLAGS_COLUMN_NAME)
	static DBObjectColumn FLAGS_COLUMN;

	static String tableName(AddressSpace space, long threadKey) {
		return DBTraceUtils.tableName(TABLE_NAME, space, threadKey, 0);
	}

	/**
	 * A context for guest instructions that maps addresses appropriately
	 */
	protected class GuestInstructionContext implements InstructionContext {
		@Override
		public Address getAddress() {
			return platform.mapHostToGuest(getX1());
		}

		@Override
		public ProcessorContextView getProcessorContext() {
			return DBTraceInstruction.this.getProcessorContext();
		}

		@Override
		public MemBuffer getMemBuffer() {
			return DBTraceInstruction.this.getMemBuffer();
		}

		@Override
		public ParserContext getParserContext() throws MemoryAccessException {
			return DBTraceInstruction.this.getParserContext();
		}

		@Override
		public ParserContext getParserContext(Address instructionAddress)
				throws UnknownContextException, MemoryAccessException {
			return DBTraceInstruction.this.getParserContext(instructionAddress);
		}
	}

	protected class GuestMemBuffer implements MemBufferMixin {
		@Override
		public Address getAddress() {
			return platform.mapHostToGuest(getX1());
		}

		@Override
		public Memory getMemory() {
			return null;
		}

		@Override
		public boolean isBigEndian() {
			return platform.getLanguage().isBigEndian();
		}

		@Override
		public int getBytes(ByteBuffer buffer, int addressOffset) {
			return DBTraceInstruction.this.getBytes(buffer, addressOffset);
		}
	}

	@DBAnnotatedField(column = PLATFORM_COLUMN_NAME)
	private int platformKey;
	@DBAnnotatedField(column = PROTOTYPE_COLUMN_NAME)
	private int prototypeKey;
	@DBAnnotatedField(column = FLAGS_COLUMN_NAME)
	private byte flags;

	private final MethodProtector clearingFallThroughs = new MethodProtector();

	protected InstructionPrototype prototype;
	protected FlowOverride flowOverride;
	protected int lengthOverride;

	protected ParserContext parserContext;
	protected InternalTracePlatform platform;
	protected InstructionContext instructionContext;
	protected MemBuffer memBuffer;

	/**
	 * Construct an instruction unit
	 * 
	 * @param space the space
	 * @param tree the storage R*-Tree
	 * @param store the object store
	 * @param record the record
	 */
	public DBTraceInstruction(DBTraceCodeSpace space,
			DBTraceAddressSnapRangePropertyMapTree<DBTraceInstruction, ?> tree,
			DBCachedObjectStore<?> store, DBRecord record) {
		super(space, tree, store, record);
	}

	/**
	 * At load/create time: set the platform and context (which may map addresses)
	 * 
	 * @param platform the platform
	 */
	protected void doSetPlatformMapping(final InternalTracePlatform platform) {
		this.platform = platform;
		if (platform.isHost()) {
			instructionContext = this;
			memBuffer = this;
		}
		else {
			instructionContext = new GuestInstructionContext();
			memBuffer = new GuestMemBuffer();
		}
	}

	/**
	 * Set the fields of this record
	 * 
	 * @param platform the platform
	 * @param prototype the instruction prototype
	 * @param context the context for locating or creating the prototype entry
	 * @param forcedLengthOverride reduced instruction byte-length (1..7) or 0 to use default length
	 */
	protected void set(InternalTracePlatform platform, InstructionPrototype prototype,
			ProcessorContextView context, int forcedLengthOverride) {
		this.platformKey = platform.getIntKey();
		// NOTE: Using "this" for the MemBuffer seems a bit precarious.
		DBTraceGuestLanguage languageEntry = platform.getLanguageEntry();
		this.prototypeKey =
			(int) space.manager.findOrRecordPrototype(prototype, languageEntry, this, context)
					.getKey();
		this.flowOverride = FlowOverride.NONE; // flags field is already consistent
		this.lengthOverride = 0;
		update(PLATFORM_COLUMN, PROTOTYPE_COLUMN, FLAGS_COLUMN);

		if (forcedLengthOverride != 0) {
			updateLengthOverride(forcedLengthOverride);
		}

		// TODO: Can there be more in this context than the context register???
		doSetPlatformMapping(platform);
		this.prototype = prototype;
	}

	@Override
	protected void fresh(boolean created) throws IOException {
		super.fresh(created);
		if (created) {
			// Wait for something to set prototype
			return;
		}
		platform = space.manager.platformManager.getPlatformByKey(platformKey);
		if (platform == null) {
			throw new IOException("Instruction table is corrupt. Missing platform: " + platformKey);
		}
		prototype = space.manager.getPrototypeByKey(prototypeKey);
		if (prototype == null) {
			Msg.error(this, "Instruction table is corrupt for address " + getMinAddress() +
				". Missing prototype " + prototypeKey);
			prototype = new InvalidPrototype(getTrace().getBaseLanguage());
		}
		flowOverride =
			FlowOverride.values()[(flags & FLOW_OVERRIDE_SET_MASK) >> FLOW_OVERRIDE_SHIFT];

		lengthOverride = (flags & LENGTH_OVERRIDE_SET_MASK) >> LENGTH_OVERRIDE_SHIFT;
		if (lengthOverride != 0 && lengthOverride < prototype.getLength()) {
			Address minAddr = getMinAddress();
			Address newEndAddr = minAddr.add(lengthOverride - 1);
			doSetRange(new AddressRangeImpl(minAddr, newEndAddr));
		}

		doSetPlatformMapping(platform);
	}

	@Override
	protected void setRecordValue(DBTraceInstruction value) {
		// Nothing: Entry is the value
	}

	@Override
	protected DBTraceInstruction getRecordValue() {
		return this;
	}

	@Override
	public void delete() {
		try (LockHold hold = LockHold.lock(space.lock.writeLock())) {
			space.instructionMapSpace.deleteData(this);
		}
		// TODO: Coalesce events?
		space.instructions.unitRemoved(this);
	}

	@Override
	public void setEndSnap(long endSnap) {
		Lifespan oldSpan;
		try (LockHold hold = LockHold.lock(space.lock.writeLock())) {
			oldSpan = getLifespan();
			super.setEndSnap(endSnap);
		}
		space.instructions.unitSpanChanged(oldSpan, this);
	}

	@Override
	public TracePlatform getPlatform() {
		return platform;
	}

	@Override
	public Language getLanguage() {
		return prototype.getLanguage();
	}

	@Override
	public String toString() {
		return getFullString();
	}

	@Override
	public TraceInstruction getNext() {
		return space.instructions.getAfter(getStartSnap(), getX2());
	}

	@Override
	public TraceInstruction getPrevious() {
		return space.instructions.getBefore(getStartSnap(), getX1());
	}

	@Override
	public InstructionPrototype getPrototype() {
		return prototype;
	}

	int getPrototypeKey() {
		return prototypeKey;
	}

	@Override
	public int getOperandType(int opIndex) {
		try (LockHold hold = LockHold.lock(space.lock.readLock())) {
			int optype = InstructionAdapterFromPrototype.super.getOperandType(opIndex);
			DBTraceReference ref = getPrimaryReference(opIndex);
			// NOTE: ExternalReference cannot currently happen, by design. All modules should
			// be "present" in a trace, though possibly not observed.
			if (ref instanceof StackReference || ref instanceof ExternalReference ||
				ref != null && ref.getToAddress().isMemoryAddress()) {
				optype |= OperandType.ADDRESS;
			}
			return optype;
		}
	}

	@Override
	public Address getAddress(int opIndex) {
		try (LockHold hold = LockHold.lock(space.lock.readLock())) {
			DBTraceReferenceSpace refSpace = space.referenceManager.get(space, false);
			if (refSpace == null) {
				return InstructionAdapterFromPrototype.super.getAddress(opIndex);
			}
			TraceReference ref = refSpace.getPrimaryReferenceFrom(getStartSnap(), getX1(), opIndex);
			if (ref == null) {
				return InstructionAdapterFromPrototype.super.getAddress(opIndex);
			}
			return ref.getToAddress();
		}
	}

	@Override
	public Address getDefaultFallThrough() {
		try (LockHold hold = LockHold.lock(space.lock.readLock())) {
			Address fallThrough = getGuestDefaultFallThrough();
			return platform.mapGuestToHost(fallThrough);
		}
	}

	@Override
	public Address getGuestDefaultFallThrough() {
		try (LockHold hold = LockHold.lock(space.lock.readLock())) {
			FlowType flowType = getFlowType();
			if (flowType.hasFallthrough()) {
				try {
					return instructionContext.getAddress()
							.addNoWrap(prototype.getFallThroughOffset(instructionContext));
				}
				catch (AddressOverflowException e) {
					return null;
				}
			}
			return null;
		}
	}

	@Override
	public Address getFallThrough() {
		try (LockHold hold = LockHold.lock(space.lock.readLock())) {
			checkIsValid();
			if (isFallThroughOverridden()) {
				DBTraceReferenceSpace refSpace = space.referenceManager.get(space, false);
				if (refSpace == null) {
					return null;
				}
				for (DBTraceReference ref : refSpace.getReferencesFrom(getStartSnap(),
					getAddress())) {
					if (!ref.getReferenceType().isFallthrough()) {
						continue;
					}
					// NOTE: Although not likely sane, it could be a register address
					return ref.getToAddress();
				}
				return null;
			}
			if (lengthOverride != 0 && getFlowType().hasFallthrough()) {
				return getMinAddress().add(lengthOverride);
			}
			return getDefaultFallThrough();
		}
	}

	@Override
	public Address getFallFrom() {
		try (LockHold hold = LockHold.lock(space.lock.readLock())) {
			checkIsValid();
			// Go back one, considering alignment
			DBTraceInstruction ins = this;
			int alignment = Math.min(1, getLanguage().getInstructionAlignment());
			// Skip past delay slots, if any
			try {
				do {
					ins = space.instructions()
							.getContaining(getStartSnap(),
								ins.getMinAddress().subtractNoWrap(alignment));
				}
				while (ins != null && ins.isInDelaySlot() &&
					ins.getLanguage() == this.getLanguage());
			}
			catch (AddressOverflowException e) {
				return null;
			}
			if (ins == null) {
				return null;
			}
			if (ins.getLanguage() != this.getLanguage()) {
				return null;
			}

			// If I'm in a delay slot, then we assume to have fallen from the found instruction
			if (this.isInDelaySlot()) {
				return ins.getMinAddress();
			}

			// The found instruction may not have a fall-through....
			Address fallAddr = ins.getFallThrough();
			if (fallAddr != null && fallAddr.equals(this.getAddress())) {
				return ins.getMinAddress();
			}

			return null;
		}
	}

	@Override
	public Address[] getFlows() {
		try (LockHold hold = LockHold.lock(space.lock.readLock())) {
			DBTraceReferenceSpace refSpace = space.referenceManager.get(space, false);
			if (refSpace == null) {
				return EMPTY_ADDRESS_ARRAY;
			}
			Collection<? extends DBTraceReference> refs =
				refSpace.getFlowReferencesFrom(getStartSnap(), getAddress());
			if (refs.isEmpty()) {
				return EMPTY_ADDRESS_ARRAY;
			}
			ArrayList<Address> list = new ArrayList<>();
			for (DBTraceReference ref : refs) {
				if (!ref.getReferenceType().isIndirect()) {
					list.add(ref.getToAddress());
				}
			}

			if (flowOverride == FlowOverride.RETURN && list.size() == 1) {
				return EMPTY_ADDRESS_ARRAY;
			}

			if (lengthOverride != 0 && getFlowType().hasFallthrough()) {
				list.add(getMinAddress().add(lengthOverride));
			}

			return list.toArray(new Address[list.size()]);
		}
	}

	@Override
	public Address[] getDefaultFlows() {
		try (LockHold hold = LockHold.lock(space.lock.readLock())) {
			Address[] guestFlows = getGuestDefaultFlows();
			if (platform.isHost() || guestFlows == null) {
				return guestFlows;
			}
			List<Address> hostFlows = new ArrayList<>();
			for (Address g : guestFlows) {
				Address h = platform.mapGuestToHost(g);
				if (h != null) {
					hostFlows.add(h);
				}
			}
			if (hostFlows.isEmpty()) {
				return EMPTY_ADDRESS_ARRAY;
			}
			return hostFlows.toArray(new Address[hostFlows.size()]);
		}
	}

	@Override
	public Address[] getGuestDefaultFlows() {
		try (LockHold hold = LockHold.lock(space.lock.readLock())) {
			Address[] flows = prototype.getFlows(instructionContext);
			if (flowOverride == FlowOverride.RETURN && flows.length == 1) {
				return EMPTY_ADDRESS_ARRAY;
			}
			return flows;
		}
	}

	@Override
	public FlowType getFlowType() {
		try (LockHold hold = LockHold.lock(space.lock.readLock())) {
			return FlowOverride.getModifiedFlowType(prototype.getFlowType(instructionContext),
				flowOverride);
		}
	}

	@Override
	public boolean isFallthrough() {
		try (LockHold hold = LockHold.lock(space.lock.readLock())) {
			if (!getFlowType().isFallthrough()) {
				return false;
			}
			return hasFallthrough();
		}
	}

	@Override
	public boolean hasFallthrough() {
		try (LockHold hold = LockHold.lock(space.lock.readLock())) {
			checkIsValid();
			if (isFallThroughOverridden()) {
				return getFallThrough() != null; // dest stored as reference
			}
			return getFlowType().hasFallthrough();
		}
	}

	@Override
	public FlowOverride getFlowOverride() {
		return flowOverride;
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
	public void setFlowOverride(FlowOverride flowOverride) {
		FlowOverride oldFlowOverride = this.flowOverride;
		try (LockHold hold = space.trace.lockWrite()) {
			checkDeleted();
			if (this.flowOverride == flowOverride) {
				return;
			}
			FlowType origFlowType = getFlowType();

			flags &= FLOW_OVERRIDE_CLEAR_MASK;
			flags |= (flowOverride.ordinal() << FLOW_OVERRIDE_SHIFT) & FLOW_OVERRIDE_SET_MASK;
			this.flowOverride = flowOverride;
			update(FLAGS_COLUMN);

			DBTraceReferenceSpace refSpace = space.referenceManager.get(space, true);
			for (DBTraceReference ref : refSpace.getFlowReferencesFrom(getStartSnap(), getX1())) {
				if (!isSameFlowType(origFlowType, ref.getReferenceType())) {
					continue;
				}
				RefType refType = RefTypeFactory.getDefaultMemoryRefType(this,
					ref.getOperandIndex(), ref.getToAddress(), true);
				if (!refType.isFlow() || ref.getReferenceType() == refType) {
					continue;
				}
				ref.setReferenceType(refType);
			}
		}
		space.trace.setChanged(
			new TraceChangeRecord<>(TraceEvents.INSTRUCTION_FLOW_OVERRIDE_CHANGED, space, this,
				oldFlowOverride, flowOverride));
	}

	@Override
	public void setLengthOverride(int length) throws CodeUnitInsertionException {
		int oldLengthOverride = this.lengthOverride;
		try (LockHold hold = space.trace.lockWrite()) {
			checkDeleted();
			InstructionPrototype proto = getPrototype();
			length = InstructionDB.checkLengthOverride(length, proto);
			if (length == lengthOverride) {
				return; // no change
			}

			int newLength = length != 0 ? length : proto.getLength();
			if (newLength > getLength()) {
				Address minAddr = getMinAddress();
				Address newEndAddr = minAddr.add(newLength - 1);
				TraceAddressSnapRange tasr = new ImmutableTraceAddressSnapRange(
					new AddressRangeImpl(minAddr.next(), newEndAddr), getLifespan());
				for (AbstractDBTraceCodeUnit<?> cu : space.definedUnits.getIntersecting(tasr)) {
					if (cu != this) {
						throw new CodeUnitInsertionException(
							"Length override of " + newLength + " conflicts with code unit at " +
								cu.getMinAddress() + ", lifespan=" + cu.getLifespan());
					}
				}
			}

			updateLengthOverride(length);
		}
		space.trace.setChanged(
			new TraceChangeRecord<>(TraceEvents.INSTRUCTION_LENGTH_OVERRIDE_CHANGED, space, this,
				oldLengthOverride, length));
	}

	private void updateLengthOverride(int length) {
		flags &= LENGTH_OVERRIDE_CLEAR_MASK;
		flags |= (length << LENGTH_OVERRIDE_SHIFT);
		lengthOverride = length;
		update(FLAGS_COLUMN);

		int newLength = length != 0 ? length : getPrototype().getLength();
		Address minAddr = getMinAddress();
		Address newEndAddr = minAddr.add(newLength - 1);
		doSetRange(new AddressRangeImpl(minAddr, newEndAddr));
	}

	@Override
	public boolean isLengthOverridden() {
		return lengthOverride != 0;
	}

	@Override
	public int getLength() {
		if (lengthOverride != 0) {
			return lengthOverride;
		}
		return super.getLength();
	}

	@Override
	public int getParsedLength() {
		if (lengthOverride == 0) {
			return super.getLength();
		}
		return getPrototype().getLength();
	}

	@Override
	public byte[] getParsedBytes() throws MemoryAccessException {
		if (!isLengthOverridden()) {
			return getBytes();
		}
		try (LockHold hold = LockHold.lock(space.lock.readLock())) {
			checkIsValid();
			int len = getPrototype().getLength();
			byte[] b = new byte[len];
			Address addr = getAddress();
			if (len != getMemory().getBytes(addr, b)) {
				throw new MemoryAccessException("Failed to read " + len + " bytes at " + addr);
			}
			return b;
		}
	}

	@Override
	public void setFallThrough(Address fallThrough) {
		try (LockHold hold = space.trace.lockWrite()) {
			checkDeleted();
			Address defaultFallThrough = prototype.getFallThrough(this);
			if (Objects.equals(fallThrough, defaultFallThrough)) {
				clearFallThroughOverride();
				return;
			}
			if (fallThrough == null) {
				clearFallThroughRefs(null);
				setFallThroughOverridden(true);
			}
			else {
				DBTraceReferenceSpace refSpace = space.referenceManager.get(space, true);
				refSpace.addMemoryReference(lifespan, getAddress(), fallThrough,
					RefType.FALL_THROUGH, SourceType.USER_DEFINED, Reference.MNEMONIC);
				// TODO: ReferenceManager must be observable. Listen for FALL_THROUGHs
				// and react by setting overriden flag appropriately
				setFallThroughOverridden(true);
			}
		}
	}

	@Override
	public void clearFallThroughOverride() {
		try (LockHold hold = space.trace.lockWrite()) {
			checkDeleted();
			if (!isFallThroughOverridden()) {
				return;
			}
			clearFallThroughRefs(null);
			setFallThroughOverridden(false);
		}
	}

	private void clearFallThroughRefs(DBTraceReference keepFallThroughRef) {
		clearingFallThroughs.take(() -> {
			DBTraceReferenceSpace refSpace = space.referenceManager.get(space, false);
			if (refSpace == null) {
				return;
			}
			for (DBTraceReference ref : refSpace.getReferencesFrom(getStartSnap(), getX1())) {
				if (ref.getReferenceType() == RefType.FALL_THROUGH &&
					!ref.equals(keepFallThroughRef)) {
					ref.delete();
				}
			}
		});
	}

	// TODO: I'm anticipating calling this from the code manager.... Clean up if not.
	void fallThroughChanged(DBTraceReference fallThroughRef) {
		clearingFallThroughs.avoid(() -> {
			clearFallThroughRefs(fallThroughRef);
			setFallThroughOverridden(fallThroughRef != null &&
				fallThroughRef.getReferenceType() == RefType.FALL_THROUGH);
		});
	}

	private void setFallThroughOverridden(boolean overridden) {
		// NOTE: Write lock must be held here
		if (isFallThroughOverridden() == overridden) {
			return;
		}
		if (overridden) {
			flags |= FALLTHROUGH_SET_MASK;
		}
		else {
			flags &= FALLTHROUGH_CLEAR_MASK;
		}
		update(FLAGS_COLUMN);
		space.trace.setChanged(
			new TraceChangeRecord<>(TraceEvents.INSTRUCTION_FALL_THROUGH_OVERRIDE_CHANGED, space,
				this, !overridden, overridden));
	}

	@Override
	public boolean isFallThroughOverridden() {
		return (flags & FALLTHROUGH_SET_MASK) != 0;
	}

	@Override
	public InstructionContext getInstructionContext() {
		return instructionContext;
	}

	@Override
	public void setValue(Register register, BigInteger value) throws ContextChangeException {
		try (LockHold hold = LockHold.lock(space.lock.writeLock())) {
			// TODO: Why would I throw ContextChangeException?
			// Where I see the check, it checks for an existing instruction.... Well, I'm one!
			DBTraceRegisterContextSpace ctxSpace =
				space.trace.getRegisterContextManager().get(space, true);
			ctxSpace.setValue(getLanguage(), new RegisterValue(register, value), lifespan, range);
		}
	}

	@Override
	public void setRegisterValue(RegisterValue value) throws ContextChangeException {
		try (LockHold hold = LockHold.lock(space.lock.writeLock())) {
			// TODO: Why would I throw ContextChangeException?
			// Where I see the check, it checks for an existing instruction.... Well, I'm one!
			DBTraceRegisterContextSpace ctxSpace =
				space.trace.getRegisterContextManager().get(space, true);
			ctxSpace.setValue(getLanguage(), value, lifespan, range);
		}
	}

	@Override
	public void clearRegister(Register register) throws ContextChangeException {
		try (LockHold hold = LockHold.lock(space.lock.writeLock())) {
			// TODO: Why would I throw ContextChangeException?
			// Where I see the check, it checks for an existing instruction.... Well, I'm one!
			DBTraceRegisterContextSpace ctxSpace =
				space.trace.getRegisterContextManager().get(space, false);
			if (ctxSpace == null) {
				return;
			}
			ctxSpace.removeValue(getLanguage(), register, lifespan, range);
		}
	}

	@Override
	public Register getBaseContextRegister() {
		return getLanguage().getContextBaseRegister();
	}

	@Override
	public List<Register> getRegisters() {
		return getLanguage().getRegisters();
	}

	@Override
	public Register getRegister(String name) {
		return getLanguage().getRegister(name);
	}

	@Override
	public BigInteger getValue(Register register, boolean signed) {
		try (LockHold hold = LockHold.lock(space.lock.readLock())) {
			DBTraceRegisterContextManager manager = space.trace.getRegisterContextManager();
			Address guestAddress = getPlatform().mapHostToGuest(getMinAddress());
			RegisterValue rv =
				manager.getValueWithDefault(getPlatform(), register, getStartSnap(), guestAddress);
			if (rv == null) {
				return null;
			}
			return signed ? rv.getSignedValue() : rv.getUnsignedValue();
		}
	}

	@Override
	public RegisterValue getRegisterValue(Register register) {
		try (LockHold hold = LockHold.lock(space.lock.readLock())) {
			DBTraceRegisterContextManager manager = space.trace.getRegisterContextManager();
			Address guestAddress = getPlatform().mapHostToGuest(getMinAddress());
			return manager.getValueWithDefault(getPlatform(), register, getStartSnap(),
				guestAddress);
		}
	}

	@Override
	public boolean hasValue(Register register) {
		try (LockHold hold = LockHold.lock(space.lock.readLock())) {
			DBTraceRegisterContextSpace ctxSpace =
				space.trace.getRegisterContextManager().get(space, false);
			if (ctxSpace == null) {
				return false;
			}
			// TODO: Should probably just use start address...?
			return ctxSpace.hasRegisterValueInAddressRange(getLanguage(), register, getStartSnap(),
				range);
		}
	}

	@Override
	public ProcessorContextView getProcessorContext() {
		return this;
	}

	@Override
	public MemBuffer getMemBuffer() {
		return memBuffer;
	}

	@Override
	public ParserContext getParserContext() throws MemoryAccessException {
		return parserContext == null
				? parserContext = prototype.getParserContext(getMemBuffer(), getProcessorContext())
				: parserContext;
	}

	@Override
	public ParserContext getParserContext(Address instructionAddress)
			throws UnknownContextException, MemoryAccessException {
		// TODO: Why is this a method of Instruction? Seems should be of Listing.
		// NOTE: Taken from InstructionDB#getParserContext(Address) 
		// Admittedly, I don't understand what it's for
		if (getAddress().equals(instructionAddress)) {
			return getParserContext();
		}
		DBTraceInstruction instruction =
			space.manager.instructions.getAt(getStartSnap(), instructionAddress);
		if (instruction == null) {
			throw new UnknownContextException("Trace does not contain referenced instruction: (" +
				getStartSnap() + "," + instructionAddress + ")");
		}
		// Ensure that prototype is the same implementation
		InstructionPrototype otherProto = instruction.getPrototype();
		if (!otherProto.getClass().equals(prototype.getClass())) {
			throw new UnknownContextException("Instruction has incompatible prototype at: (" +
				getStartSnap() + "," + instructionAddress + ")");
		}
		return instruction.getParserContext();
	}
}
