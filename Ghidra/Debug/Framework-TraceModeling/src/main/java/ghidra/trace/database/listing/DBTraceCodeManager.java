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

import static ghidra.lifecycle.Unfinished.TODO;

import java.io.IOException;
import java.math.BigInteger;
import java.util.*;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.RemovalNotification;
import com.google.common.collect.Range;

import db.DBHandle;
import db.DBRecord;
import ghidra.lifecycle.Internal;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.ByteMemBufferImpl;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.util.ProgramContextImpl;
import ghidra.trace.database.DBTrace;
import ghidra.trace.database.address.DBTraceOverlaySpaceAdapter;
import ghidra.trace.database.address.DBTraceOverlaySpaceAdapter.AddressDBFieldCodec;
import ghidra.trace.database.address.DBTraceOverlaySpaceAdapter.DecodesAddresses;
import ghidra.trace.database.data.DBTraceDataTypeManager;
import ghidra.trace.database.guest.DBTraceGuestPlatform;
import ghidra.trace.database.guest.DBTraceGuestPlatform.DBTraceGuestLanguage;
import ghidra.trace.database.guest.DBTracePlatformManager;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.TraceAddressSnapRangeQuery;
import ghidra.trace.database.space.AbstractDBTraceSpaceBasedManager;
import ghidra.trace.database.space.DBTraceDelegatingManager;
import ghidra.trace.database.symbol.DBTraceReferenceManager;
import ghidra.trace.database.thread.DBTraceThreadManager;
import ghidra.trace.model.AddressSnap;
import ghidra.trace.model.DefaultAddressSnap;
import ghidra.trace.model.listing.TraceCodeManager;
import ghidra.trace.model.listing.TraceCodeSpace;
import ghidra.trace.model.stack.TraceStackFrame;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.util.TraceAddressSpace;
import ghidra.util.*;
import ghidra.util.database.*;
import ghidra.util.database.annot.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

public class DBTraceCodeManager
		extends AbstractDBTraceSpaceBasedManager<DBTraceCodeSpace, DBTraceCodeRegisterSpace>
		implements TraceCodeManager, DBTraceDelegatingManager<DBTraceCodeSpace> {
	public static final String NAME = "Code";

	/**
	 * A prototype entry
	 *
	 * <p>
	 * Version history:
	 * <ul>
	 * <li>1: Change {@link #address} to 10-byte fixed encoding</li>
	 * <li>0: Initial version and previous unversioned implementation</li>
	 * </ul>
	 */
	@DBAnnotatedObjectInfo(version = 1)
	public static class DBTraceCodePrototypeEntry extends DBAnnotatedObject
			implements DecodesAddresses {
		public static final String TABLE_NAME = "Prototypes";

		static final String LANGUAGE_COLUMN_NAME = "Language";
		static final String BYTES_COLUMN_NAME = "Bytes";
		static final String CONTEXT_COLUMN_NAME = "Context";
		static final String ADDRESS_COLUMN_NAME = "Address";
		static final String DELAY_COLUMN_NAME = "Delay";

		@DBAnnotatedColumn(LANGUAGE_COLUMN_NAME)
		static DBObjectColumn LANGUAGE_COLUMN;
		@DBAnnotatedColumn(BYTES_COLUMN_NAME)
		static DBObjectColumn BYTES_COLUMN;
		@DBAnnotatedColumn(CONTEXT_COLUMN_NAME)
		static DBObjectColumn CONTEXT_COLUMN;
		// Because this could contribute to the parsing context
		@DBAnnotatedColumn(ADDRESS_COLUMN_NAME)
		static DBObjectColumn ADDRESS_COLUMN;
		@DBAnnotatedColumn(DELAY_COLUMN_NAME)
		static DBObjectColumn DELAY_COLUMN;

		@DBAnnotatedField(column = LANGUAGE_COLUMN_NAME)
		private int languageKey;
		@DBAnnotatedField(column = BYTES_COLUMN_NAME)
		private byte[] bytes;
		@DBAnnotatedField(column = CONTEXT_COLUMN_NAME)
		private byte[] context;
		@DBAnnotatedField(column = ADDRESS_COLUMN_NAME, codec = AddressDBFieldCodec.class)
		private Address address = Address.NO_ADDRESS;
		@DBAnnotatedField(column = DELAY_COLUMN_NAME)
		private boolean delaySlot;

		private InstructionPrototype prototype;

		private DBTraceCodeManager manager;

		public DBTraceCodePrototypeEntry(DBTraceCodeManager manager, DBCachedObjectStore<?> store,
				DBRecord record) {
			super(store, record);
			this.manager = manager;
		}

		@Override
		public DBTraceOverlaySpaceAdapter getOverlaySpaceAdapter() {
			return manager.overlayAdapter;
		}

		void set(DBTraceGuestLanguage languageEntry, byte[] bytes, byte[] context, Address address,
				boolean delaySlot) {
			this.languageKey = (int) (languageEntry == null ? -1 : languageEntry.getKey());
			this.bytes = bytes;
			this.context = context;
			this.address = address;
			this.delaySlot = delaySlot;
			update(LANGUAGE_COLUMN, BYTES_COLUMN, CONTEXT_COLUMN, ADDRESS_COLUMN, DELAY_COLUMN);
			this.prototype = parsePrototype();
		}

		@Override
		protected void fresh(boolean created) throws IOException {
			super.fresh(created);
			if (created) {
				return;
			}
			this.prototype = parsePrototype();
		}

		public InstructionPrototype getPrototype() {
			return prototype;
		}

		private InstructionPrototype parsePrototype() {
			DBTraceGuestLanguage guest = manager.platformManager.getLanguageByKey(languageKey);
			Language language = guest == null ? manager.baseLanguage : guest.getLanguage();
			MemBuffer memBuffer = new ByteMemBufferImpl(address, bytes, language.isBigEndian());
			ProcessorContext ctx =
				new ProtoProcessorContext(getBaseContextValue(language, context, address));
			try {
				return language.parse(memBuffer, ctx, delaySlot);
			}
			catch (Exception e) {
				Msg.error(this, "Bad Instruction Prototype found in DB! Address: " + address +
					"Bytes: " + NumericUtilities.convertBytesToString(bytes));
				return new InvalidPrototype(language);
			}
		}

		static RegisterValue getBaseContextValue(Language language, byte[] context,
				Address address) {
			Register register = language.getContextBaseRegister();
			if (register == Register.NO_CONTEXT) {
				return null;
			}
			if (context == null) {
				ProgramContextImpl defaultContext = new ProgramContextImpl(language);
				language.applyContextSettings(defaultContext);
				return defaultContext.getDisassemblyContext(address);
			}
			return new RegisterValue(register, new BigInteger(context));
		}
	}

	protected static Address instructionMax(Instruction instruction, boolean includeDelays)
			throws AddressOverflowException {
		Address min = instruction.getMinAddress();
		Address max = instruction.getMaxAddress();
		InstructionPrototype prototype = instruction.getPrototype();
		if (includeDelays && prototype.hasDelaySlots()) {
			max = min.addNoWrap(
				prototype.getFallThroughOffset(instruction.getInstructionContext()) - 1);
		}
		return max;
	}

	protected final DBTracePlatformManager platformManager;
	protected final DBTraceDataTypeManager dataTypeManager;
	protected final DBTraceOverlaySpaceAdapter overlayAdapter;
	protected final DBTraceReferenceManager referenceManager;

	protected final DBCachedObjectStore<DBTraceCodePrototypeEntry> protoStore;
	protected final Map<InstructionPrototype, DBTraceCodePrototypeEntry> entriesByProto =
		new HashMap<>();

	protected final DBTraceCodeUnitsMemoryView codeUnits = new DBTraceCodeUnitsMemoryView(this);
	protected final DBTraceInstructionsMemoryView instructions =
		new DBTraceInstructionsMemoryView(this);
	protected final DBTraceDataMemoryView data = new DBTraceDataMemoryView(this);
	protected final DBTraceDefinedDataMemoryView definedData =
		new DBTraceDefinedDataMemoryView(this);
	protected final DBTraceUndefinedDataMemoryView undefinedData =
		new DBTraceUndefinedDataMemoryView(this);
	protected final DBTraceDefinedUnitsMemoryView definedUnits =
		new DBTraceDefinedUnitsMemoryView(this);

	protected final Map<AddressSnap, UndefinedDBTraceData> undefinedCache =
		CacheBuilder.newBuilder()
				.removalListener(this::undefinedRemovedFromCache)
				.weakValues()
				.build()
				.asMap();

	public DBTraceCodeManager(DBHandle dbh, DBOpenMode openMode, ReadWriteLock lock,
			TaskMonitor monitor, Language baseLanguage, DBTrace trace,
			DBTraceThreadManager threadManager, DBTracePlatformManager platformManager,
			DBTraceDataTypeManager dataTypeManager, DBTraceOverlaySpaceAdapter overlayAdapter,
			DBTraceReferenceManager referenceManager) throws IOException, VersionException {
		super(NAME, dbh, openMode, lock, monitor, baseLanguage, trace, threadManager);
		this.platformManager = platformManager;
		this.dataTypeManager = dataTypeManager;
		this.overlayAdapter = overlayAdapter;
		this.referenceManager = referenceManager;

		DBCachedObjectStoreFactory factory = trace.getStoreFactory();
		protoStore = factory.getOrCreateCachedStore(DBTraceCodePrototypeEntry.TABLE_NAME,
			DBTraceCodePrototypeEntry.class, (s, r) -> new DBTraceCodePrototypeEntry(this, s, r),
			true);

		loadPrototypes();
		loadSpaces();
	}

	private void undefinedRemovedFromCache(
			RemovalNotification<AddressSnap, UndefinedDBTraceData> rn) {
		// Do nothing
	}

	// Internal
	public UndefinedDBTraceData doCreateUndefinedUnit(long snap, Address address,
			TraceThread thread, int frameLevel) {
		return undefinedCache.computeIfAbsent(new DefaultAddressSnap(address, snap),
			ot -> new UndefinedDBTraceData(trace, snap, address, thread, frameLevel));
	}

	protected void loadPrototypes() {
		// NOTE: Should already own write lock
		for (DBTraceCodePrototypeEntry protoEnt : protoStore.asMap().values()) {
			// NOTE: No need to check if it exists. This is only called on new or after clear
			entriesByProto.put(protoEnt.prototype, protoEnt);
		}
	}

	protected byte[] valueBytes(RegisterValue rv) {
		byte[] bytes = rv.toBytes();
		return Arrays.copyOfRange(bytes, bytes.length / 2, bytes.length);
	}

	protected DBTraceCodePrototypeEntry doRecordPrototype(InstructionPrototype prototype,
			DBTraceGuestLanguage guest, MemBuffer memBuffer, ProcessorContextView context) {
		DBTraceCodePrototypeEntry protoEnt = protoStore.create();
		byte[] bytes = new byte[prototype.getLength()];
		if (memBuffer.getBytes(bytes, 0) != bytes.length) {
			throw new AssertionError("Insufficient bytes for prototype");
		}
		byte[] ctx;
		Register baseCtxReg = context.getBaseContextRegister();
		if (baseCtxReg == null) {
			ctx = null;
		}
		else {
			RegisterValue value = context.getRegisterValue(baseCtxReg);
			ctx = value == null ? null : valueBytes(value);
		}
		protoEnt.set(guest, bytes, ctx, memBuffer.getAddress(), prototype.isInDelaySlot());
		return protoEnt;
	}

	protected DBTraceCodePrototypeEntry findOrRecordPrototype(InstructionPrototype prototype,
			DBTraceGuestLanguage guest, MemBuffer memBuffer, ProcessorContextView context) {
		// NOTE: Must already have write lock
		return entriesByProto.computeIfAbsent(prototype,
			p -> doRecordPrototype(prototype, guest, memBuffer, context));
	}

	protected InstructionPrototype getPrototypeByKey(int key) {
		DBTraceCodePrototypeEntry protoEnt = protoStore.getObjectAt(key);
		return protoEnt == null ? null : protoEnt.prototype;
	}

	@Override
	protected DBTraceCodeSpace createSpace(AddressSpace space, DBTraceSpaceEntry ent)
			throws VersionException, IOException {
		return new DBTraceCodeSpace(this, dbh, space, ent);
	}

	@Override
	protected DBTraceCodeRegisterSpace createRegisterSpace(AddressSpace space, TraceThread thread,
			DBTraceSpaceEntry ent) throws VersionException, IOException {
		return new DBTraceCodeRegisterSpace(this, dbh, space, ent, thread);
	}

	@Override
	public DBTraceCodeSpace getForSpace(AddressSpace space, boolean createIfAbsent) {
		return super.getForSpace(space, createIfAbsent);
	}

	@Override
	public Lock readLock() {
		return spaceStore.readLock();
	}

	@Override
	public Lock writeLock() {
		return spaceStore.writeLock();
	}

	@Override
	public TraceCodeSpace getCodeSpace(TraceAddressSpace space, boolean createIfAbsent) {
		return get(space, createIfAbsent);
	}

	@Override
	public DBTraceCodeSpace getCodeSpace(AddressSpace space, boolean createIfAbsent) {
		return getForSpace(space, createIfAbsent);
	}

	@Override
	public DBTraceCodeRegisterSpace getCodeRegisterSpace(TraceThread thread,
			boolean createIfAbsent) {
		return getForRegisterSpace(thread, 0, createIfAbsent);
	}

	@Override
	public DBTraceCodeRegisterSpace getCodeRegisterSpace(TraceThread thread, int frameLevel,
			boolean createIfAbsent) {
		return getForRegisterSpace(thread, frameLevel, createIfAbsent);
	}

	@Override
	public DBTraceCodeRegisterSpace getCodeRegisterSpace(TraceStackFrame frame,
			boolean createIfAbsent) {
		return getForRegisterSpace(frame, createIfAbsent);
	}

	@Internal
	public void replaceDataTypes(long oldID, long newID) {
		TODO();
	}

	@Internal
	public void clearData(LinkedList<Long> deletedDataTypeIds, TaskMonitor monitor) {
		TODO();
	}

	@Internal
	public void clearPlatform(Range<Long> span, AddressRange range, DBTraceGuestPlatform guest,
			TaskMonitor monitor) throws CancelledException {
		delegateDeleteV(range.getAddressSpace(),
			m -> m.clearPlatform(span, range, guest, monitor));
	}

	@Internal
	public void deletePlatform(DBTraceGuestPlatform guest, TaskMonitor monitor)
			throws CancelledException {
		// TODO: Use sub-monitors when available
		for (DBTraceCodeSpace codeSpace : memSpaces.values()) {
			codeSpace.clearPlatform(Range.all(), codeSpace.all, guest, monitor);
		}
		for (DBTraceCodeRegisterSpace codeSpace : regSpaces.values()) {
			// TODO: I don't know any way to get guest instructions into register space
			// The mapping manager does (should) not allow guest register addresses
			// TODO: Test this if I ever get guest data units
			// TODO: I think explicit per-thread/frame register spaces will be going away, anyway
			// They'll just be path-named overlays on register space?
			codeSpace.clearPlatform(Range.all(), codeSpace.all, guest, monitor);
		}
	}

	@Internal
	public void deleteLangauge(DBTraceGuestLanguage guest, TaskMonitor monitor)
			throws CancelledException {
		monitor.setMessage("Clearing instruction prototypes");
		monitor.setMaximum(protoStore.getRecordCount());
		for (Iterator<DBTraceCodePrototypeEntry> it = protoStore.asMap().values().iterator(); it
				.hasNext();) {
			monitor.checkCanceled();
			monitor.incrementProgress(1);
			DBTraceCodePrototypeEntry protoEnt = it.next();
			if (protoEnt.prototype.getLanguage() != guest.getLanguage()) {
				continue;
			}
			it.remove();
			entriesByProto.remove(protoEnt.prototype);
		}
	}

	@Override
	public void invalidateCache(boolean all) {
		try (LockHold hold = LockHold.lock(lock.writeLock())) {
			protoStore.invalidateCache();
			entriesByProto.clear();
			loadPrototypes();

			super.invalidateCache(all);
		}
	}

	static class ProtoProcessorContext implements ProcessorContext {
		// NOTE: Only used to parse prototypes from DB
		private final RegisterValue baseContextValue;
		private final Register baseContextRegister;

		public ProtoProcessorContext(RegisterValue baseContextValue) {
			this.baseContextValue = baseContextValue;
			this.baseContextRegister =
				baseContextValue == null ? null : baseContextValue.getRegister();
		}

		@Override
		public Register getBaseContextRegister() {
			return baseContextRegister;
		}

		@Override
		public List<Register> getRegisters() {
			if (baseContextRegister == null) {
				return List.of();
			}
			return List.of(baseContextRegister);
		}

		@Override
		public Register getRegister(String name) {
			if (baseContextRegister == null || !baseContextRegister.getName().equals(name)) {
				return null;
			}
			return baseContextRegister;
		}

		@Override
		public BigInteger getValue(Register register, boolean signed) {
			if (register == null || register != baseContextRegister) {
				return null;
			}
			return signed ? baseContextValue.getSignedValueIgnoreMask()
					: baseContextValue.getUnsignedValueIgnoreMask();
		}

		@Override
		public RegisterValue getRegisterValue(Register register) {
			if (register == null || register != baseContextRegister) {
				return null;
			}
			return baseContextValue;
		}

		@Override
		public boolean hasValue(Register register) {
			if (register == null || register != baseContextRegister) {
				return false;
			}
			return true;
		}

		@Override
		public void setValue(Register register, BigInteger value) throws ContextChangeException {
			throw new UnsupportedOperationException();
		}

		@Override
		public void setRegisterValue(RegisterValue value) throws ContextChangeException {
			throw new UnsupportedOperationException();
		}

		@Override
		public void clearRegister(Register register) throws ContextChangeException {
			throw new UnsupportedOperationException();
		}
	}

	@Override
	public DBTraceCodeUnitsMemoryView codeUnits() {
		return codeUnits;
	}

	@Override
	public DBTraceInstructionsMemoryView instructions() {
		return instructions;
	}

	@Override
	public DBTraceDataMemoryView data() {
		return data;
	}

	@Override
	public DBTraceDefinedDataMemoryView definedData() {
		return definedData;
	}

	@Override
	public DBTraceUndefinedDataMemoryView undefinedData() {
		return undefinedData;
	}

	@Override
	public DBTraceDefinedUnitsMemoryView definedUnits() {
		return definedUnits;
	}

	@Override
	public AddressSetView getCodeAdded(long from, long to) {
		AddressSet result = new AddressSet();
		if (from == to) {
			return result;
		}
		Collection<AbstractDBTraceCodeUnit<?>> changes = new ArrayList<>();
		for (DBTraceCodeSpace space : memSpaces.values()) {
			changes.addAll(
				space.dataMapSpace.reduce(TraceAddressSnapRangeQuery.added(from, to, space.space))
						.values());
			changes.addAll(space.instructionMapSpace
					.reduce(TraceAddressSnapRangeQuery.added(from, to, space.space))
					.values());
		}
		for (AbstractDBTraceCodeUnit<?> unit : changes) {
			result.add(unit.getRange());
		}
		return result;
	}

	@Override
	public AddressSetView getCodeRemoved(long from, long to) {
		AddressSet result = new AddressSet();
		if (from == to) {
			return result;
		}
		Collection<AbstractDBTraceCodeUnit<?>> changes = new ArrayList<>();
		for (DBTraceCodeSpace space : memSpaces.values()) {
			changes.addAll(
				space.dataMapSpace.reduce(TraceAddressSnapRangeQuery.removed(from, to, space.space))
						.values());
			changes.addAll(space.instructionMapSpace
					.reduce(TraceAddressSnapRangeQuery.removed(from, to, space.space))
					.values());
		}
		for (AbstractDBTraceCodeUnit<?> unit : changes) {
			result.add(unit.getRange());
		}
		return result;
	}
}
