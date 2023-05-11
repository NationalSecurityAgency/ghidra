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

import db.DBHandle;
import db.DBRecord;
import ghidra.lifecycle.Internal;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
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
import ghidra.trace.model.*;
import ghidra.trace.model.listing.*;
import ghidra.trace.model.stack.TraceStackFrame;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.util.TraceAddressSpace;
import ghidra.util.*;
import ghidra.util.database.*;
import ghidra.util.database.annot.*;
import ghidra.util.datastruct.WeakValueHashMap;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 * The implementation of {@link TraceCodeManager} for {@link DBTrace}
 * 
 * <p>
 * The "fluent" interfaces actually create quite a burden to implement here; however, we have some
 * opportunity to extract common code among the various views. There are a few concepts and nuances
 * to consider in order to handle all the fluent cases. The manager implements
 * {@link TraceCodeOperations} directly, which means it must provide a version of each
 * {@link TraceCodeUnitsView} that composes all memory address spaces. These are named with the
 * suffix {@code MemoryView} and extend {@link AbstractBaseDBTraceCodeUnitsMemoryView}.
 * 
 * <p>
 * In addition, in order to support {@link #getCodeSpace(AddressSpace, boolean)}, it must provide a
 * version of each that can be bound to a single memory address space. Same for
 * {@link #getCodeRegisterSpace(TraceThread, int, boolean)}. These are named with the suffix
 * {@code View} and extend {@link AbstractBaseDBTraceCodeUnitsView}.
 * 
 * <p>
 * Furthermore, there are three types of views:
 * 
 * <ol>
 * <li>Those defined by a table, i.e., defined data and instructions. These extend
 * {@link AbstractBaseDBTraceDefinedUnitsView}.</li>
 * <li>Those defined implicitly, but may have a support table, i.e., undefined units. This is
 * implemented by {@link DBTraceUndefinedDataView}.</li>
 * <li>Those defined as the composition of others, i.e., data and defined units. These extend
 * {@link AbstractComposedDBTraceCodeUnitsView}.</li>
 * </ol>
 * 
 * <p>
 * The first two types represent a view of a single code unit type, so they both extend
 * {@link AbstractSingleDBTraceCodeUnitsView}.
 * 
 * <p>
 * The abstract classes do not nominally implement the trace manager's
 * {@link TraceBaseCodeUnitsView} nor {@link TraceBaseDefinedUnitsView} interfaces, because Java
 * prevents the (nominal) implementation of the same interface with different type parameters by the
 * same class. E.g., {@link DBTraceDataView} would inherit
 * {@code TraceBaseCodeUnitsView<DBTraceData>} via {@link AbstractBaseDBTraceCodeUnitsView}, but
 * also {@code TraceBaseCodeUnitsView<TraceDataUnit>} via {@link TraceDataView}. Instead, the
 * abstract classes <em>structurally</em> implement those interfaces, meaning they implement the
 * methods required by the interface, but without naming the interface in their `implements` clause.
 * The realizations, e.g., {@link DBTraceDataView}, <em>nominally</em> implement their corresponding
 * interfaces, meaning they do name the interface. Each realization will inherit the structural
 * implementation from the abstract classes, satisfying the requirements imposed by nominally
 * implementing the interface.
 * 
 * <p>
 * Note, as a result, navigating from declarations in the interfaces to implementations in abstract
 * classes using your IDE may not work as expected :/ . The best way is probably to display the type
 * hierarchy of the interface declaring the desired method. Open one of the classes implementing it,
 * then display all its methods, including those inherited, and search for desired method.
 * 
 * <p>
 * Here is the type hierarchy presented with notes regarding structural interface implementations:
 * <ul>
 * <li>{@link AbstractBaseDBTraceCodeUnitsView} structurally implements
 * {@link TraceBaseCodeUnitsView}</li>
 * <ul>
 * <li>{@link AbstractComposedDBTraceCodeUnitsView}</li>
 * <ul>
 * <li>{@link DBTraceCodeUnitsView} nominally implements {@link TraceCodeUnitsView}</li>
 * <li>{@link DBTraceDataView} nominally implements {@link TraceDataView}</li>
 * <li>{@link DBTraceDefinedUnitsView} nominally implements {@link TraceDefinedUnitsView}</li>
 * </ul>
 * <li>{@link AbstractSingleDBTraceCodeUnitsView}</li>
 * <ul>
 * <li>{@link AbstractBaseDBTraceDefinedUnitsView} structurally implements
 * {@link TraceBaseDefinedUnitsView}</li>
 * <ul>
 * <li>{@link DBTraceDefinedDataView} nominally implements {@link TraceDefinedDataView}</li>
 * <li>{@link DBTraceInstructionsView} nominally implements {@link TraceInstructionsView}</li>
 * </ul>
 * <li>{@link DBTraceUndefinedDataView} nominally implements {@link TraceUndefinedDataView}</li>
 * </ul>
 * </ul>
 * 
 * <p>
 * The view composition is not hierarchical, as each may represent a different combination, and one
 * type may appear in several compositions. The single-type views are named first, then the composed
 * views:
 * <ul>
 * <li>Instructions - single-type view</li>
 * <li>Defined Data - single-type view</li>
 * <li>Undefined Data - single-type view</li>
 * </ul>
 * 
 * <p>
 * Note that while the API presents separate views for defined data and undefined units, both are
 * represented by the type {@link TraceData}. Meaning, a client with a data unit in hand cannot
 * determine whether it is defined or undefined from its type alone. It must invoke
 * {@link Data#isDefined()} instead. While the implementation provides a separate type, which we see
 * mirrors the hierarchy of the views' implementation, the client interfaces do not.
 * 
 * <ul>
 * <li>Code Units - Instructions, Defined Data, Undefined Data</li>
 * <li>Data - Defined Data, Undefined Data</li>
 * <li>Defined Units - Instructions, Defined Data</li>
 * </ul>
 * 
 * <p>
 * The {@code MemoryView} classes compose the memory address spaces into a single view. These need
 * not mirror the same implementation hierarchy as the views they compose. Other than special
 * handling for compositions including undefined units, each memory view need not know anything
 * about the views it composes. There are two abstract classes:
 * {@link AbstractBaseDBTraceCodeUnitsMemoryView}, which is suitable for composing views without
 * undefined units, and {@link AbstractWithUndefinedDBTraceCodeUnitsMemoryView}, which extends the
 * base making it suitable for composing views with undefined units. The realizations each extend
 * from the appropriate abstract class. Again, the abstract classes do not nominally implement
 * {@link TraceBaseCodeUnitsView}. They structurally implement it, partly satisfying the
 * requirements on the realizations, which nominally implement their appropriate interfaces.
 */
public class DBTraceCodeManager extends AbstractDBTraceSpaceBasedManager<DBTraceCodeSpace>
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
		new WeakValueHashMap<>();

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
		return new DBTraceCodeSpace(this, dbh, space, ent, null);
	}

	@Override
	protected DBTraceCodeSpace createRegisterSpace(AddressSpace space, TraceThread thread,
			DBTraceSpaceEntry ent) throws VersionException, IOException {
		return new DBTraceCodeSpace(this, dbh, space, ent, thread);
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
	public DBTraceCodeSpace getCodeRegisterSpace(TraceThread thread,
			boolean createIfAbsent) {
		return getForRegisterSpace(thread, 0, createIfAbsent);
	}

	@Override
	public DBTraceCodeSpace getCodeRegisterSpace(TraceThread thread, int frameLevel,
			boolean createIfAbsent) {
		return getForRegisterSpace(thread, frameLevel, createIfAbsent);
	}

	@Override
	public DBTraceCodeSpace getCodeRegisterSpace(TraceStackFrame frame,
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
	public void clearPlatform(Lifespan span, AddressRange range, DBTraceGuestPlatform guest,
			TaskMonitor monitor) throws CancelledException {
		delegateDeleteV(range.getAddressSpace(),
			m -> m.clearPlatform(span, range, guest, monitor));
	}

	@Internal
	public void deletePlatform(DBTraceGuestPlatform guest, TaskMonitor monitor)
			throws CancelledException {
		// TODO: Use sub-monitors when available
		for (DBTraceCodeSpace codeSpace : memSpaces.values()) {
			codeSpace.clearPlatform(Lifespan.ALL, codeSpace.all, guest, monitor);
		}
		for (DBTraceCodeSpace codeSpace : regSpaces.values()) {
			// TODO: I don't know any way to get guest instructions into register space
			// The mapping manager does (should) not allow guest register addresses
			// TODO: Test this if I ever get guest data units
			// TODO: I think explicit per-thread/frame register spaces will be going away, anyway
			// They'll just be path-named overlays on register space?
			codeSpace.clearPlatform(Lifespan.ALL, codeSpace.all, guest, monitor);
		}
	}

	@Internal
	public void deleteLangauge(DBTraceGuestLanguage guest, TaskMonitor monitor)
			throws CancelledException {
		monitor.setMessage("Clearing instruction prototypes");
		monitor.setMaximum(protoStore.getRecordCount());
		for (Iterator<DBTraceCodePrototypeEntry> it = protoStore.asMap().values().iterator(); it
				.hasNext();) {
			monitor.checkCancelled();
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
