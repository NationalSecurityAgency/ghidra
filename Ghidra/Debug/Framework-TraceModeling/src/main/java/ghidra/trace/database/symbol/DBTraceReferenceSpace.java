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
package ghidra.trace.database.symbol;

import java.io.IOException;
import java.util.Collection;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.stream.Stream;

import db.DBHandle;
import db.DBRecord;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.trace.database.DBTrace;
import ghidra.trace.database.DBTraceUtils;
import ghidra.trace.database.DBTraceUtils.RefTypeDBFieldCodec;
import ghidra.trace.database.address.DBTraceOverlaySpaceAdapter;
import ghidra.trace.database.address.DBTraceOverlaySpaceAdapter.AddressDBFieldCodec;
import ghidra.trace.database.address.DBTraceOverlaySpaceAdapter.DecodesAddresses;
import ghidra.trace.database.map.*;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.AbstractDBTraceAddressSnapRangePropertyMapData;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.TraceAddressSnapRangeQuery;
import ghidra.trace.database.space.AbstractDBTraceSpaceBasedManager.DBTraceSpaceEntry;
import ghidra.trace.database.space.DBTraceSpaceBased;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.memory.TraceMemoryRegion;
import ghidra.trace.model.symbol.TraceReference;
import ghidra.trace.model.symbol.TraceReferenceSpace;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.util.TraceChangeRecord;
import ghidra.trace.util.TraceEvents;
import ghidra.util.*;
import ghidra.util.database.*;
import ghidra.util.database.annot.*;
import ghidra.util.exception.VersionException;

public class DBTraceReferenceSpace implements DBTraceSpaceBased, TraceReferenceSpace {
	protected enum TypeEnum {
		MEMORY {
			/**
			 * TODO: It seems ill-conceived to make a separate type for stack references. Shift and
			 * offset references could also be to the stack, no? Let the client examine the
			 * destination address, or make {@link Reference#isStackReference()} do it.
			 */
			@Override
			protected DBTraceReference construct(DBTraceReferenceEntry ent) {
				if (ent.toAddress.isStackAddress()) {
					return new DBTraceStackReference(ent);
				}
				return new DBTraceReference(ent);
			}
		},
		OFFSET {
			@Override
			protected DBTraceReference construct(DBTraceReferenceEntry ent) {
				return new DBTraceOffsetReference(ent, false);
			}
		},
		SHIFT {
			@Override
			protected DBTraceReference construct(DBTraceReferenceEntry ent) {
				return new DBTraceShiftedReference(ent);
			}
		},
		OFFSET_EXTERNAL { // Offset Reference into EXTERNAL memory block region
			@Override
			protected DBTraceReference construct(DBTraceReferenceEntry ent) {
				return new DBTraceOffsetReference(ent, true);
			}
		};

		protected abstract DBTraceReference construct(DBTraceReferenceEntry ent);
	}

	/**
	 * A reference entry
	 * 
	 * <p>
	 * Version history:
	 * <ul>
	 * <li>1: Change {@link #toAddress} to 10-byte fixed encoding</li>
	 * <li>0: Initial version and previous unversioned implementation</li>
	 * </ul>
	 */
	@DBAnnotatedObjectInfo(version = 1)
	protected static class DBTraceReferenceEntry
			extends AbstractDBTraceAddressSnapRangePropertyMapData<DBTraceReferenceEntry>
			implements DecodesAddresses {
		private static final String TABLE_NAME = "References";

		private static final byte SOURCE_MASK = 0x0F;
		private static final byte SOURCE_SHIFT = 0;
		//private static final byte SOURCE_CLEAR = ~(SOURCE_MASK << SOURCE_SHIFT);

		private static final byte PRIMARY_MASK = 0x10;
		private static final byte PRIMARY_CLEAR = ~PRIMARY_MASK;

		private static final byte TYPE_MASK = 0x3;
		private static final byte TYPE_SHIFT = 5;
		//private static final byte TYPE_CLEAR = ~(TYPE_MASK << TYPE_SHIFT);

		static final String TO_ADDR_COLUMN_NAME = "ToAddr";
		static final String SYMBOL_ID_COLUMN_NAME = "SymbolId";
		static final String REF_TYPE_COLUMN_NAME = "RefType";
		static final String OP_INDEX_COLUMN_NAME = "OpIndex";
		static final String EXT_COLUMN_NAME = "Ext";
		// bit-packed sourceType, isPrimary, type
		static final String FLAGS_COLUMN_NAME = "Flags";

		@DBAnnotatedColumn(TO_ADDR_COLUMN_NAME)
		static DBObjectColumn TO_ADDR_COLUMN;
		@DBAnnotatedColumn(SYMBOL_ID_COLUMN_NAME)
		static DBObjectColumn SYMBOL_ID_COLUMN;
		@DBAnnotatedColumn(REF_TYPE_COLUMN_NAME)
		static DBObjectColumn REF_TYPE_COLUMN;
		@DBAnnotatedColumn(OP_INDEX_COLUMN_NAME)
		static DBObjectColumn OP_INDEX_COLUMN;
		@DBAnnotatedColumn(EXT_COLUMN_NAME)
		static DBObjectColumn EXT_COLUMN;
		@DBAnnotatedColumn(FLAGS_COLUMN_NAME)
		static DBObjectColumn FLAGS_COLUMN;

		public static String tableName(AddressSpace space, long threadKey, int frameLevel) {
			return DBTraceUtils.tableName(TABLE_NAME, space, threadKey, frameLevel);
		}

		@DBAnnotatedField(
			column = TO_ADDR_COLUMN_NAME,
			indexed = true,
			codec = AddressDBFieldCodec.class)
		protected Address toAddress = Address.NO_ADDRESS;
		@DBAnnotatedField(column = SYMBOL_ID_COLUMN_NAME, indexed = true)
		protected long symbolId; // TODO: Is this at the from or to address? I think TO...
		@DBAnnotatedField(column = REF_TYPE_COLUMN_NAME, codec = RefTypeDBFieldCodec.class)
		protected RefType refType;
		@DBAnnotatedField(column = OP_INDEX_COLUMN_NAME)
		protected byte opIndex;
		@DBAnnotatedField(column = EXT_COLUMN_NAME)
		protected long ext; // For Offset, Shift, or others to come
		@DBAnnotatedField(column = FLAGS_COLUMN_NAME)
		protected byte flags;

		protected final DBTraceReferenceSpace space;

		protected DBTraceReference ref;

		public DBTraceReferenceEntry(DBTraceReferenceSpace space,
				DBTraceAddressSnapRangePropertyMapTree<DBTraceReferenceEntry, ?> tree,
				DBCachedObjectStore<?> store, DBRecord record) {
			super(tree, store, record);
			this.space = space;
		}

		@Override
		public DBTraceOverlaySpaceAdapter getOverlaySpaceAdapter() {
			return this.space.manager.overlayAdapter;
		}

		@Override
		protected void fresh(boolean created) throws IOException {
			super.fresh(created);
			if (created) {
				return;
			}
			TypeEnum type = TypeEnum.values()[(flags >> TYPE_SHIFT) & TYPE_MASK];
			ref = type.construct(this);
		}

		@Override
		protected void setRecordValue(DBTraceReferenceEntry value) {
			// Nothing: record is the value
		}

		@Override
		protected DBTraceReferenceEntry getRecordValue() {
			return this;
		}

		protected void set(Address toAddress, long symbolId, RefType refType, int opIndex, long ext,
				boolean isPrimary, TypeEnum type, SourceType sourceType) {
			this.toAddress = toAddress;
			this.symbolId = symbolId;
			this.refType = refType;
			this.opIndex = (byte) opIndex;
			this.ext = ext;
			this.flags = (byte) ((isPrimary ? PRIMARY_MASK : 0) |
				(sourceType.ordinal() << SOURCE_SHIFT) | type.ordinal() << TYPE_SHIFT);
			update(TO_ADDR_COLUMN, SYMBOL_ID_COLUMN, REF_TYPE_COLUMN, OP_INDEX_COLUMN, EXT_COLUMN,
				FLAGS_COLUMN);
		}

		protected void setLifespan(Lifespan lifespan) {
			super.doSetLifespan(lifespan);
			space.manager.doSetXRefLifespan(this);
		}

		public void setEndSnap(long endSnap) {
			setLifespan(lifespan.withMax(endSnap));
		}

		public void setSymbolId(long symbolId) {
			if (this.symbolId == symbolId) {
				return;
			}
			AbstractDBTraceSymbol oldSymbol =
				space.trace.getSymbolManager().getSymbolByID(this.symbolId);
			AbstractDBTraceSymbol newSymbol =
				space.trace.getSymbolManager().getSymbolByID(symbolId);
			//validateAssociation();
			this.symbolId = symbolId;
			update(SYMBOL_ID_COLUMN);

			if (oldSymbol != null) {
				space.trace.setChanged(new TraceChangeRecord<>(
					TraceEvents.SYMBOL_ASSOCIATION_REMOVED, space, oldSymbol, ref));
			}
			if (newSymbol != null) {
				space.trace.setChanged(new TraceChangeRecord<>(
					TraceEvents.SYMBOL_ASSOCIATION_ADDED, space, newSymbol, ref));
			}
		}

		public long getSymbolId() {
			return symbolId;
		}

		public void setRefType(RefType refType) {
			this.refType = refType;
			update(REF_TYPE_COLUMN);
		}

		public RefType getRefType() {
			return refType;
		}

		public void setPrimary(boolean b) {
			if (b) {
				flags |= PRIMARY_MASK;
			}
			else {
				flags &= PRIMARY_CLEAR;
			}
			update(FLAGS_COLUMN);
		}

		public boolean isPrimary() {
			return (flags & PRIMARY_MASK) != 0;
		}

		public SourceType getSourceType() {
			return SourceType.values()[(flags >> SOURCE_SHIFT) & SOURCE_MASK];
		}

		protected void doDelete() {
			try (LockHold hold = LockHold.lock(space.lock.writeLock())) {
				space.referenceMapSpace.deleteData(this);
				space.manager.doDelXRef(this);
			}
		}
	}

	@DBAnnotatedObjectInfo(version = 0)
	protected static class DBTraceXRefEntry
			extends AbstractDBTraceAddressSnapRangePropertyMapData<DBTraceXRefEntry> {
		private static final String TABLE_NAME = "XRefs";

		static final String REF_KEY_COLUMN_NAME = "RefKey";
		static final String REF_SPACE_COLUMN_NAME = "Space";

		@DBAnnotatedColumn(REF_KEY_COLUMN_NAME)
		static DBObjectColumn REF_KEY_COLUMN;
		@DBAnnotatedColumn(REF_SPACE_COLUMN_NAME)
		static DBObjectColumn REF_SPACE_COLUMN;

		public static String tableName(AddressSpace space, long threadKey, int frameLevel) {
			return DBTraceUtils.tableName(TABLE_NAME, space, threadKey, frameLevel);
		}

		@DBAnnotatedField(column = REF_SPACE_COLUMN_NAME)
		protected short refSpaceId;

		@DBAnnotatedField(column = REF_KEY_COLUMN_NAME, indexed = true)
		protected long refKey;

		protected final DBTraceReferenceSpace space;

		public DBTraceXRefEntry(DBTraceReferenceSpace space,
				DBTraceAddressSnapRangePropertyMapTree<DBTraceXRefEntry, ?> tree,
				DBCachedObjectStore<?> store, DBRecord record) {
			super(tree, store, record);
			this.space = space;
		}

		@Override
		protected void setRecordValue(DBTraceXRefEntry value) {
			// Nothing, entry is the value
		}

		@Override
		protected DBTraceXRefEntry getRecordValue() {
			return this;
		}

		void set(short refSpaceId, long refKey) {
			this.refSpaceId = refSpaceId;
			this.refKey = refKey;
			update(REF_SPACE_COLUMN, REF_KEY_COLUMN);
		}

		protected void setLifespan(Lifespan lifespan) {
			super.doSetLifespan(lifespan);
		}
	}

	protected final DBTraceReferenceManager manager;
	protected final DBHandle dbh;
	protected final AddressSpace space;
	protected final TraceThread thread;
	protected final int frameLevel;
	protected final ReadWriteLock lock;
	protected final Language baseLanguage;
	protected final DBTrace trace;

	protected final AddressRangeImpl fullSpace;

	protected final DBTraceAddressSnapRangePropertyMapSpace<DBTraceReferenceEntry, DBTraceReferenceEntry> referenceMapSpace;
	protected final DBCachedObjectIndex<Long, DBTraceReferenceEntry> refsBySymbolId;

	protected final DBTraceAddressSnapRangePropertyMapSpace<DBTraceXRefEntry, DBTraceXRefEntry> xrefMapSpace;
	protected final DBCachedObjectIndex<Long, DBTraceXRefEntry> xrefsByRefKey;

	public DBTraceReferenceSpace(DBTraceReferenceManager manager, DBHandle dbh, AddressSpace space,
			DBTraceSpaceEntry ent, TraceThread thread) throws VersionException, IOException {
		this.manager = manager;
		this.dbh = dbh;
		this.space = space;
		this.thread = thread;
		this.frameLevel = ent.getFrameLevel();
		this.lock = manager.getLock();
		this.baseLanguage = manager.getBaseLanguage();
		this.trace = manager.getTrace();

		this.fullSpace = new AddressRangeImpl(space.getMinAddress(), space.getMaxAddress());

		DBCachedObjectStoreFactory factory = trace.getStoreFactory();

		long threadKey = ent.getThreadKey();
		int frameLevel = ent.getFrameLevel();
		this.referenceMapSpace = new DBTraceAddressSnapRangePropertyMapSpace<>(
			DBTraceReferenceEntry.tableName(space, threadKey, frameLevel), factory, lock, space,
			thread, frameLevel, DBTraceReferenceEntry.class,
			(t, s, r) -> new DBTraceReferenceEntry(this, t, s, r));
		this.refsBySymbolId =
			referenceMapSpace.getUserIndex(long.class, DBTraceReferenceEntry.SYMBOL_ID_COLUMN);

		this.xrefMapSpace = new DBTraceAddressSnapRangePropertyMapSpace<>(
			DBTraceXRefEntry.tableName(space, threadKey, frameLevel), factory, lock, space, thread,
			frameLevel, DBTraceXRefEntry.class, (t, s, r) -> new DBTraceXRefEntry(this, t, s, r));
		this.xrefsByRefKey = xrefMapSpace.getUserIndex(long.class, DBTraceXRefEntry.REF_KEY_COLUMN);
	}

	protected void doAddXRef(DBTraceReferenceEntry refEnt) {
		// Note: called from manager on relevant space
		DBTraceXRefEntry xrefEnt = xrefMapSpace.put(refEnt.toAddress, refEnt.getLifespan(), null);
		xrefEnt.set((short) refEnt.getRange().getAddressSpace().getSpaceID(),
			refEnt.getKey());
	}

	protected void doDelXRef(DBTraceReferenceEntry refEnt) {
		for (DBTraceXRefEntry xrefEnt : xrefsByRefKey.get(refEnt.getKey())) {
			// Keys could be duplicate. Match the "from" space, too.
			if (xrefEnt.refSpaceId == refEnt.getRange().getAddressSpace().getSpaceID()) {
				xrefMapSpace.deleteData(xrefEnt);
				return;
			}
		}
		throw new AssertionError(); // The entry must exist (unless database is corrupt)
	}

	protected void doSetXRefLifespan(DBTraceReferenceEntry refEnt) {
		for (DBTraceXRefEntry xrefEnt : xrefsByRefKey.get(refEnt.getKey())) {
			// Keys could be duplicate. Match the "from" space, too.
			if (xrefEnt.refSpaceId == refEnt.getRange().getAddressSpace().getSpaceID()) {
				xrefEnt.setLifespan(refEnt.getLifespan());
				return;
			}
		}
		throw new AssertionError(); // The entry must exist (unless database is corrupt)
	}

	@Override
	public AddressSpace getAddressSpace() {
		return space;
	}

	@Override
	public TraceThread getThread() {
		return thread;
	}

	@Override
	public int getFrameLevel() {
		return frameLevel;
	}

	@Override
	public DBTraceReference addReference(TraceReference reference) {
		return addReference(reference.getLifespan(), reference);
	}

	@Override
	public DBTraceReference addReference(Lifespan lifespan, Reference reference) {
		// Copy over other properties?:
		//    Symbol ID? (maybe not, since associated symbol may not exist here
		//    Primary? (maybe not, primary is more a property of the from address
		// TODO: Reference (from, to, opIndex) must be unique!
		if (reference.isOffsetReference()) {
			OffsetReference oRef = (OffsetReference) reference;
			return addOffsetReference(lifespan, oRef.getFromAddress(), oRef.getBaseAddress(), true,
				oRef.getOffset(), oRef.getReferenceType(), oRef.getSource(),
				oRef.getOperandIndex());
		}
		if (reference.isShiftedReference()) {
			ShiftedReference sRef = (ShiftedReference) reference;
			return addShiftedReference(lifespan, sRef.getFromAddress(), sRef.getToAddress(),
				sRef.getShift(), sRef.getReferenceType(), sRef.getSource(), sRef.getOperandIndex());
		}
		return addMemoryReference(lifespan, reference.getFromAddress(), reference.getToAddress(),
			reference.getReferenceType(), reference.getSource(), reference.getOperandIndex());
	}

	protected void makeWay(Lifespan span, Address fromAddress, Address toAddress,
			int operandIndex) {
		// TODO: Do I consider "compatibility?" as in ReferenceDBManager?
		// NOTE: Always call with the write lock
		for (DBTraceReferenceEntry ent : referenceMapSpace.reduce(
			TraceAddressSnapRangeQuery.intersecting(new AddressRangeImpl(fromAddress, fromAddress),
				span)).values()) {
			if (!ent.toAddress.equals(toAddress)) {
				continue;
			}
			if (ent.opIndex != operandIndex) {
				continue;
			}

			// TODO: This sends events and updates primary. Do I want that here?
			DBTraceUtils.makeWay(ent, span, (e, s) -> e.setLifespan(s), e -> e.ref.delete());
		}
	}

	@Override
	public DBTraceReference addMemoryReference(Lifespan lifespan, Address fromAddress,
			Address toAddress, RefType refType, SourceType source, int operandIndex) {
		if (operandIndex < -1) {
			throw new IllegalArgumentException("operandIndex");
		}
		try (LockHold hold = LockHold.lock(lock.writeLock())) {
			makeWay(lifespan, fromAddress, toAddress, operandIndex);

			DBTraceReferenceEntry entry = referenceMapSpace.put(fromAddress, lifespan, null);
			entry.set(toAddress, -1, refType, operandIndex, 0, false, TypeEnum.MEMORY, source);
			DBTraceReference ref = TypeEnum.MEMORY.construct(entry);
			entry.ref = ref;
			manager.doAddXRef(entry);
			return ref;
		}
	}

	private boolean isExternalBlockAddress(Lifespan lifespan, Address addr) {
		// TODO: Verify that this works for emulation
		TraceMemoryRegion region =
			trace.getMemoryManager().getRegionContaining(lifespan.lmin(), addr);
		return region != null &&
			MemoryBlock.EXTERNAL_BLOCK_NAME.equals(region.getName(lifespan.lmin()));
	}

	@Override
	public DBTraceOffsetReference addOffsetReference(Lifespan lifespan, Address fromAddress,
			Address toAddress, boolean toAddrIsBase, long offset, RefType refType,
			SourceType source, int operandIndex) {
		if (operandIndex < -1) {
			throw new IllegalArgumentException("operandIndex");
		}

		try (LockHold hold = LockHold.lock(lock.writeLock())) {

			// Handle EXTERNAL Block offset-reference transformation
			TypeEnum type = TypeEnum.OFFSET;
			boolean isExternalBlockRef = isExternalBlockAddress(lifespan, toAddress);
			boolean badOffsetReference = false;
			if (isExternalBlockRef) {
				type = TypeEnum.OFFSET_EXTERNAL;
				if (!toAddrIsBase) {
					Address baseAddr = toAddress.subtractWrap(offset);
					if (isExternalBlockAddress(lifespan, baseAddr)) {
						toAddress = baseAddr;
						toAddrIsBase = true;
					}
					else {
						// assume unintentional reference into EXTERNAL block
						isExternalBlockRef = false;
						type = TypeEnum.OFFSET;
						badOffsetReference = true;
					}
				}
			}
			else if (toAddrIsBase) {
				toAddress = toAddress.addWrap(offset);
				toAddrIsBase = false;
				if (isExternalBlockAddress(lifespan, toAddress)) {
					badOffsetReference = true;
				}
			}

			if (badOffsetReference) {
				Msg.warn(this, "Offset Reference from " + fromAddress +
					" produces bad Xref into EXTERNAL block");
			}

			makeWay(lifespan, fromAddress, toAddress, operandIndex);

			DBTraceReferenceEntry entry = referenceMapSpace.put(fromAddress, lifespan, null);
			entry.set(toAddress, -1, refType, operandIndex, offset, false, type, source);
			DBTraceOffsetReference ref = new DBTraceOffsetReference(entry, isExternalBlockRef);
			entry.ref = ref;
			manager.doAddXRef(entry);
			return ref;
		}
	}

	@Override
	public DBTraceShiftedReference addShiftedReference(Lifespan lifespan, Address fromAddress,
			Address toAddress, int shift, RefType refType, SourceType source, int operandIndex) {
		if (operandIndex < -1) {
			throw new IllegalArgumentException("operandIndex");
		}
		try (LockHold hold = LockHold.lock(lock.writeLock())) {
			makeWay(lifespan, fromAddress, toAddress, operandIndex);

			DBTraceReferenceEntry entry = referenceMapSpace.put(fromAddress, lifespan, null);
			entry.set(toAddress, -1, refType, operandIndex, shift, false, TypeEnum.SHIFT, source);
			DBTraceShiftedReference ref = new DBTraceShiftedReference(entry);
			entry.ref = ref;
			manager.doAddXRef(entry);
			return ref;
		}
	}

	@Override
	public DBTraceReference addRegisterReference(Lifespan lifespan, Address fromAddress,
			Register toRegister, RefType refType, SourceType source, int operandIndex) {
		return addMemoryReference(lifespan, fromAddress, toRegister.getAddress(), refType, source,
			operandIndex);
	}

	@Override
	public DBTraceReference addStackReference(Lifespan lifespan, Address fromAddress,
			int toStackOffset, RefType refType, SourceType source, int operandIndex) {
		// TODO: base and guest compiler specs, too?
		AddressSpace stack = baseLanguage.getDefaultCompilerSpec().getStackSpace();
		return addMemoryReference(lifespan, fromAddress, stack.getAddress(toStackOffset), refType,
			source, operandIndex);
	}

	@Override
	public DBTraceReference getReference(long snap, Address fromAddress, Address toAddress,
			int operandIndex) {
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			for (DBTraceReferenceEntry entry : referenceMapSpace.reduce(
				TraceAddressSnapRangeQuery.at(fromAddress, snap)).values()) {
				if (!toAddress.equals(entry.toAddress)) {
					continue;
				}
				if (entry.opIndex != operandIndex) {
					continue;
				}
				return entry.ref;
			}
			return null;
		}
	}

	private Stream<? extends DBTraceReference> streamReferencesFrom(long snap,
			Address fromAddress) {
		return referenceMapSpace.reduce(TraceAddressSnapRangeQuery.at(fromAddress, snap))
				.values()
				.stream()
				.map(e -> e.ref);
	}

	@Override
	public Collection<? extends DBTraceReference> getReferencesFrom(long snap,
			Address fromAddress) {
		return streamReferencesFrom(snap, fromAddress).toList();
	}

	@Override
	public Collection<? extends DBTraceReference> getReferencesFrom(long snap, Address fromAddress,
			int operandIndex) {
		return streamReferencesFrom(snap, fromAddress)
				.filter(r -> r.getOperandIndex() == operandIndex)
				.toList();
	}

	@Override
	public Collection<? extends DBTraceReference> getReferencesFromRange(Lifespan span,
			AddressRange range) {
		return new LazyCollection<>(
			() -> referenceMapSpace.reduce(TraceAddressSnapRangeQuery.intersecting(range, span))
					.values()
					.stream()
					.map(e -> e.ref));
	}

	@Override
	public DBTraceReference getPrimaryReferenceFrom(long snap, Address fromAddress,
			int operandIndex) {
		return streamReferencesFrom(snap, fromAddress)
				.filter(r -> r.isPrimary() && r.getOperandIndex() == operandIndex)
				.findFirst()
				.orElse(null);
	}

	@Override
	public Collection<? extends DBTraceReference> getFlowReferencesFrom(long snap,
			Address fromAddress) {
		return streamReferencesFrom(snap, fromAddress)
				.filter(r -> r.getReferenceType().isFlow())
				.toList();
	}

	@Override
	public void clearReferencesFrom(Lifespan span, AddressRange range) {
		try (LockHold hold = manager.getTrace().lockWrite()) {
			long startSnap = span.lmin();
			for (DBTraceReferenceEntry ref : referenceMapSpace.reduce(
				TraceAddressSnapRangeQuery.intersecting(range, span)).values()) {
				truncateOrDeleteEntry(ref, startSnap);
			}
			// TODO: Coalesce events?
		}
	}

	protected DBTraceReferenceEntry getRefEntryForXRefEntry(DBTraceXRefEntry e) {
		AddressSpace fromAddressSpace =
			baseLanguage.getAddressFactory().getAddressSpace(e.refSpaceId);
		DBTraceReferenceSpace fromSpace = manager.getForSpace(fromAddressSpace, false);
		assert fromSpace != null;
		return fromSpace.referenceMapSpace.getDataByKey(e.refKey);
	}

	protected DBTraceReference getRefForXRefEntry(DBTraceXRefEntry e) {
		return getRefEntryForXRefEntry(e).ref;
	}

	@Override
	public Collection<? extends DBTraceReference> getReferencesTo(long snap, Address toAddress) {
		return xrefMapSpace.reduce(TraceAddressSnapRangeQuery.at(toAddress, snap))
				.values()
				.stream()
				.map(this::getRefForXRefEntry)
				.toList();
	}

	@Override
	public Collection<? extends DBTraceReference> getReferencesToRange(Lifespan span,
			AddressRange range) {
		return new LazyCollection<>(
			() -> xrefMapSpace.reduce(TraceAddressSnapRangeQuery.intersecting(range, span))
					.values()
					.stream()
					.map(this::getRefForXRefEntry));
	}

	protected void truncateOrDeleteEntry(DBTraceReferenceEntry ref, long otherStartSnap) {
		if (ref.getLifespan().lmin() < otherStartSnap) {
			Lifespan oldSpan = ref.getLifespan();
			ref.setEndSnap(otherStartSnap - 1);
			trace.setChanged(new TraceChangeRecord<>(TraceEvents.REFERENCE_LIFESPAN_CHANGED, this,
				ref.ref, oldSpan, ref.getLifespan()));
		}
		else {
			ref.ref.delete();
		}
	}

	@Override
	public void clearReferencesTo(Lifespan span, AddressRange range) {
		try (LockHold hold = manager.getTrace().lockWrite()) {
			long startSnap = span.lmin();
			for (DBTraceXRefEntry xref : xrefMapSpace.reduce(
				TraceAddressSnapRangeQuery.intersecting(range, span)).values()) {
				DBTraceReferenceEntry ref = getRefEntryForXRefEntry(xref);
				truncateOrDeleteEntry(ref, startSnap);
			}
			// TODO: Coalesce events?
		}
	}

	@Override
	public AddressSetView getReferenceSources(Lifespan span) {
		return new DBTraceAddressSnapRangePropertyMapAddressSetView<>(space, lock,
			referenceMapSpace.reduce(TraceAddressSnapRangeQuery.intersecting(fullSpace, span)),
			e -> true);
	}

	@Override
	public AddressSetView getReferenceDestinations(Lifespan span) {
		return new DBTraceAddressSnapRangePropertyMapAddressSetView<>(space, lock,
			xrefMapSpace.reduce(TraceAddressSnapRangeQuery.intersecting(fullSpace, span)),
			e -> true);
	}

	@Override
	public int getReferenceCountFrom(long snap, Address fromAddress) {
		return referenceMapSpace.reduce(TraceAddressSnapRangeQuery.at(fromAddress, snap)).size();
	}

	@Override
	public int getReferenceCountTo(long snap, Address toAddress) {
		return xrefMapSpace.reduce(TraceAddressSnapRangeQuery.at(toAddress, snap)).size();
	}

	protected Collection<? extends DBTraceReference> getReferencesBySymbolId(long id) {
		return refsBySymbolId.get(id).stream().map(e -> e.ref).toList();
	}

	@Override
	public void invalidateCache() {
		try (LockHold hold = LockHold.lock(lock.writeLock())) {
			referenceMapSpace.invalidateCache();
			xrefMapSpace.invalidateCache();
		}
	}
}
