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

import com.google.common.collect.Collections2;
import com.google.common.collect.Range;

import db.DBHandle;
import db.DBRecord;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.symbol.*;
import ghidra.trace.database.DBTrace;
import ghidra.trace.database.DBTraceUtils;
import ghidra.trace.database.DBTraceUtils.*;
import ghidra.trace.database.map.*;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.AbstractDBTraceAddressSnapRangePropertyMapData;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.TraceAddressSnapRangeQuery;
import ghidra.trace.database.space.AbstractDBTraceSpaceBasedManager.DBTraceSpaceEntry;
import ghidra.trace.database.space.DBTraceSpaceBased;
import ghidra.trace.database.thread.DBTraceThread;
import ghidra.trace.model.Trace.TraceReferenceChangeType;
import ghidra.trace.model.Trace.TraceSymbolChangeType;
import ghidra.trace.model.symbol.TraceReference;
import ghidra.trace.model.symbol.TraceReferenceSpace;
import ghidra.trace.util.TraceChangeRecord;
import ghidra.util.LockHold;
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
				return new DBTraceOffsetReference(ent);
			}
		},
		SHIFT {
			@Override
			protected DBTraceReference construct(DBTraceReferenceEntry ent) {
				return new DBTraceShiftedReference(ent);
			}
		};

		protected abstract DBTraceReference construct(DBTraceReferenceEntry ent);
	}

	@DBAnnotatedObjectInfo(version = 0)
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

		@DBAnnotatedField(column = TO_ADDR_COLUMN_NAME, indexed = true, codec = AddressDBFieldCodec.class)
		protected Address toAddress;
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
		public Address decodeAddress(int spaceId, long offset) {
			return this.space.baseLanguage.getAddressFactory().getAddress(spaceId, offset);
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

		protected void setLifespan(Range<Long> lifespan) {
			super.doSetLifespan(lifespan);
			space.manager.doSetXRefLifespan(this);
		}

		public void setEndSnap(long endSnap) {
			setLifespan(DBTraceUtils.toRange(DBTraceUtils.lowerEndpoint(lifespan), endSnap));
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
					TraceSymbolChangeType.ASSOCIATION_REMOVED, space, oldSymbol, ref));
			}
			if (newSymbol != null) {
				space.trace.setChanged(new TraceChangeRecord<>(
					TraceSymbolChangeType.ASSOCIATION_ADDED, space, newSymbol, ref));
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

		protected void setLifespan(Range<Long> lifespan) {
			super.doSetLifespan(lifespan);
		}
	}

	protected final DBTraceReferenceManager manager;
	protected final DBHandle dbh;
	protected final AddressSpace space;
	protected final ReadWriteLock lock;
	protected final Language baseLanguage;
	protected final DBTrace trace;

	protected final AddressRangeImpl fullSpace;

	protected final DBTraceAddressSnapRangePropertyMapSpace<DBTraceReferenceEntry, DBTraceReferenceEntry> referenceMapSpace;
	protected final DBCachedObjectIndex<Long, DBTraceReferenceEntry> refsBySymbolId;

	protected final DBTraceAddressSnapRangePropertyMapSpace<DBTraceXRefEntry, DBTraceXRefEntry> xrefMapSpace;
	protected final DBCachedObjectIndex<Long, DBTraceXRefEntry> xrefsByRefKey;

	public DBTraceReferenceSpace(DBTraceReferenceManager manager, DBHandle dbh, AddressSpace space,
			DBTraceSpaceEntry ent) throws VersionException, IOException {
		this.manager = manager;
		this.dbh = dbh;
		this.space = space;
		this.lock = manager.getLock();
		this.baseLanguage = manager.getBaseLanguage();
		this.trace = manager.getTrace();

		this.fullSpace = new AddressRangeImpl(space.getMinAddress(), space.getMaxAddress());

		DBCachedObjectStoreFactory factory = trace.getStoreFactory();

		long threadKey = ent.getThreadKey();
		int frameLevel = ent.getFrameLevel();
		this.referenceMapSpace = new DBTraceAddressSnapRangePropertyMapSpace<>(
			DBTraceReferenceEntry.tableName(space, threadKey, frameLevel), factory, lock, space,
			DBTraceReferenceEntry.class, (t, s, r) -> new DBTraceReferenceEntry(this, t, s, r));
		this.refsBySymbolId =
			referenceMapSpace.getUserIndex(long.class, DBTraceReferenceEntry.SYMBOL_ID_COLUMN);

		this.xrefMapSpace = new DBTraceAddressSnapRangePropertyMapSpace<>(
			DBTraceXRefEntry.tableName(space, threadKey, frameLevel), factory, lock, space,
			DBTraceXRefEntry.class, (t, s, r) -> new DBTraceXRefEntry(this, t, s, r));
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
	public DBTraceThread getThread() {
		return null;
	}

	@Override
	public int getFrameLevel() {
		return 0;
	}

	@Override
	public DBTraceReference addReference(TraceReference reference) {
		return addReference(reference.getLifespan(), reference);
	}

	@Override
	public DBTraceReference addReference(Range<Long> lifespan, Reference reference) {
		// Copy over other properties?:
		//    Symbol ID? (maybe not, since associated symbol may not exist here
		//    Primary? (maybe not, primary is more a property of the from address
		// TODO: Reference (from, to, opIndex) must be unique!
		if (reference.isOffsetReference()) {
			OffsetReference oRef = (OffsetReference) reference;
			return addOffsetReference(lifespan, oRef.getFromAddress(), oRef.getToAddress(),
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

	protected void makeWay(Range<Long> span, Address fromAddress, Address toAddress,
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
	public DBTraceReference addMemoryReference(Range<Long> lifespan, Address fromAddress,
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

	@Override
	public DBTraceOffsetReference addOffsetReference(Range<Long> lifespan, Address fromAddress,
			Address toAddress, long offset, RefType refType, SourceType source, int operandIndex) {
		if (operandIndex < -1) {
			throw new IllegalArgumentException("operandIndex");
		}
		try (LockHold hold = LockHold.lock(lock.writeLock())) {
			makeWay(lifespan, fromAddress, toAddress, operandIndex);

			DBTraceReferenceEntry entry = referenceMapSpace.put(fromAddress, lifespan, null);
			entry.set(toAddress, -1, refType, operandIndex, offset, false, TypeEnum.OFFSET, source);
			DBTraceOffsetReference ref = new DBTraceOffsetReference(entry);
			entry.ref = ref;
			manager.doAddXRef(entry);
			return ref;
		}
	}

	@Override
	public DBTraceShiftedReference addShiftedReference(Range<Long> lifespan, Address fromAddress,
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
	public DBTraceReference addRegisterReference(Range<Long> lifespan, Address fromAddress,
			Register toRegister, RefType refType, SourceType source, int operandIndex) {
		return addMemoryReference(lifespan, fromAddress, toRegister.getAddress(), refType, source,
			operandIndex);
	}

	@Override
	public DBTraceReference addStackReference(Range<Long> lifespan, Address fromAddress,
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

	@Override
	public Collection<? extends DBTraceReference> getReferencesFrom(long snap,
			Address fromAddress) {
		return Collections2.transform(
			referenceMapSpace.reduce(TraceAddressSnapRangeQuery.at(fromAddress, snap)).values(),
			e -> e.ref);
	}

	@Override
	public Collection<? extends DBTraceReference> getReferencesFrom(long snap, Address fromAddress,
			int operandIndex) {
		return Collections2.filter(getReferencesFrom(snap, fromAddress),
			r -> r.getOperandIndex() == operandIndex);
	}

	@Override
	public Collection<? extends DBTraceReference> getReferencesFromRange(Range<Long> span,
			AddressRange range) {
		return Collections2.transform(
			referenceMapSpace.reduce(TraceAddressSnapRangeQuery.intersecting(range, span)).values(),
			e -> e.ref);
	}

	@Override
	public DBTraceReference getPrimaryReferenceFrom(long snap, Address fromAddress,
			int operandIndex) {
		for (DBTraceReference ref : getReferencesFrom(snap, fromAddress)) {
			if (!ref.isPrimary()) {
				continue;
			}
			if (ref.getOperandIndex() != operandIndex) {
				continue;
			}
			return ref;
		}
		return null;
	}

	@Override
	public Collection<? extends DBTraceReference> getFlowReferencesFrom(long snap,
			Address fromAddress) {
		return Collections2.filter(getReferencesFrom(snap, fromAddress),
			r -> r.getReferenceType().isFlow());
	}

	@Override
	public void clearReferencesFrom(Range<Long> span, AddressRange range) {
		long startSnap = DBTraceUtils.lowerEndpoint(span);
		for (DBTraceReferenceEntry ref : referenceMapSpace.reduce(
			TraceAddressSnapRangeQuery.intersecting(range, span)).values()) {
			if (DBTraceUtils.lowerEndpoint(ref.getLifespan()) < startSnap) {
				Range<Long> oldSpan = ref.getLifespan();
				ref.setEndSnap(startSnap - 1);
				trace.setChanged(new TraceChangeRecord<>(TraceReferenceChangeType.LIFESPAN_CHANGED,
					this, ref.ref, oldSpan, ref.getLifespan()));
			}
			else {
				ref.ref.delete();
			}
			// TODO: Coalesce events?
		}
	}

	protected DBTraceReference getRefForXRefEntry(DBTraceXRefEntry e) {
		AddressSpace fromAddressSpace =
			baseLanguage.getAddressFactory().getAddressSpace(e.refSpaceId);
		DBTraceReferenceSpace fromSpace = manager.getForSpace(fromAddressSpace, false);
		assert fromSpace != null;
		return fromSpace.referenceMapSpace.getDataByKey(e.refKey).ref;
	}

	@Override
	public Collection<? extends DBTraceReference> getReferencesTo(long snap, Address toAddress) {
		return Collections2.transform(
			xrefMapSpace.reduce(TraceAddressSnapRangeQuery.at(toAddress, snap)).values(),
			this::getRefForXRefEntry);
	}

	@Override
	public Collection<? extends DBTraceReference> getReferencesToRange(Range<Long> span,
			AddressRange range) {
		return Collections2.transform(
			xrefMapSpace.reduce(TraceAddressSnapRangeQuery.intersecting(range, span)).values(),
			this::getRefForXRefEntry);
	}

	@Override
	public AddressSetView getReferenceSources(Range<Long> span) {
		return new DBTraceAddressSnapRangePropertyMapAddressSetView<>(space, lock,
			referenceMapSpace.reduce(TraceAddressSnapRangeQuery.intersecting(fullSpace, span)),
			e -> true);
	}

	@Override
	public AddressSetView getReferenceDestinations(Range<Long> span) {
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
		return Collections2.transform(refsBySymbolId.get(id), e -> e.ref);
	}

	@Override
	public void invalidateCache() {
		try (LockHold hold = LockHold.lock(lock.writeLock())) {
			referenceMapSpace.invalidateCache();
			xrefMapSpace.invalidateCache();
		}
	}
}
