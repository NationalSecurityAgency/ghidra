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
import ghidra.trace.database.DBTrace;
import ghidra.trace.database.DBTraceUtils;
import ghidra.trace.database.map.*;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.AbstractDBTraceAddressSnapRangePropertyMapData;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.TraceAddressSnapRangeQuery;
import ghidra.trace.database.space.AbstractDBTraceSpaceBasedManager.DBTraceSpaceEntry;
import ghidra.trace.database.space.DBTraceSpaceBased;
import ghidra.trace.database.thread.DBTraceThread;
import ghidra.trace.model.symbol.TraceEquateSpace;
import ghidra.util.LockHold;
import ghidra.util.database.*;
import ghidra.util.database.annot.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

public class DBTraceEquateSpace implements DBTraceSpaceBased, TraceEquateSpace {
	protected enum EquateRefType {
		OP, HASH;
	}

	@DBAnnotatedObjectInfo(version = 0)
	protected static class DBTraceEquateReference
			extends AbstractDBTraceAddressSnapRangePropertyMapData<DBTraceEquateReference> {
		private static final String TABLE_NAME = "EquateRefs";

		private static final String EQUATE_COLUMN_NAME = "Equate";
		private static final String OP_HASH_COLUMN_NAME = "OpOrHash";
		private static final String TYPE_COLUMN_NAME = "Type";

		@DBAnnotatedColumn(EQUATE_COLUMN_NAME)
		static DBObjectColumn EQUATE_COLUMN;
		@DBAnnotatedColumn(OP_HASH_COLUMN_NAME)
		static DBObjectColumn OP_HASH_COLUMN;
		@DBAnnotatedColumn(TYPE_COLUMN_NAME)
		static DBObjectColumn TYPE_COLUMN;

		public static String tableName(AddressSpace space, long threadKey, int frameLevel) {
			return DBTraceUtils.tableName(TABLE_NAME, space, threadKey, frameLevel);
		}

		@DBAnnotatedField(column = EQUATE_COLUMN_NAME, indexed = true)
		long equateKey;
		@DBAnnotatedField(column = OP_HASH_COLUMN_NAME)
		long opOrHash;
		@DBAnnotatedField(column = TYPE_COLUMN_NAME)
		EquateRefType type; // TODO: Could probably pack into upper bit of equateKey

		protected final DBTraceEquateSpace space;

		public DBTraceEquateReference(DBTraceEquateSpace space,
				DBTraceAddressSnapRangePropertyMapTree<DBTraceEquateReference, ?> tree,
				DBCachedObjectStore<?> store, DBRecord record) {
			super(tree, store, record);
			this.space = space;
		}

		@Override
		protected void setRecordValue(DBTraceEquateReference value) {
			// Nothing: record is the value
		}

		@Override
		protected DBTraceEquateReference getRecordValue() {
			return this;
		}

		protected void setLifespan(Range<Long> lifespan) {
			doSetLifespan(lifespan);
		}
	}

	protected final DBTraceEquateManager manager;
	protected final DBHandle dbh;
	protected final AddressSpace space;
	protected final ReadWriteLock lock;
	protected final Language baseLanguage;
	protected final DBTrace trace;

	protected final AddressRangeImpl fullSpace;

	protected final DBTraceAddressSnapRangePropertyMapSpace<DBTraceEquateReference, DBTraceEquateReference> equateMapSpace;

	public DBTraceEquateSpace(DBTraceEquateManager manager, DBHandle dbh, AddressSpace space,
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
		this.equateMapSpace = new DBTraceAddressSnapRangePropertyMapSpace<>(
			DBTraceEquateReference.tableName(space, threadKey, frameLevel), factory, lock, space,
			DBTraceEquateReference.class, (t, s, r) -> new DBTraceEquateReference(this, t, s, r));
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
	public AddressSetView getReferringAddresses(Range<Long> span) {
		return new DBTraceAddressSnapRangePropertyMapAddressSetView<>(space, lock,
			equateMapSpace.reduce(TraceAddressSnapRangeQuery.intersecting(fullSpace, span)),
			e -> true);
	}

	@Override
	public void clearReferences(Range<Long> span, AddressSetView asv, TaskMonitor monitor)
			throws CancelledException {
		try (LockHold hold = LockHold.lock(lock.writeLock())) {
			for (AddressRange range : asv) {
				clearReferences(span, range, monitor);
			}
		}
	}

	@Override
	public void clearReferences(Range<Long> span, AddressRange range, TaskMonitor monitor)
			throws CancelledException {
		try (LockHold hold = LockHold.lock(lock.writeLock())) {
			for (DBTraceEquateReference eref : equateMapSpace.reduce(
				TraceAddressSnapRangeQuery.intersecting(range, span)).values()) {
				DBTraceUtils.makeWay(eref, span, (d, r) -> d.setLifespan(r),
					d -> equateMapSpace.deleteData(d));
			}
		}
	}

	@Override
	public DBTraceEquate getReferencedByValue(long snap, Address address, int operandIndex,
			long value) {
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			for (DBTraceEquateReference eref : equateMapSpace.reduce(
				TraceAddressSnapRangeQuery.at(address, snap)).values()) {
				DBTraceEquate equate = manager.equateStore.getObjectAt(eref.equateKey);
				assert equate != null;
				if (equate.getValue() != value) {
					continue;
				}
				return equate;
			}
			return null;
		}
	}

	@Override
	public Collection<? extends DBTraceEquate> getReferenced(long snap, Address address,
			int operandIndex) {
		Collection<DBTraceEquateReference> refs =
			equateMapSpace.reduce(TraceAddressSnapRangeQuery.at(address, snap)).values();
		Collection<DBTraceEquateReference> filt = Collections2.filter(refs, r -> {
			if (r.type != EquateRefType.OP) {
				return false;
			}
			if (r.opOrHash != operandIndex) {
				return false;
			}
			return true;
		});
		return Collections2.transform(filt, r -> manager.equateStore.getObjectAt(r.equateKey));
	}

	@Override
	public Collection<? extends DBTraceEquate> getReferenced(long snap, Address address) {
		Collection<DBTraceEquateReference> refs =
			equateMapSpace.reduce(TraceAddressSnapRangeQuery.at(address, snap)).values();
		return Collections2.transform(refs, r -> manager.equateStore.getObjectAt(r.equateKey));
	}

	@Override
	public void invalidateCache() {
		equateMapSpace.invalidateCache();
	}
}
