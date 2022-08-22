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
package ghidra.trace.database.target;

import com.google.common.collect.Range;

import db.DBRecord;
import ghidra.trace.database.DBTraceUtils;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.AbstractDBTraceAddressSnapRangePropertyMapData;
import ghidra.trace.database.target.DBTraceObjectValue.DBTraceObjectDBFieldCodec;
import ghidra.trace.model.Trace;
import ghidra.trace.model.target.TraceObjectKeyPath;
import ghidra.trace.model.target.TraceObjectValue;
import ghidra.trace.util.TraceAddressSpace;
import ghidra.util.LockHold;
import ghidra.util.database.DBCachedObjectStore;
import ghidra.util.database.DBObjectColumn;
import ghidra.util.database.annot.*;

@DBAnnotatedObjectInfo(version = 0)
public class DBTraceObjectAddressRangeValue
		extends AbstractDBTraceAddressSnapRangePropertyMapData<DBTraceObjectAddressRangeValue>
		implements InternalTraceObjectValue {
	public static final String TABLE_NAME = "ObjectRangeValue";

	static final String PARENT_COLUMN_NAME = "ValueParent";
	static final String KEY_COLUMN_NAME = "ValueKey";
	static final String TYPE_COLUMN_NAME = "IsAddress";

	@DBAnnotatedColumn(PARENT_COLUMN_NAME)
	static DBObjectColumn PARENT_COLUMN;
	@DBAnnotatedColumn(KEY_COLUMN_NAME)
	static DBObjectColumn KEY_COLUMN;
	@DBAnnotatedColumn(TYPE_COLUMN_NAME)
	static DBObjectColumn TYPE_COLUMN;

	@DBAnnotatedField(
		column = PARENT_COLUMN_NAME,
		indexed = true,
		codec = DBTraceObjectDBFieldCodec.class)
	private DBTraceObject parent;
	@DBAnnotatedField(column = KEY_COLUMN_NAME)
	private String entryKey;
	@DBAnnotatedField(column = TYPE_COLUMN_NAME)
	private boolean isAddress;

	protected final DBTraceObjectManager manager;

	public DBTraceObjectAddressRangeValue(DBTraceObjectManager manager,
			DBTraceAddressSnapRangePropertyMapTree<DBTraceObjectAddressRangeValue, ?> tree,
			DBCachedObjectStore<?> store, DBRecord record) {
		super(tree, store, record);
		this.manager = manager;
	}

	@Override
	public String toString() {
		return getClass().getSimpleName() + ": parent=" + parent + ", key=" + entryKey +
			", lifespan=" + getLifespan() + ", value=" + getValue();
	}

	@Override
	protected void setRecordValue(DBTraceObjectAddressRangeValue value) {
		// Nothing to do. I am the value
		assert value == null;
	}

	public TraceAddressSpace getTraceAddressSpace() {
		return tree.getMapSpace();
	}

	@Override
	protected DBTraceObjectAddressRangeValue getRecordValue() {
		return this;
	}

	void set(DBTraceObject parent, String key, boolean isAddress) {
		this.parent = parent;
		this.entryKey = key;
		this.isAddress = isAddress;
		update(PARENT_COLUMN, KEY_COLUMN, TYPE_COLUMN);
	}

	@Override
	public Trace getTrace() {
		return manager.trace;
	}

	@Override
	public DBTraceObjectManager getManager() {
		return manager;
	}

	@Override
	public DBTraceObject getParent() {
		return parent;
	}

	@Override
	public String getEntryKey() {
		return entryKey;
	}

	@Override
	public Object getValue() {
		if (isAddress) {
			return getRange().getMinAddress();
		}
		return getRange();
	}

	@Override
	public DBTraceObject getChild() {
		throw new ClassCastException();
	}

	@Override
	public boolean isObject() {
		return false;
	}

	@Override
	public DBTraceObject getChildOrNull() {
		return null;
	}

	@Override
	public TraceObjectKeyPath getCanonicalPath() {
		try (LockHold hold = manager.trace.lockRead()) {
			return parent.getCanonicalPath().extend(entryKey);
		}
	}

	@Override
	public boolean isCanonical() {
		return false;
	}

	@Override
	public void doSetLifespan(Range<Long> lifespan) {
		super.doSetLifespan(lifespan);
	}

	@Override
	public void setMinSnap(long minSnap) {
		try (LockHold hold = manager.trace.lockWrite()) {
			setLifespan(DBTraceUtils.toRange(minSnap, getY2()));
		}
	}

	@Override
	public long getMinSnap() {
		try (LockHold hold = manager.trace.lockRead()) {
			return getY1();
		}
	}

	@Override
	public void setMaxSnap(long maxSnap) {
		try (LockHold hold = manager.trace.lockWrite()) {
			setLifespan(DBTraceUtils.toRange(getY1(), maxSnap));
		}
	}

	@Override
	public long getMaxSnap() {
		try (LockHold hold = manager.trace.lockRead()) {
			return getY2();
		}
	}

	@Override
	public void doDelete() {
		manager.rangeValueMap.deleteData(this);
	}

	@Override
	public void delete() {
		try (LockHold hold = LockHold.lock(manager.lock.writeLock())) {
			doDeleteAndEmit();
		}
	}

	@Override
	public TraceObjectValue truncateOrDelete(Range<Long> span) {
		try (LockHold hold = LockHold.lock(manager.lock.writeLock())) {
			return doTruncateOrDeleteAndEmitLifeChange(span);
		}
	}
}
