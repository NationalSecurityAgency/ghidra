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
package ghidra.trace.database.map;

import java.io.IOException;
import java.util.Collection;
import java.util.Map.Entry;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.function.Predicate;

import com.google.common.collect.Range;

import ghidra.lifecycle.Internal;
import ghidra.program.model.address.*;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMap.DBTraceAddressSnapRangePropertyMapDataFactory;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.AbstractDBTraceAddressSnapRangePropertyMapData;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.TraceAddressSnapRangeQuery;
import ghidra.trace.database.space.DBTraceSpaceBased;
import ghidra.trace.database.thread.DBTraceThread;
import ghidra.trace.model.TraceAddressSnapRange;
import ghidra.trace.model.map.TraceAddressSnapRangePropertyMapSpace;
import ghidra.util.LockHold;
import ghidra.util.database.*;
import ghidra.util.database.spatial.AbstractConstraintsTreeSpatialMap;
import ghidra.util.database.spatial.SpatialMap;
import ghidra.util.exception.VersionException;

public class DBTraceAddressSnapRangePropertyMapSpace<T, DR extends AbstractDBTraceAddressSnapRangePropertyMapData<T>>
		implements DBTraceSpaceBased,
		SpatialMap<TraceAddressSnapRange, T, TraceAddressSnapRangeQuery>,
		TraceAddressSnapRangePropertyMapSpace<T> {

	protected final AddressSpace space;
	protected final ReadWriteLock lock;
	protected final DBTraceAddressSnapRangePropertyMapTree<T, DR> tree;
	protected final AbstractConstraintsTreeSpatialMap<TraceAddressSnapRange, DR, TraceAddressSnapRange, T, TraceAddressSnapRangeQuery> map;
	protected final AddressRangeImpl fullSpace;

	public DBTraceAddressSnapRangePropertyMapSpace(String tableName,
			DBCachedObjectStoreFactory storeFactory, ReadWriteLock lock, AddressSpace space,
			Class<DR> dataType, DBTraceAddressSnapRangePropertyMapDataFactory<T, DR> dataFactory)
			throws VersionException, IOException {
		this.space = space;
		this.lock = lock;

		this.tree = new DBTraceAddressSnapRangePropertyMapTree<>(storeFactory, tableName, this,
			dataType, dataFactory, true);
		this.map = tree.asSpatialMap();

		this.fullSpace = new AddressRangeImpl(space.getMinAddress(), space.getMaxAddress());
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

	public <K> DBCachedObjectIndex<K, DR> getUserIndex(Class<K> fieldClass, DBObjectColumn column) {
		return tree.getUserIndex(fieldClass, column);
	}

	@Override
	@SuppressWarnings({ "unchecked" })
	public void deleteValue(T value) {
		if (!(value instanceof AbstractDBTraceAddressSnapRangePropertyMapData)) {
			throw new UnsupportedOperationException(
				"Can only directly delete values for maps where the entry is the value");
		}
		deleteData((DR) value);
	}

	public void deleteData(DR data) {
		if (data.tree != this.tree) {
			throw new IllegalArgumentException("The given entry is not in this space");
		}
		try (LockHold hold = LockHold.lock(lock.writeLock())) {
			tree.doDeleteEntry(data);
		}
	}

	@Override
	public T put(TraceAddressSnapRange shape, T value) {
		return map.put(shape, value);
	}

	@Override
	public boolean remove(TraceAddressSnapRange shape, T value) {
		return map.remove(shape, value);
	}

	@Override
	public boolean remove(Entry<TraceAddressSnapRange, T> entry) {
		return map.remove(entry);
	}

	@Override
	public int size() {
		return map.size();
	}

	@Override
	public boolean isEmpty() {
		return map.isEmpty();
	}

	@Override
	public Collection<Entry<TraceAddressSnapRange, T>> entries() {
		return map.entries();
	}

	@Override
	public Collection<Entry<TraceAddressSnapRange, T>> orderedEntries() {
		return map.orderedEntries();
	}

	@Override
	public Collection<TraceAddressSnapRange> keys() {
		return map.keys();
	}

	@Override
	public Collection<TraceAddressSnapRange> orderedKeys() {
		return map.orderedKeys();
	}

	@Override
	public Collection<T> values() {
		return map.values();
	}

	@Override
	public Collection<T> orderedValues() {
		return map.orderedValues();
	}

	@Override
	public SpatialMap<TraceAddressSnapRange, T, TraceAddressSnapRangeQuery> reduce(
			TraceAddressSnapRangeQuery query) {
		return map.reduce(query);
	}

	@Override
	public Entry<TraceAddressSnapRange, T> firstEntry() {
		return map.firstEntry();
	}

	@Override
	public TraceAddressSnapRange firstKey() {
		return map.firstKey();
	}

	@Override
	public T firstValue() {
		return map.firstValue();
	}

	@Override
	public void clear() {
		map.clear();
	}

	@Override
	public void invalidateCache() {
		tree.invalidateCache();
	}

	@Override
	public AddressSetView getAddressSetView(Range<Long> span, Predicate<T> predicate) {
		return new DBTraceAddressSnapRangePropertyMapAddressSetView<T>(space, lock,
			reduce(TraceAddressSnapRangeQuery.intersecting(fullSpace, span)), predicate);
	}

	@Override
	public AddressSetView getAddressSetView(Range<Long> span) {
		return getAddressSetView(span, t -> true);
	}

	public DR getDataByKey(long key) {
		return tree.getDataByKey(key);
	}

	/**
	 * For developers and testers.
	 */
	@Internal
	public void checkIntegrity() {
		tree.checkIntegrity();
	}
}
