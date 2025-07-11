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
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.function.Predicate;

import db.DBHandle;
import db.DBRecord;
import ghidra.framework.data.OpenMode;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;
import ghidra.trace.database.DBTrace;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.AbstractDBTraceAddressSnapRangePropertyMapData;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.TraceAddressSnapRangeQuery;
import ghidra.trace.database.space.AbstractDBTraceSpaceBasedManager;
import ghidra.trace.database.space.DBTraceDelegatingManager;
import ghidra.trace.database.thread.DBTraceThreadManager;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.TraceAddressSnapRange;
import ghidra.trace.model.map.TraceAddressSnapRangePropertyMap;
import ghidra.trace.model.stack.TraceStackFrame;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.UnionAddressSetView;
import ghidra.util.database.DBCachedObjectStore;
import ghidra.util.database.spatial.SpatialMap;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

public class DBTraceAddressSnapRangePropertyMap<T, DR extends AbstractDBTraceAddressSnapRangePropertyMapData<T>>
		extends AbstractDBTraceSpaceBasedManager<DBTraceAddressSnapRangePropertyMapSpace<T, DR>>
		implements TraceAddressSnapRangePropertyMap<T>,
		DBTraceDelegatingManager<DBTraceAddressSnapRangePropertyMapSpace<T, DR>> {

	public static interface DBTraceAddressSnapRangePropertyMapDataFactory<T, DR extends AbstractDBTraceAddressSnapRangePropertyMapData<T>> {
		DR create(DBTraceAddressSnapRangePropertyMapTree<T, DR> tree, DBCachedObjectStore<DR> store,
				DBRecord record);
	}

	protected final Class<DR> dataType;
	protected final DBTraceAddressSnapRangePropertyMapDataFactory<T, DR> dataFactory;

	public DBTraceAddressSnapRangePropertyMap(String name, DBHandle dbh, OpenMode openMode,
			ReadWriteLock lock, TaskMonitor monitor, Language baseLanguage, DBTrace trace,
			DBTraceThreadManager threadManager, Class<DR> dataType,
			DBTraceAddressSnapRangePropertyMapDataFactory<T, DR> dataFactory)
			throws IOException, VersionException {
		super(name, dbh, openMode, lock, monitor, baseLanguage, trace, threadManager);
		this.dataType = dataType;
		this.dataFactory = dataFactory;

		loadSpaces();
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	protected DBTraceAddressSnapRangePropertyMapSpace<T, DR> createSpace(AddressSpace space,
			DBTraceSpaceEntry ent) throws VersionException, IOException {
		return new DBTraceAddressSnapRangePropertyMapSpace<>(tableName(space), trace,
			trace.getStoreFactory(), lock, space, dataType, dataFactory);
	}

	@Override
	public DBTraceAddressSnapRangePropertyMapSpace<T, DR> getRegisterSpace(TraceThread thread,
			boolean createIfAbsent) {
		return getForRegisterSpace(thread, 0, createIfAbsent);
	}

	@Override
	public DBTraceAddressSnapRangePropertyMapSpace<T, DR> getRegisterSpace(TraceStackFrame frame,
			boolean createIfAbsent) {
		return getForRegisterSpace(frame, createIfAbsent);
	}

	@Override
	public DBTraceAddressSnapRangePropertyMapSpace<T, DR> getForSpace(AddressSpace space,
			boolean createIfAbsent) {
		return super.getForSpace(space, createIfAbsent);
	}

	@Override
	public Lock readLock() {
		return lock.readLock();
	}

	@Override
	public Lock writeLock() {
		return lock.writeLock();
	}

	@Override
	@SuppressWarnings({ "unchecked" })
	public void deleteValue(T value) {
		if (!(value instanceof AbstractDBTraceAddressSnapRangePropertyMapData)) {
			throw new IllegalArgumentException(
				"Can only directly delete values for maps where the entry is the value");
		}
		deleteData((DR) value);
	}

	// NOTE: DR is not declared in interface
	public void deleteData(DR data) {
		AddressSpace space = data.range.getAddressSpace();
		delegateDeleteV(space, m -> m.deleteData(data));
	}

	@Override
	public T put(TraceAddressSnapRange shape, T value) {
		return delegateWrite(shape.getRange().getAddressSpace(), m -> m.put(shape, value));
	}

	@Override
	public boolean remove(TraceAddressSnapRange shape, T value) {
		return delegateDeleteB(shape.getRange().getAddressSpace(), m -> m.remove(shape, value),
			false);
	}

	@Override
	public boolean remove(Entry<TraceAddressSnapRange, T> entry) {
		return delegateDeleteB(entry.getKey().getRange().getAddressSpace(), m -> m.remove(entry),
			false);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Note this counts entries in memory spaces only. No register spaces are included.
	 */
	@Override
	public int size() {
		int count = 0;
		for (DBTraceAddressSnapRangePropertyMapSpace<T, DR> space : getActiveSpaces()) {
			count += space.size();
		}
		return count;
	}

	@Override
	public boolean isEmpty() {
		return !delegateAny(spacesView, m -> !m.isEmpty());
	}

	@Override
	public Collection<Entry<TraceAddressSnapRange, T>> entries() {
		return delegateCollection(spacesView, m -> m.entries());
	}

	@Override
	public Collection<Entry<TraceAddressSnapRange, T>> orderedEntries() {
		return delegateCollection(spacesView, m -> m.orderedEntries());
	}

	@Override
	public Collection<TraceAddressSnapRange> keys() {
		return delegateCollection(spacesView, m -> m.keys());
	}

	@Override
	public Collection<TraceAddressSnapRange> orderedKeys() {
		return delegateCollection(spacesView, m -> m.orderedKeys());
	}

	@Override
	public Collection<T> values() {
		return delegateCollection(spacesView, m -> m.values());
	}

	@Override
	public Collection<T> orderedValues() {
		return delegateCollection(spacesView, m -> m.orderedValues());
	}

	@Override
	public SpatialMap<TraceAddressSnapRange, T, TraceAddressSnapRangeQuery> reduce(
			TraceAddressSnapRangeQuery query) {
		return delegateRead(query.getAddressSpace(), m -> m.reduce(query), SpatialMap.emptyMap());
	}

	@Override
	public Entry<TraceAddressSnapRange, T> firstEntry() {
		return delegateFirst(spacesView, m -> m.firstEntry());
	}

	@Override
	public TraceAddressSnapRange firstKey() {
		return delegateFirst(spacesView, m -> m.firstKey());
	}

	@Override
	public T firstValue() {
		return delegateFirst(spacesView, m -> m.firstValue());
	}

	@Override
	public void clear() {
		for (DBTraceAddressSnapRangePropertyMapSpace<T, DR> space : spacesView) {
			space.clear();
		}
	}

	@Override
	public AddressSetView getAddressSetView(Lifespan span, Predicate<T> predicate) {
		return new UnionAddressSetView(
			spaces.values().stream().map(m -> m.getAddressSetView(span, predicate)).toList());
	}

	@Override
	public AddressSetView getAddressSetView(Lifespan span) {
		return getAddressSetView(span, t -> true);
	}
}
