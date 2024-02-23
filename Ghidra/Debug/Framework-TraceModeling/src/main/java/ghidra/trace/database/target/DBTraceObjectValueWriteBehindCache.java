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

import java.util.*;
import java.util.concurrent.ExecutionException;
import java.util.function.Predicate;
import java.util.stream.Stream;

import db.Transaction;
import ghidra.async.AsyncReference;
import ghidra.program.model.address.*;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.target.TraceObjectInterface;
import ghidra.trace.model.target.TraceObjectKeyPath;
import ghidra.util.*;

class DBTraceObjectValueWriteBehindCache {
	public static final int INITIAL_CACHE_SIZE = 1000;
	public static final int BATCH_SIZE = 100;
	public static final int DELAY_MS = 10000;

	private final DBTraceObjectManager manager;
	private final Thread worker;
	private volatile long mark = 0;
	private final AsyncReference<Boolean, Void> busy = new AsyncReference<>(false);
	private volatile boolean flushing = false;

	private final Map<DBTraceObject, Map<String, NavigableMap<Long, DBTraceObjectValueBehind>>> cachedValues =
		new HashMap<>();

	public DBTraceObjectValueWriteBehindCache(DBTraceObjectManager manager) {
		this.manager = manager;

		worker = new Thread(this::workLoop, "WriteBehind for " + manager.trace.getName());
		worker.start();
	}

	private void workLoop() {
		while (!manager.trace.isClosed()) {
			try {
				synchronized (cachedValues) {
					if (cachedValues.isEmpty()) {
						busy.set(false, null);
						flushing = false;
						cachedValues.wait();
					}
					while (!flushing) {
						long left = mark - System.currentTimeMillis();
						if (left <= 0) {
							break;
						}
						Msg.trace(this,
							"Waiting %d ms. Cache is %d big".formatted(left, cachedValues.size()));
						cachedValues.wait(left);
					}
				}
				if (manager.trace.isClosed()) {
					break;
				}
				writeBatch();
				if (!flushing && !manager.trace.isClosing()) {
					Thread.sleep(100);
				}
			}
			catch (InterruptedException e) {
			}
		}
		busy.set(false, null);
		flushing = false;
	}

	private List<DBTraceObjectValueBehind> getBatch() {
		synchronized (cachedValues) {
			return doStreamAllValues()
					.limit(BATCH_SIZE)
					.toList();
		}
	}

	private Stream<DBTraceObjectValueBehind> doStreamAllValues() {
		return cachedValues.values()
				.stream()
				.flatMap(v -> v.values().stream())
				.flatMap(v -> v.values().stream());
	}

	private void doAdd(DBTraceObjectValueBehind behind) {
		var keys = cachedValues.computeIfAbsent(behind.getParent(), k -> new HashMap<>());
		var values = keys.computeIfAbsent(behind.getEntryKey(), k -> new TreeMap<>());
		values.put(behind.getLifespan().min(), behind);
	}

	NavigableMap<Long, DBTraceObjectValueBehind> doRemoveNoCleanup(
			DBTraceObjectValueBehind behind) {
		var keys = cachedValues.get(behind.getParent());
		var values = keys.get(behind.getEntryKey());
		values.remove(behind.getLifespan().min());
		return values;
	}

	void doAddDirect(NavigableMap<Long, DBTraceObjectValueBehind> values,
			DBTraceObjectValueBehind b) {
		values.put(b.getLifespan().min(), b);
	}

	private void doRemove(DBTraceObjectValueBehind behind) {
		var keys = cachedValues.get(behind.getParent());
		var values = keys.get(behind.getEntryKey());
		values.remove(behind.getLifespan().min());
		if (values.isEmpty()) {
			keys.remove(behind.getEntryKey());
			if (keys.isEmpty()) {
				cachedValues.remove(behind.getParent());
			}
		}
	}

	private void writeBatch() {
		try (Transaction tx = manager.trace.openTransaction("Write Behind")) {
			try (LockHold hold = LockHold.lock(manager.lock.writeLock())) {
				for (DBTraceObjectValueBehind behind : getBatch()) {
					synchronized (cachedValues) {
						doRemove(behind);
					}
					DBTraceObjectValueData value = manager.doCreateValueData(behind.getLifespan(),
						behind.getParent(), behind.getEntryKey(), behind.getValue());
					behind.getWrapper().setWrapped(value);
				}
			}
		}
		manager.trace.clearUndo();
		Msg.trace(this, "Wrote a batch. %d parents remain.".formatted(cachedValues.size()));
	}

	public DBTraceObjectValueBehind doCreateValue(Lifespan lifespan, DBTraceObject parent,
			String key, Object value) {
		if (manager.trace.isClosing()) {
			throw new IllegalStateException("Trace is closing");
		}
		DBTraceObjectValueBehind entry =
			new DBTraceObjectValueBehind(manager, parent, key, lifespan,
				manager.validateValue(value));
		synchronized (cachedValues) {
			doAdd(entry);
			mark = System.currentTimeMillis() + DELAY_MS;
			busy.set(true, null);
			cachedValues.notify();
		}
		return entry;
	}

	public void remove(DBTraceObjectValueBehind value) {
		synchronized (cachedValues) {
			doRemove(value);
		}
	}

	public void clear() {
		synchronized (cachedValues) {
			cachedValues.clear();
		}
	}

	public Stream<DBTraceObjectValueBehind> streamAllValues() {
		return StreamUtils.sync(cachedValues, doStreamAllValues());
	}

	public DBTraceObjectValueBehind get(DBTraceObject parent, String key, long snap) {
		synchronized (cachedValues) {
			var keys = cachedValues.get(parent);
			if (keys == null) {
				return null;
			}
			var values = keys.get(key);
			if (values == null) {
				return null;
			}

			var floor = values.floorEntry(snap);
			if (floor == null) {
				return null;
			}

			if (!floor.getValue().getLifespan().contains(snap)) {
				return null;
			}
			return floor.getValue();
		}
	}

	public Stream<DBTraceObjectValueBehind> streamParents(DBTraceObject child, Lifespan lifespan) {
		// TODO: Optimize/index this?
		return streamAllValues()
				.filter(v -> v.getValue() == child && v.getLifespan().intersects(lifespan));
	}

	private Stream<DBTraceObjectValueBehind> streamSub(
			NavigableMap<Long, DBTraceObjectValueBehind> map, Lifespan span, boolean forward) {
		Long floor = map.floorKey(span.min());
		if (floor == null) {
			floor = span.min();
		}
		var sub = map.subMap(floor, true, span.max(), true);
		if (!forward) {
			sub = sub.descendingMap();
		}
		return sub.values().stream();
	}

	public Stream<DBTraceObjectValueBehind> streamCanonicalParents(DBTraceObject child,
			Lifespan lifespan) {
		TraceObjectKeyPath path = child.getCanonicalPath();
		TraceObjectKeyPath parentPath = path.parent();
		if (parentPath == null) { // child is the root
			return Stream.of();
		}
		DBTraceObject parent = manager.getObjectByCanonicalPath(parentPath);
		if (parent == null) {
			// Not inserted yet, or someone deleted the parent object
			return Stream.of();
		}
		String entryKey = path.key();
		return streamValues(parent, entryKey, lifespan, true);
	}

	public Stream<DBTraceObjectValueBehind> streamValues(DBTraceObject parent, Lifespan lifespan) {
		synchronized (cachedValues) {
			var keys = cachedValues.get(parent);
			if (keys == null) {
				return Stream.of();
			}
			return StreamUtils.sync(cachedValues,
				keys.values().stream().flatMap(v -> streamSub(v, lifespan, true)));
		}
	}

	public Stream<DBTraceObjectValueBehind> streamValues(DBTraceObject parent, String key,
			Lifespan lifespan, boolean forward) {
		synchronized (cachedValues) {
			var keys = cachedValues.get(parent);
			if (keys == null) {
				return Stream.of();
			}
			var values = keys.get(key);
			if (values == null) {
				return Stream.of();
			}
			return StreamUtils.sync(cachedValues, streamSub(values, lifespan, forward));
		}
	}

	static boolean intersectsRange(Object value, AddressRange range) {
		return (value instanceof Address av && range.contains(av)) ||
			(value instanceof AddressRange rv && range.intersects(rv));
	}

	private Stream<DBTraceObjectValueBehind> streamValuesIntersectingLifespan(Lifespan lifespan,
			String entryKey) {
		// TODO: In-memory spatial index?
		synchronized (cachedValues) {
			var top = cachedValues.values().stream();
			var keys = entryKey == null
					? top.flatMap(v -> v.values().stream())
					: top.flatMap(v -> v.entrySet()
							.stream()
							.filter(e -> entryKey.equals(e.getKey()))
							.map(e -> e.getValue()));
			return StreamUtils.sync(cachedValues, keys.flatMap(v -> streamSub(v, lifespan, true)));
		}
	}

	public Stream<DBTraceObjectValueBehind> streamValuesIntersecting(Lifespan lifespan,
			AddressRange range, String entryKey) {
		return streamValuesIntersectingLifespan(lifespan, entryKey)
				.filter(v -> intersectsRange(v.getValue(), range));
	}

	static boolean atAddress(Object value, Address address) {
		return (value instanceof Address av && address.equals(av)) ||
			(value instanceof AddressRange rv && rv.contains(address));
	}

	public Stream<DBTraceObjectValueBehind> streamValuesAt(long snap, Address address,
			String entryKey) {
		return streamValuesIntersectingLifespan(Lifespan.at(snap), entryKey)
				.filter(v -> atAddress(v.getValue(), address));
	}

	static AddressRange getIfRangeOrAddress(Object v) {
		if (v instanceof AddressRange rv) {
			return rv;
		}
		if (v instanceof Address av) {
			return new AddressRangeImpl(av, av);
		}
		return null;
	}

	public <I extends TraceObjectInterface> AddressSetView getObjectsAddressSet(long snap,
			String key, Class<I> ifaceCls, Predicate<? super I> predicate) {
		return new AbstractAddressSetView() {
			AddressSet collectRanges() {
				AddressSet result = new AddressSet();
				try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
					synchronized (cachedValues) {
						for (DBTraceObjectValueBehind v : StreamUtils
								.iter(streamValuesIntersectingLifespan(Lifespan.at(snap), key))) {
							AddressRange range = getIfRangeOrAddress(v.getValue());
							if (range == null) {
								continue;
							}
							if (!DBTraceObjectManager.acceptValue(v.getWrapper(), key, ifaceCls,
								predicate)) {
								continue;
							}
							result.add(range);
						}
					}
				}
				return result;
			}

			@Override
			public boolean contains(Address addr) {
				try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
					synchronized (cachedValues) {
						for (DBTraceObjectValueBehind v : StreamUtils
								.iter(streamValuesIntersectingLifespan(Lifespan.at(snap), key))) {
							if (!addr.equals(v.getValue())) {
								continue;
							}
							if (!DBTraceObjectManager.acceptValue(v.getWrapper(), key, ifaceCls,
								predicate)) {
								continue;
							}
							return true;
						}
					}
				}
				return false;
			}

			@Override
			public AddressRangeIterator getAddressRanges() {
				return collectRanges().getAddressRanges();
			}

			@Override
			public AddressRangeIterator getAddressRanges(boolean forward) {
				return collectRanges().getAddressRanges(forward);
			}

			@Override
			public AddressRangeIterator getAddressRanges(Address start, boolean forward) {
				// TODO: Could cull during collection
				return collectRanges().getAddressRanges(start, forward);
			}
		};
	}

	public void flush() {
		flushing = true;
		worker.interrupt();
		try {
			busy.waitValue(false).get();
		}
		catch (InterruptedException | ExecutionException e) {
			throw new AssertionError(e);
		}
	}

	public void waitWorkers() {
		worker.interrupt();
		try {
			worker.join(10000);
		}
		catch (InterruptedException e) {
			throw new AssertionError(e);
		}
	}
}
