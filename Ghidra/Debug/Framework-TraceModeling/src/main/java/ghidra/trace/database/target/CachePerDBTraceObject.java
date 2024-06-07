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
import java.util.Map.Entry;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import ghidra.trace.model.Lifespan;

public class CachePerDBTraceObject {

	private record SnapKey(long snap, String key) implements Comparable<SnapKey> {
		@Override
		public int compareTo(SnapKey that) {
			int c = Long.compare(this.snap, that.snap);
			if (c != 0) {
				return c;
			}
			if (this.key == that.key) {
				return 0;
			}
			if (this.key == null) {
				return 1;
			}
			if (that.key == null) {
				return -1;
			}
			return this.key.compareTo(that.key);
		}

		public static SnapKey forValue(DBTraceObjectValue value) {
			return new SnapKey(value.getMinSnap(), value.getEntryKey());
		}
	}

	public record Cached<T>(boolean isMiss, T value) {
		static final Cached<?> MISS = new Cached<>(true, null);

		@SuppressWarnings("unchecked")
		public static <T> Cached<T> miss() {
			return (Cached<T>) MISS;
		}

		static <T> Cached<T> hit(T value) {
			return new Cached<>(false, value);
		}
	}

	private static final int MAX_CACHE_KEYS = 200;
	private static final int MAX_VALUES_PER_KEY = 20;
	private static final int MAX_VALUES_ANY_KEY = 4000;
	private static final int EXPANSION = 10;

	private record CachedLifespanValues<K>(Lifespan span,
			NavigableMap<K, DBTraceObjectValue> values) {
	}

	private final Map<String, CachedLifespanValues<Long>> perKeyCache = new LinkedHashMap<>() {
		protected boolean removeEldestEntry(Map.Entry<String, CachedLifespanValues<Long>> eldest) {
			return size() > MAX_CACHE_KEYS;
		}
	};

	private CachedLifespanValues<SnapKey> anyKeyCache = null;

	private Stream<DBTraceObjectValue> doStreamAnyKey(NavigableMap<SnapKey, DBTraceObjectValue> map,
			Lifespan lifespan) {
		// TODO: Can be a HashMap, if that's faster
		return map.values().stream().filter(v -> lifespan.intersects(v.getLifespan()));
	}

	private Stream<DBTraceObjectValue> doStreamPerKey(NavigableMap<Long, DBTraceObjectValue> map,
			Lifespan lifespan, boolean forward) {
		Long min = lifespan.min();
		var floor = map.floorEntry(min);
		if (floor != null && floor.getValue().getLifespan().contains(min)) {
			min = floor.getKey();
		}
		NavigableMap<Long, DBTraceObjectValue> sub = map.subMap(min, true, lifespan.max(), true);
		if (forward) {
			return sub.values().stream();
		}
		return sub.descendingMap().values().stream();
	}

	private DBTraceObjectValue doGetValue(NavigableMap<Long, DBTraceObjectValue> map, long snap) {
		Entry<Long, DBTraceObjectValue> floor = map.floorEntry(snap);
		if (floor == null) {
			return null;
		}
		DBTraceObjectValue value = floor.getValue();
		if (!value.getLifespan().contains(snap)) {
			return null;
		}
		return value;
	}

	public Cached<Stream<DBTraceObjectValue>> streamValues(Lifespan lifespan) {
		if (anyKeyCache == null) {
			return Cached.miss();
		}
		if (!anyKeyCache.span.encloses(lifespan)) {
			return Cached.miss();
		}
		return Cached.hit(doStreamAnyKey(anyKeyCache.values, lifespan));
	}

	public Cached<Stream<DBTraceObjectValue>> streamValues(Lifespan lifespan, String key,
			boolean forward) {
		CachedLifespanValues<Long> cached = perKeyCache.get(key);
		if (cached == null) {
			return Cached.miss();
		}
		if (!cached.span.encloses(lifespan)) {
			return Cached.miss();
		}
		return Cached.hit(doStreamPerKey(cached.values, lifespan, forward));
	}

	public Cached<DBTraceObjectValue> getValue(long snap, String key) {
		CachedLifespanValues<Long> cached = perKeyCache.get(key);
		if (cached == null) {
			return Cached.miss();
		}
		if (!cached.span.contains(snap)) {
			return Cached.miss();
		}
		return Cached.hit(doGetValue(cached.values, snap));
	}

	public Lifespan expandLifespan(Lifespan lifespan) {
		// Expand the query to take advantage of spatial locality (in the time dimension)
		long min = lifespan.lmin() - EXPANSION;
		if (min > lifespan.lmin()) {
			min = Lifespan.ALL.lmin();
		}
		long max = lifespan.lmax() + EXPANSION;
		if (max < lifespan.lmax()) {
			max = Lifespan.ALL.lmax();
		}
		return Lifespan.span(min, max);
	}

	private DBTraceObjectValue mergeValues(DBTraceObjectValue v1, DBTraceObjectValue v2) {
		throw new IllegalStateException("Conflicting values: %s, %s".formatted(v1, v2));
	}

	private NavigableMap<SnapKey, DBTraceObjectValue> collectAnyKey(
			Stream<DBTraceObjectValue> values) {
		return values.collect(
			Collectors.toMap(SnapKey::forValue, v -> v, this::mergeValues, TreeMap::new));
	}

	private NavigableMap<Long, DBTraceObjectValue> collectPerKey(
			Stream<DBTraceObjectValue> values) {
		return values.collect(
			Collectors.toMap(v -> v.getLifespan().min(), v -> v, this::mergeValues, TreeMap::new));
	}

	public Stream<DBTraceObjectValue> offerStreamAnyKey(Lifespan expanded,
			Stream<DBTraceObjectValue> values, Lifespan lifespan) {
		NavigableMap<SnapKey, DBTraceObjectValue> map = collectAnyKey(values);
		anyKeyCache = new CachedLifespanValues<>(expanded, map);
		return doStreamAnyKey(map, lifespan);
	}

	public Stream<DBTraceObjectValue> offerStreamPerKey(Lifespan expanded,
			Stream<DBTraceObjectValue> values, Lifespan lifespan, String key, boolean forward) {
		NavigableMap<Long, DBTraceObjectValue> map = collectPerKey(values);
		perKeyCache.put(key, new CachedLifespanValues<>(expanded, map));
		return doStreamPerKey(map, lifespan, forward);
	}

	public DBTraceObjectValue offerGetValue(Lifespan expanded, Stream<DBTraceObjectValue> values,
			long snap, String key) {
		NavigableMap<Long, DBTraceObjectValue> map = collectPerKey(values);
		perKeyCache.put(key, new CachedLifespanValues<>(expanded, map));
		return doGetValue(map, snap);
	}

	public void notifyValueCreated(DBTraceObjectValue value) {
		Objects.requireNonNull(value);
		if (anyKeyCache != null && anyKeyCache.span.intersects(value.getLifespan())) {
			anyKeyCache.values.put(SnapKey.forValue(value), value);
		}
		CachedLifespanValues<Long> cached = perKeyCache.get(value.getEntryKey());
		if (cached != null && cached.span.intersects(value.getLifespan())) {
			cached.values.put(value.getLifespan().min(), value);
		}
	}

	public void notifyValueDeleted(DBTraceObjectValue value) {
		Objects.requireNonNull(value);
		if (anyKeyCache != null) {
			anyKeyCache.values.remove(SnapKey.forValue(value));
		}
		CachedLifespanValues<Long> cached = perKeyCache.get(value.getEntryKey());
		if (cached != null) {
			cached.values.remove(value.getLifespan().min());
		}
	}
}
