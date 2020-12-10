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
package ghidra.util.database;

import java.io.IOException;
import java.util.*;
import java.util.Map.Entry;

import com.google.common.collect.Range;

import db.Field;
import db.util.ErrorHandler;
import ghidra.util.database.DBCachedObjectStoreFactory.DBFieldCodec;
import ghidra.util.database.DirectedIterator.Direction;

/**
 * 
 * NOTE: This seems ripe for implementing a collection interface, but each defies implementation on
 * our DB framework.
 *
 * @param <K>
 * @param <T>
 */
public class DBCachedObjectIndex<K, T extends DBAnnotatedObject> {
	protected final DBCachedObjectStore<T> store;
	protected final ErrorHandler errHandler;
	protected final DBFieldCodec<K, T, ?> codec;
	protected final int columnIndex;

	protected final Range<Field> fieldRange;
	protected final Direction direction;

	protected DBCachedObjectIndex(DBCachedObjectStore<T> store, ErrorHandler errHandler,
			DBFieldCodec<K, T, ?> codec, int columnIndex, Range<Field> fieldRange,
			Direction direction) {
		this.store = store;
		this.errHandler = errHandler;
		this.codec = codec;
		this.columnIndex = columnIndex;
		this.fieldRange = fieldRange;
		this.direction = direction;
	}

	public DBCachedObjectStoreFoundKeysValueCollection<T> get(K key) {
		Field field = codec.encodeField(key);
		if (!fieldRange.contains(field)) {
			return null;
		}
		try {
			return store.findObjects(columnIndex, field);
		}
		catch (IOException e) {
			errHandler.dbError(e);
			return null;
		}
	}

	/**
	 * 
	 * NOTE: Not sensitive to bounds at all
	 * 
	 * @param key
	 * @return
	 */
	public Collection<T> getLazily(K key) {
		return new AbstractCollection<>() {
			@Override
			public Iterator<T> iterator() {
				return get(key).iterator();
			}

			@Override
			public int size() {
				return countKey(key);
			}

			public boolean isEmpty() {
				return !containsKey(key);
			}
		};
	}

	public T getOne(K value) {
		Field field = codec.encodeField(value);
		if (!fieldRange.contains(field)) {
			return null;
		}
		try {
			return store.findOneObject(columnIndex, field);
		}
		catch (IOException e) {
			errHandler.dbError(e);
			return null;
		}
	}

	public Iterable<K> keys() {
		return new Iterable<>() {
			@Override
			public Iterator<K> iterator() {
				try {
					Iterator<T> valueIterator = store.iterator(columnIndex, fieldRange, direction);
					return new Iterator<>() {
						@Override
						public boolean hasNext() {
							return valueIterator.hasNext();
						}

						@Override
						public K next() {
							T value = valueIterator.next();
							return codec.getValue(value);
						}
					};
				}
				catch (IOException e) {
					errHandler.dbError(e);
					return null;
				}
			}
		};
	}

	public Iterable<T> values() {
		return new Iterable<>() {
			@Override
			public Iterator<T> iterator() {
				try {
					return store.iterator(columnIndex, fieldRange, direction);
				}
				catch (IOException e) {
					errHandler.dbError(e);
					return null;
				}
			}
		};
	}

	public Iterable<Entry<K, T>> entries() {
		return new Iterable<>() {
			@Override
			public Iterator<Entry<K, T>> iterator() {
				try {
					Iterator<T> valueIterator = store.iterator(columnIndex, fieldRange, direction);
					return new Iterator<>() {
						@Override
						public boolean hasNext() {
							return valueIterator.hasNext();
						}

						@Override
						public Entry<K, T> next() {
							T value = valueIterator.next();
							return Map.entry(codec.getValue(value), value);
						}
					};
				}
				catch (IOException e) {
					errHandler.dbError(e);
					return null;
				}
			}
		};
	}

	protected static <T> T firstOf(Iterable<T> of) {
		Iterator<T> it = of.iterator();
		return it.hasNext() ? it.next() : null;
	}

	public boolean isEmpty() {
		return values().iterator().hasNext();
	}

	public boolean containsKey(K key) {
		Field field = codec.encodeField(key);
		if (!fieldRange.contains(field)) {
			return false;
		}
		try {
			return store.table.hasRecord(field, columnIndex);
		}
		catch (IOException e) {
			store.dbError(e);
			return false;
		}
	}

	public boolean containsValue(T value) {
		if (!fieldRange.contains(value.record.getFieldValue(columnIndex))) {
			return false;
		}
		return store.contains(value);
	}

	public int countKey(K key) {
		Field field = codec.encodeField(key);
		if (!fieldRange.contains(field)) {
			return 0;
		}
		try {
			return store.table.getMatchingRecordCount(field, columnIndex);
		}
		catch (IOException e) {
			store.dbError(e);
			return 0;
		}
	}

	public K firstKey() {
		return firstOf(keys());
	}

	public T firstValue() {
		return firstOf(values());
	}

	public Entry<K, T> firstEntry() {
		return firstOf(entries());
	}

	public K lastKey() {
		return firstOf(descending().keys());
	}

	public T lastValue() {
		return firstOf(descending().values());
	}

	public Entry<K, T> lastEntry() {
		return firstOf(descending().entries());
	}

	public K lowerKey(K key) {
		return firstOf(head(key, false).descending().keys());
	}

	public T lowerValue(K key) {
		return firstOf(head(key, false).descending().values());
	}

	public Entry<K, T> lowerEntry(K key) {
		return firstOf(head(key, false).descending().entries());
	}

	public K floorKey(K key) {
		return firstOf(head(key, true).descending().keys());
	}

	public T floorValue(K key) {
		return firstOf(head(key, true).descending().values());
	}

	public Entry<K, T> floorEntry(K key) {
		return firstOf(head(key, true).descending().entries());
	}

	public K ceilingKey(K key) {
		return firstOf(tail(key, true).keys());
	}

	public T ceilingValue(K key) {
		return firstOf(tail(key, true).values());
	}

	public Entry<K, T> ceilingEntry(K key) {
		return firstOf(tail(key, true).entries());
	}

	public K higherKey(K key) {
		return firstOf(tail(key, false).keys());
	}

	public T higherValue(K key) {
		return firstOf(tail(key, false).values());
	}

	public Entry<K, T> higherEntry(K key) {
		return firstOf(tail(key, false).entries());
	}

	public DBCachedObjectIndex<K, T> head(K to, boolean toInclusive) {
		Range<Field> rng =
			DBCachedObjectStore.toRangeHead(codec.encodeField(to), toInclusive, direction);
		return new DBCachedObjectIndex<>(store, errHandler, codec, columnIndex,
			fieldRange.intersection(rng), direction);
	}

	public DBCachedObjectIndex<K, T> tail(K from, boolean fromInclusive) {
		Range<Field> rng =
			DBCachedObjectStore.toRangeTail(codec.encodeField(from), fromInclusive, direction);
		return new DBCachedObjectIndex<>(store, errHandler, codec, columnIndex,
			fieldRange.intersection(rng), direction);
	}

	public DBCachedObjectIndex<K, T> sub(K from, boolean fromInclusive, K to, boolean toInclusive) {
		Range<Field> rng = DBCachedObjectStore.toRange(codec.encodeField(from), fromInclusive,
			codec.encodeField(to), toInclusive, direction);
		return new DBCachedObjectIndex<>(store, errHandler, codec, columnIndex,
			fieldRange.intersection(rng), direction);
	}

	public DBCachedObjectIndex<K, T> descending() {
		return new DBCachedObjectIndex<>(store, errHandler, codec, columnIndex, fieldRange,
			Direction.reverse(direction));
	}
}
