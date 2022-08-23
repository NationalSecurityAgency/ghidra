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
 * An index on a field in a {@link DBCachedObjectStore}
 * 
 * <p>
 * This provides access to a table index backing the store, allowing clients to retrieve objects
 * having specified field values. Its methods are inspired by {@link NavigableMap}; however, its
 * semantics permit duplicate keys, so this cannot implement it in the manner desired.
 * 
 * @implNote This seems rife for implementing a collection interface, but each defies implementation
 *           on our DB framework. Probably because it's better understood as a multimap, which is
 *           not a standard Java collection. Guava's proved too burdensome to implement. We never
 *           tried Apache's.
 *
 * @param <K> the type of keys in the index, i.e., the indexed field's type
 * @param <T> the type of objects in the store
 */
public class DBCachedObjectIndex<K, T extends DBAnnotatedObject> {
	protected final DBCachedObjectStore<T> store;
	protected final ErrorHandler errHandler;
	protected final DBFieldCodec<K, T, ?> codec;
	protected final int columnIndex;

	protected final Range<Field> fieldRange;
	protected final Direction direction;

	/**
	 * Construct an index
	 * 
	 * <p>
	 * Clients should use {@link DBCachedObjectStore#getIndex(Class, DBObjectColumn)}.
	 * 
	 * @param store the store containing the indexed objects
	 * @param errHandler an error handler
	 * @param codec the codec for the indexed field/column
	 * @param columnIndex the column number
	 * @param fieldRange required: the restricted range, can be {@link Range#all()}
	 * @param direction the sort order / direction of iteration
	 */
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

	protected Collection<T> get(Field encoded) {
		try {
			return store.findObjects(columnIndex, encoded);
		}
		catch (IOException e) {
			errHandler.dbError(e);
			return List.of();
		}
	}

	/**
	 * Get the objects having the given value in the indexed field
	 * 
	 * <p>
	 * <b>NOTE:</b> The objects' primary keys are retrieved immediately, but the returned collection
	 * loads each requested object lazily. This may have timing implications. If the returned
	 * collection is used at a later time, the keys found may no longer be valid, and even if they
	 * are, the indexed field may no longer have the requested value when retrieved. See
	 * {@link #getLazily(Object)}.
	 * 
	 * @param key the value
	 * @return the collection of objects
	 */
	public Collection<T> get(K key) {
		Field encoded = codec.encodeField(key);
		if (!fieldRange.contains(encoded)) {
			return List.of();
		}
		return get(encoded);
	}

	/**
	 * Get the objects having the given value in the index field
	 * 
	 * <p>
	 * This differs from {@link #get(Object)} in that the keys are retrieved each time the
	 * collection is iterated. The returned collection can be saved and used later. The iterator
	 * itself still has a fixed set of keys, though, so clients should use it and discard it in a
	 * timely fashion, and/or while holding the domain object's lock.
	 * 
	 * @param key the value
	 * @return the lazy collection of objects
	 */
	public Collection<T> getLazily(K key) {
		Field encoded = codec.encodeField(key);
		if (!fieldRange.contains(encoded)) {
			return List.of();
		}
		return new AbstractCollection<>() {
			@Override
			public Iterator<T> iterator() {
				return get(encoded).iterator();
			}

			@Override
			public int size() {
				return countKey(encoded);
			}

			public boolean isEmpty() {
				return !containsKey(encoded);
			}
		};
	}

	/**
	 * Get a unique object having the given value in the index field
	 * 
	 * <p>
	 * Clients should use this method when the index behaves like a map, rather than a multimap. It
	 * is the client's responsibility to ensure that duplicate values do not exist in the indexed
	 * column.
	 * 
	 * @param value the value
	 * @return the object, if found, or null
	 * @throws IllegalStateException if the object is not unique
	 */
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

	/**
	 * Iterate over the values of the indexed column, in order
	 * 
	 * <p>
	 * Despite being called keys, the values may not be unique
	 * 
	 * @return the iterator
	 */
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

	/**
	 * Iterate over the objects as ordered by the index
	 * 
	 * @return the iterator
	 */
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

	/**
	 * Iterate over the entries as ordered by the index
	 * 
	 * <p>
	 * Each entry is a key-value value where the "key" is the value of the indexed field, and the
	 * "value" is the object.
	 * 
	 * @return the iterator
	 */
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

	/**
	 * Check if this index is empty
	 * 
	 * <p>
	 * Except for sub-ranged indexes, this is equivalent to checking if the object store is empty.
	 * For sub-ranged indexes, this checks if the store contains any object whose value for the
	 * indexed field falls within the restricted range.
	 * 
	 * @return true if empty
	 */
	public boolean isEmpty() {
		return values().iterator().hasNext();
	}

	protected boolean containsKey(Field encoded) {
		try {
			return store.table.hasRecord(encoded, columnIndex);
		}
		catch (IOException e) {
			store.dbError(e);
			return false;
		}
	}

	/**
	 * Check if there is any object having the given value for its indexed field
	 * 
	 * <p>
	 * This method is more efficient than using {@code get(key).isEmpty()}, since it need only find
	 * one match, whereas {@link #get(Object)} will retrieve every match. Granted, it doesn't make
	 * sense to immediately call {@link #get(Object)} after {@link #containsKey(Object)} returns
	 * true.
	 */
	public boolean containsKey(K key) {
		Field encoded = codec.encodeField(key);
		if (!fieldRange.contains(encoded)) {
			return false;
		}
		return containsKey(encoded);
	}

	/**
	 * Check if the given object is in the index
	 * 
	 * <p>
	 * Except for sub-ranged indexes, this is equivalent to checking if the object is in the store.
	 * For a sub-ranged index, the value of its indexed field must fall within the restricted range.
	 * 
	 * @param value the object
	 * @return true if it appears in this (sub-ranged) index.
	 */
	public boolean containsValue(T value) {
		if (!fieldRange.contains(value.record.getFieldValue(columnIndex))) {
			return false;
		}
		return store.contains(value);
	}

	protected int countKey(Field encoded) {
		try {
			return store.table.getMatchingRecordCount(encoded, columnIndex);
		}
		catch (IOException e) {
			store.dbError(e);
			return 0;
		}
	}

	/**
	 * Count the number of objects whose indexed field has the given value
	 * 
	 * @param key the value
	 * @return the count
	 */
	public int countKey(K key) {
		Field encoded = codec.encodeField(key);
		if (!fieldRange.contains(encoded)) {
			return 0;
		}
		return countKey(encoded);
	}

	/**
	 * Get the first key in the index
	 * 
	 * @see #descending()
	 * @see #sub(Object, boolean, Object, boolean)
	 * @return the first key, or null
	 */
	public K firstKey() {
		return firstOf(keys());
	}

	/**
	 * Get the first object in the index
	 * 
	 * @see #descending()
	 * @see #sub(Object, boolean, Object, boolean)
	 * @return the first object, or null
	 */
	public T firstValue() {
		return firstOf(values());
	}

	/**
	 * Get the first entry in the index
	 * 
	 * @see #descending()
	 * @see #sub(Object, boolean, Object, boolean)
	 * @return the first key, or null
	 */
	public Entry<K, T> firstEntry() {
		return firstOf(entries());
	}

	/**
	 * Get the last key in the index
	 * 
	 * @see #descending()
	 * @see #sub(Object, boolean, Object, boolean)
	 * @return the first key, or null
	 */
	public K lastKey() {
		return firstOf(descending().keys());
	}

	/**
	 * Get the last object in the index
	 * 
	 * @see #descending()
	 * @see #sub(Object, boolean, Object, boolean)
	 * @return the first object, or null
	 */
	public T lastValue() {
		return firstOf(descending().values());
	}

	/**
	 * Get the last entry in the index
	 * 
	 * @see #descending()
	 * @see #sub(Object, boolean, Object, boolean)
	 * @return the first key, or null
	 */
	public Entry<K, T> lastEntry() {
		return firstOf(descending().entries());
	}

	/**
	 * Get the key before the given key
	 * 
	 * @param key the key
	 * @see #descending()
	 * @see #sub(Object, boolean, Object, boolean)
	 * @return the previous key, or null
	 */
	public K lowerKey(K key) {
		return firstOf(head(key, false).descending().keys());
	}

	/**
	 * Get the value before the given key
	 * 
	 * @param key the key
	 * @see #descending()
	 * @see #sub(Object, boolean, Object, boolean)
	 * @return the the value of the previous key, or null
	 */
	public T lowerValue(K key) {
		return firstOf(head(key, false).descending().values());
	}

	/**
	 * Get the entry before the given key
	 * 
	 * @param key the key
	 * @see #descending()
	 * @see #sub(Object, boolean, Object, boolean)
	 * @return the entry of the previous key, or null
	 */
	public Entry<K, T> lowerEntry(K key) {
		return firstOf(head(key, false).descending().entries());
	}

	/**
	 * Get the key at or before the given key
	 * 
	 * @param key the key
	 * @see #descending()
	 * @see #sub(Object, boolean, Object, boolean)
	 * @return the same or previous key, or null
	 */
	public K floorKey(K key) {
		return firstOf(head(key, true).descending().keys());
	}

	/**
	 * Get the value at or before the given key
	 * 
	 * @param key the key
	 * @see #descending()
	 * @see #sub(Object, boolean, Object, boolean)
	 * @return the value of the same or previous key, or null
	 */
	public T floorValue(K key) {
		return firstOf(head(key, true).descending().values());
	}

	/**
	 * Get the entry at or before the given key
	 * 
	 * @param key the key
	 * @see #descending()
	 * @see #sub(Object, boolean, Object, boolean)
	 * @return the entry of the same or previous key, or null
	 */
	public Entry<K, T> floorEntry(K key) {
		return firstOf(head(key, true).descending().entries());
	}

	/**
	 * Get the key at or after the given key
	 * 
	 * @param key the key
	 * @see #descending()
	 * @see #sub(Object, boolean, Object, boolean)
	 * @return the same or next key, or null
	 */
	public K ceilingKey(K key) {
		return firstOf(tail(key, true).keys());
	}

	/**
	 * Get the value at or after the given key
	 * 
	 * @param key the key
	 * @see #descending()
	 * @see #sub(Object, boolean, Object, boolean)
	 * @return the value of the same or next key, or null
	 */
	public T ceilingValue(K key) {
		return firstOf(tail(key, true).values());
	}

	/**
	 * Get the entry at or after the given key
	 * 
	 * @param key the key
	 * @see #descending()
	 * @see #sub(Object, boolean, Object, boolean)
	 * @return the entry of the same or next key, or null
	 */
	public Entry<K, T> ceilingEntry(K key) {
		return firstOf(tail(key, true).entries());
	}

	/**
	 * Get the key after the given key
	 * 
	 * @param key the key
	 * @see #descending()
	 * @see #sub(Object, boolean, Object, boolean)
	 * @return the same or next key, or null
	 */
	public K higherKey(K key) {
		return firstOf(tail(key, false).keys());
	}

	/**
	 * Get the value after the given key
	 * 
	 * @param key the key
	 * @see #descending()
	 * @see #sub(Object, boolean, Object, boolean)
	 * @return the value of the next key, or null
	 */
	public T higherValue(K key) {
		return firstOf(tail(key, false).values());
	}

	/**
	 * Get the entry after the given key
	 * 
	 * @param key the key
	 * @see #descending()
	 * @see #sub(Object, boolean, Object, boolean)
	 * @return the entry of the next key, or null
	 */
	public Entry<K, T> higherEntry(K key) {
		return firstOf(tail(key, false).entries());
	}

	/**
	 * Get a sub-ranged view of this index, limited to entries whose keys occur before the given key
	 * 
	 * @param to the upper bound
	 * @param toInclusive whether the upper bound is included in the restricted view
	 * @see #descending()
	 * @see #sub(Object, boolean, Object, boolean)
	 * @return the restricted view
	 */
	public DBCachedObjectIndex<K, T> head(K to, boolean toInclusive) {
		Range<Field> rng =
			DBCachedObjectStore.toRangeHead(codec.encodeField(to), toInclusive, direction);
		return new DBCachedObjectIndex<>(store, errHandler, codec, columnIndex,
			fieldRange.intersection(rng), direction);
	}

	/**
	 * Get a sub-ranged view of this index, limited to entries whose keys occur after the given key
	 * 
	 * @param from the lower bound
	 * @param fromInclusive whether the lower bound is included in the restricted view
	 * @see #descending()
	 * @see #sub(Object, boolean, Object, boolean)
	 * @return the restricted view
	 */
	public DBCachedObjectIndex<K, T> tail(K from, boolean fromInclusive) {
		Range<Field> rng =
			DBCachedObjectStore.toRangeTail(codec.encodeField(from), fromInclusive, direction);
		return new DBCachedObjectIndex<>(store, errHandler, codec, columnIndex,
			fieldRange.intersection(rng), direction);
	}

	/**
	 * Get a sub-ranged view of this index
	 * 
	 * @param from the lower bound
	 * @param fromInclusive whether the lower bound is included in the restricted view
	 * @param to the upper bound
	 * @param toInclusive whether the upper bound is included in the restricted view
	 * @see #descending()
	 * @return the restricted view
	 */
	public DBCachedObjectIndex<K, T> sub(K from, boolean fromInclusive, K to, boolean toInclusive) {
		Range<Field> rng = DBCachedObjectStore.toRange(codec.encodeField(from), fromInclusive,
			codec.encodeField(to), toInclusive, direction);
		return new DBCachedObjectIndex<>(store, errHandler, codec, columnIndex,
			fieldRange.intersection(rng), direction);
	}

	/**
	 * Get a reversed view of this index
	 * 
	 * <p>
	 * This affects iteration as well as all the navigation and sub-ranging methods. E.g.,
	 * {@link #lowerKey(Object)} in the reversed view will behave like {@link #higherKey(Object)} in
	 * the original. In other words, the returned index is equivalent to the original, but with a
	 * negated comparator. Calling {@link #descending()} on the returned view will return a view
	 * equivalent to the original.
	 * 
	 * @return the reversed view
	 */
	public DBCachedObjectIndex<K, T> descending() {
		return new DBCachedObjectIndex<>(store, errHandler, codec, columnIndex, fieldRange,
			Direction.reverse(direction));
	}
}
