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
package ghidra.util.database.spatial;

import java.awt.Color;
import java.util.Collection;
import java.util.Collections;
import java.util.Map.Entry;

public interface SpatialMap<DS extends BoundedShape<?>, T, Q> {
	static class EmptySpatialMap<DS extends BoundedShape<?>, T, Q> implements SpatialMap<DS, T, Q> {
		@Override
		public T put(DS shape, T value) {
			throw new IllegalArgumentException();
		}

		@Override
		public boolean remove(DS shape, T value) {
			throw new IllegalArgumentException();
		}

		@Override
		public boolean remove(Entry<DS, T> entry) {
			throw new IllegalArgumentException();
		}

		@Override
		public int size() {
			return 0;
		}

		@Override
		public boolean isEmpty() {
			return true;
		}

		@Override
		public Collection<Entry<DS, T>> entries() {
			return Collections.emptyList();
		}

		@Override
		public Collection<Entry<DS, T>> orderedEntries() {
			return Collections.emptyList();
		}

		@Override
		public Collection<DS> keys() {
			return Collections.emptyList();
		}

		@Override
		public Collection<DS> orderedKeys() {
			return Collections.emptyList();
		}

		@Override
		public Collection<T> values() {
			return Collections.emptyList();
		}

		@Override
		public Collection<T> orderedValues() {
			return Collections.emptyList();
		}

		@Override
		public SpatialMap<DS, T, Q> reduce(Q query) {
			return this;
		}

		@Override
		public Entry<DS, T> firstEntry() {
			return null;
		}

		@Override
		public DS firstKey() {
			return null;
		}

		@Override
		public T firstValue() {
			return null;
		}

		@Override
		public void clear() {
			// Do nothing
		}
	}

	SpatialMap<?, ?, ?> EMPTY_MAP = new EmptySpatialMap<>();

	@SuppressWarnings("unchecked")
	static <DS extends BoundedShape<?>, T, Q> SpatialMap<DS, T, Q> emptyMap() {
		return (SpatialMap<DS, T, Q>) EMPTY_MAP;
	}

	/**
	 * Put an entry into the map
	 * 
	 * Note that the map may copy, and possibly modify, the given value. The value returned is the
	 * value actually stored by the map. This may be useful when the map's values are identical to
	 * its records. This allows the creation of a "blank" entry with a given shape. The entry is
	 * then populated by the user.
	 * 
	 * <pre>
	 * class MyDBDataRecord extends DBTreeDataRecord<MyShape, MyNodeShape, MyDBDataRecord> {
	 * 	&#64;Override
	 * 	protected void setValue(MyDBDataRecord value) {
	 * 		// Do nothing: value ought to be null. Map will create and return "blank" record
	 * 	}
	 * 
	 * 	protected MyDBDataRecord getValue() {
	 * 		return this; // The record is the value
	 * 	}
	 * }
	 * </pre>
	 * 
	 * <pre>
	 * MyDBDataRecord rec = map.put(MyShape.create(args), null);
	 * rec.setSomething(6);
	 * rec.setAnother("My user data");
	 * </pre>
	 * 
	 * This practice is preferred when the values are not simple, and/or when the shape is a
	 * property of the value. In other cases, e.g., when the value is an enum or a {@link Color},
	 * then {@link DBTreeDataRecord#setValue(Object)} and {@link DBTreeDataRecord#getValue()} should
	 * be implemented as field accessors.
	 * 
	 * @param shape the shape of the entry
	 * @param value the value for the entry
	 * @return the value as stored in the map
	 */
	T put(DS shape, T value);

	/**
	 * Remove an entry from the map
	 * 
	 * Removes a single matching entry, if found, from the map. If you have a reference to an entry
	 * obtained from this map, use {@link #remove(Entry)} instead. Otherwise, this is the preferred
	 * method.
	 * 
	 * @param shape the shape of the entry to remove
	 * @param value the value of the entry to remove
	 * @return true if the map was modified
	 */
	boolean remove(DS shape, T value);

	/**
	 * Remove an entry from the map
	 * 
	 * This method is preferred <em>only</em> when the given entry comes directly from this map.
	 * This spares the implementation from having to search for a matching entry. If the entry does
	 * not come from this map, it will behave like {@link #remove(BoundedShape, Object)}.
	 * 
	 * @param entry the entry to remove
	 * @return true if the map was modified
	 */
	boolean remove(Entry<DS, T> entry);

	/**
	 * Get or compute the size of this map
	 * 
	 * Note that this may not necessarily be a quick operation, esp., if this map is the result of
	 * {@link #reduce(Object)}. In the worst case, all elements in the reduced map will be visited.
	 * 
	 * @return the number of data entries in the map
	 */
	int size();

	boolean isEmpty();

	Collection<Entry<DS, T>> entries();

	Collection<Entry<DS, T>> orderedEntries();

	Collection<DS> keys();

	Collection<DS> orderedKeys();

	Collection<T> values();

	Collection<T> orderedValues();

	SpatialMap<DS, T, Q> reduce(Q query);

	Entry<DS, T> firstEntry();

	DS firstKey();

	T firstValue();

	void clear();
}
