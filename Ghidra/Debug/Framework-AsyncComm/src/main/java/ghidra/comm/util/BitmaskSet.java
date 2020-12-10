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
package ghidra.comm.util;

import java.util.*;

import org.apache.commons.collections4.IteratorUtils;

/**
 * A set of enumeration constants encoded using bits
 * 
 * All constants in the set must belong to the same enumeration called the "universe." The
 * enumeration must implement {@link BitmaskUniverse}, so that each constant provides its mask bit.
 * This is essentially a "set" abstraction on the idiom of using "flag" bits to represent the
 * present or absence of each element.
 * 
 * It is highly recommended that each constant's mask have a population of one bit. At the very
 * least, each should have one unique bit. Constants which represent combinations of other flags are
 * allowed, but they should be documented. Defining such combinations may produce surprising
 * behavior from the perspective of the {@link Set} interface. For instance, consider constants
 * {@code VAL_A}, {@code VAL_B}, and {@code VALS_A_B}. Adding {@code VAL_A} will cause no surprise,
 * but subsequently adding {@code VAL_B} will cause {@code VALS_A_B} to materialize, even though it
 * was never added explicitly. So long as the calling methods do not expect strict set behavior,
 * this is OK. If there exists a constant which defines zero flags, then the behavior is undefined.
 * In general, the element will always be present, even though {@link #isEmpty()} may return
 * {@code true}.
 *
 * @param <E> the type of enumeration constant elements
 */
public class BitmaskSet<E extends Enum<E> & BitmaskUniverse> implements Set<E> {

	/**
	 * Obtain a set of the given constants
	 * 
	 * @param elements the constants, all from the same enumeration
	 * @return the set
	 */
	@SafeVarargs
	public static <E extends Enum<E> & BitmaskUniverse> BitmaskSet<E> of(E... elements) {
		long bitmask = 0;
		for (E elem : elements) {
			bitmask |= elem.getMask();
		}
		@SuppressWarnings("unchecked")
		Class<E> universe = (Class<E>) elements.getClass().getComponentType();
		return new BitmaskSet<>(universe, bitmask);
	}

	private final Class<E> universe;
	private long bitmask;

	/**
	 * Decode a set of constants from the given universe using the given bitmask
	 * 
	 * @param universe the enumeration of constants the set may contain
	 * @param bitmask the bitmask to decode
	 */
	public BitmaskSet(Class<E> universe, long bitmask) {
		this.universe = universe;
		this.bitmask = bitmask;
	}

	/**
	 * Copy the given collection as a bitmask of constants
	 * 
	 * @param universe the enumeration of constants the set may contain
	 * @param collection the collection to copy
	 */
	public BitmaskSet(Class<E> universe, Collection<E> collection) {
		this.universe = universe;

		// Use bitmasking shortcut, if possible
		BitmaskSet<E> that = castSameType(collection);
		if (that != null) {
			this.bitmask = that.bitmask;
			return;
		}

		// Otherwise, do it the long way...
		if (collection.isEmpty()) {
			return;
		}
		for (E elem : collection) {
			bitmask |= elem.getMask();
		}
	}

	/**
	 * Copy the given bitmask set
	 * 
	 * @param that the other set
	 */
	public BitmaskSet(BitmaskSet<E> that) {
		this.universe = that.universe;
		this.bitmask = that.bitmask;
	}

	/**
	 * Create an empty set
	 * 
	 * @param universe the enumeration of constants the set may contain
	 */
	public BitmaskSet(Class<E> universe) {
		this.universe = universe;
	}

	/**
	 * Check if a constant is in the set
	 * 
	 * @param elem the constant
	 * @return {@code true} if it is present, {@code false} otherwise
	 */
	protected boolean containsImpl(E elem) {
		long mask = elem.getMask();
		return (mask & bitmask) == mask;
	}

	/**
	 * Remove a constant from the set
	 * 
	 * @param elem the constant to remove
	 * @return {@code true} if it was present and removed, {@code false} if already not present
	 */
	protected boolean removeImpl(E elem) {
		long old = bitmask;
		bitmask &= ~elem.getMask();
		return old != bitmask;
	}

	/**
	 * Attempt to cast the given collection as a bitmask of the same type of elements as this
	 * 
	 * @param c the collection to cast
	 * @return the same collection, or {@code null} if the collection or element types differ
	 */
	protected BitmaskSet<E> castSameType(Collection<?> c) {
		if (!(c instanceof BitmaskSet)) {
			return null;
		}
		BitmaskSet<?> bm = (BitmaskSet<?>) c;
		if (this.universe != bm.universe) {
			return null;
		}
		@SuppressWarnings("unchecked")
		BitmaskSet<E> bme = (BitmaskSet<E>) bm;
		return bme;
	}

	@Override
	public int size() {
		int count = 0;
		for (E elem : universe.getEnumConstants()) {
			if (containsImpl(elem)) {
				count++;
			}
		}
		return count;
	}

	@Override
	public boolean isEmpty() {
		return bitmask == 0;
	}

	@Override
	public boolean contains(Object o) {
		if (universe != o.getClass()) {
			return false;
		}
		@SuppressWarnings("unchecked")
		E elem = (E) o;
		return containsImpl(elem);
	}

	@Override
	public Iterator<E> iterator() {
		List<E> all = Arrays.asList(universe.getEnumConstants());
		return IteratorUtils.filteredIterator(all.iterator(), this::containsImpl);
	}

	@Override
	public Object[] toArray() {
		return toArray(new Object[] {});
	}

	@Override
	public <T> T[] toArray(T[] a) {
		List<Object> arr = new ArrayList<>();
		for (E elem : universe.getEnumConstants()) {
			if (containsImpl(elem)) {
				arr.add(elem);
			}
		}
		return arr.toArray(a);
	}

	@Override
	public boolean add(E elem) {
		long old = bitmask;
		bitmask |= elem.getMask();
		return old != bitmask;
	}

	@Override
	public boolean remove(Object o) {
		if (universe != o.getClass()) {
			return false;
		}
		@SuppressWarnings("unchecked")
		E elem = (E) o;
		return removeImpl(elem);
	}

	@Override
	public boolean containsAll(Collection<?> c) {
		if (c.isEmpty()) {
			return true;
		}

		// Use bitmasking shortcut, if possible
		BitmaskSet<E> that = castSameType(c);
		if (that != null) {
			return (this.bitmask | that.bitmask) == this.bitmask;
		}

		// Otherwise, do it the long way...
		for (Object o : c) {
			if (!contains(o)) {
				return false;
			}
		}
		return true;
	}

	public boolean containsAny(Collection<?> c) {
		if (c.isEmpty()) {
			return false;
		}

		// Use bitmasking shortcut, if possible
		BitmaskSet<E> that = castSameType(c);
		if (that != null) {
			return (this.bitmask & that.bitmask) != 0;
		}

		// Otherwise, do it the long way...
		for (Object o : c) {
			if (contains(o)) {
				return true;
			}
		}
		return false;
	}

	@Override
	public boolean addAll(Collection<? extends E> c) {
		long old = this.bitmask;

		// Use bitmasking shortcut, if possible
		BitmaskSet<E> that = castSameType(c);
		if (that != null) {
			this.bitmask |= that.bitmask;
			return old != this.bitmask;
		}

		if (c.isEmpty()) {
			return false;
		}

		// Otherwise, do it the long way...
		for (E elem : c) {
			this.bitmask |= elem.getMask();
		}
		return old != this.bitmask;
	}

	@Override
	public boolean retainAll(Collection<?> c) {
		long old = this.bitmask;
		if (c.isEmpty()) {
			this.bitmask = 0;
			return old != this.bitmask;
		}

		// Use bitmasking shortcut, if possible
		BitmaskSet<E> that = castSameType(c);
		if (that != null) {
			this.bitmask &= that.bitmask;
			return old != this.bitmask;
		}

		// Otherwise, do it the long way... Build the bitmask manually
		long toKeep = 0;
		for (Object o : c) {
			if (universe == o.getClass()) {
				@SuppressWarnings("unchecked")
				E elem = (E) o;
				toKeep |= elem.getMask();
			}
		}
		this.bitmask &= toKeep;
		return old != this.bitmask;
	}

	@Override
	public boolean removeAll(Collection<?> c) {
		if (c.isEmpty()) {
			return false;
		}
		long old = this.bitmask;

		// Use bitmasking shortcut, if possible
		BitmaskSet<E> that = castSameType(c);
		if (that != null) {
			this.bitmask &= ~that.bitmask;
			return old != this.bitmask;
		}

		// Otherwise, do it the long way... Build the bitmask manually
		long toRemove = 0;
		for (Object o : c) {
			if (universe == o.getClass()) {
				@SuppressWarnings("unchecked")
				E elem = (E) o;
				toRemove |= elem.getMask();
			}
		}
		this.bitmask &= ~toRemove;
		return old != this.bitmask;
	}

	@Override
	public void clear() {
		this.bitmask = 0;
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof Collection)) {
			return false;
		}
		Collection<?> col = (Collection<?>) obj;

		// Use bitmasking shortcut, if possible
		BitmaskSet<E> that = castSameType(col);
		if (that != null) {
			return this.bitmask == that.bitmask;
		}

		// Otherwise, do it the long way...
		return this.containsAll(col) && col.containsAll(this);
	}

	@Override
	public int hashCode() {
		return Long.hashCode(bitmask);
	}

	/**
	 * Obtain the encoded bitmask
	 * 
	 * @return the bitmask
	 */
	public long getBitmask() {
		return bitmask;
	}

	/**
	 * Decode the given bitmask, overwriting the value of this set
	 * 
	 * @param bitmask the bitmask to decode
	 */
	public void setBitmask(long bitmask) {
		this.bitmask = bitmask;
	}

	/**
	 * Get this set's universe
	 * 
	 * @return the enumeration representing the universe
	 */
	public Class<E> getUniverse() {
		return universe;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder("[");
		boolean first = true;
		for (E elem : this) {
			if (first) {
				first = false;
			}
			else {
				sb.append(", ");
			}
			sb.append(elem);
		}
		sb.append(']');
		return sb.toString();
	}
}
