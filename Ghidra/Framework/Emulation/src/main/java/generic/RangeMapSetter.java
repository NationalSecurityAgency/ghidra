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
package generic;

import java.util.*;
import java.util.Map.Entry;

/**
 * A method outline for setting an entry in a range map where coalescing is desired
 *
 * @param <E> the type of entries
 * @param <D> the type of range bounds
 * @param <R> the type of ranges
 * @param <V> the type of values
 */
public abstract class RangeMapSetter<E, D, R, V> {
	/**
	 * Compare two values as in {@link Comparator#compare(Object, Object)}
	 * 
	 * @param d1 the first value
	 * @param d2 the second value
	 * @return the result
	 */
	protected abstract int compare(D d1, D d2);

	/**
	 * Get the range of the given entry
	 * 
	 * @param entry the entry
	 * @return the range
	 */
	protected abstract R getRange(E entry);

	/**
	 * Get the value of the given entry
	 * 
	 * @param entry the entry
	 * @return the value
	 */
	protected abstract V getValue(E entry);

	/**
	 * Remove an entry from the map
	 * 
	 * @param entry the entry
	 */
	protected abstract void remove(E entry);

	/**
	 * Get the lower bound of the range
	 * 
	 * @param range the range
	 * @return the lower bound
	 */
	protected abstract D getLower(R range);

	/**
	 * Get the upper bound of the range
	 * 
	 * @param range the range
	 * @return the upper bound
	 */
	protected abstract D getUpper(R range);

	/**
	 * Create a closed range with the given bounds
	 * 
	 * @param lower the lower bound
	 * @param upper the upper bound
	 * @return the range
	 */
	protected abstract R toSpan(D lower, D upper);

	/**
	 * Get the number immediately preceding the given bound
	 * 
	 * @param d the bound
	 * @return the previous bound, or null if it doesn't exist
	 */
	protected abstract D getPrevious(D d);

	/**
	 * Get the number immediately following the given bound
	 * 
	 * @param d the bound
	 * @return the next bound, or null if it doesn't exist
	 */
	protected abstract D getNext(D d);

	/**
	 * Get all entries intersecting the closed range formed by the given bounds
	 * 
	 * @param lower the lower bound
	 * @param upper the upper bound
	 * @return the intersecting entries
	 */
	protected abstract Iterable<E> getIntersecting(D lower, D upper);

	/**
	 * Place an entry into the map
	 * 
	 * @param range the range of the entry
	 * @param value the value of the entry
	 * @return the new entry (or an existing entry)
	 */
	protected abstract E put(R range, V value);

	/**
	 * Get the previous bound or this same bound, if the previous doesn't exist
	 * 
	 * @param d the bound
	 * @return the previous or same bound
	 */
	protected D getPreviousOrSame(D d) {
		D prev = getPrevious(d);
		if (prev == null) {
			return d;
		}
		return prev;
	}

	/**
	 * Get the next bound or this same bound, if the next doesn't exist
	 * 
	 * @param d the bound
	 * @return the next or same bound
	 */
	protected D getNextOrSame(D d) {
		D next = getNext(d);
		if (next == null) {
			return d;
		}
		return next;
	}

	/**
	 * Check if the two ranges are connected
	 * 
	 * <p>
	 * The ranges are connected if they intersect, or if their bounds abut.
	 * 
	 * @param r1 the first range
	 * @param r2 the second range
	 * @return true if connected
	 */
	protected boolean connects(R r1, R r2) {
		return compare(getPreviousOrSame(getLower(r1)), getUpper(r2)) <= 0 ||
			compare(getPreviousOrSame(getLower(r2)), getUpper(r1)) <= 0;
	}

	/**
	 * Entry point: Set the given range to the given value, coalescing where possible
	 * 
	 * @param range the range
	 * @param value the value
	 * @return the entry containing the value
	 */
	public E set(R range, V value) {
		return set(getLower(range), getUpper(range), value);
	}

	/**
	 * Entry point: Set the given range to the given value, coalescing where possible
	 * 
	 * @param lower the lower bound
	 * @param upper the upper bound
	 * @param value the value
	 * @return the entry containing the value
	 */
	public E set(D lower, D upper, V value) {
		// Go one out to find abutting ranges, too.
		D prev = getPreviousOrSame(lower);
		D next = getNextOrSame(upper);
		Set<E> toRemove = new LinkedHashSet<>();
		Map<R, V> toPut = new HashMap<>();
		for (E entry : getIntersecting(prev, next)) {
			R r = getRange(entry);
			int cmpMin = compare(getLower(r), lower);
			int cmpMax = compare(getUpper(r), upper);
			boolean sameVal = Objects.equals(getValue(entry), value);
			if (cmpMin <= 0 && cmpMax >= 0 && sameVal) {
				return entry; // The value in this range is already set as specified
			}
			toRemove.add(entry);
			if (cmpMin < 0) {
				if (sameVal) {
					// Expand the new entry to cover the one we just removed
					lower = getLower(r);
				}
				else {
					// Create a truncated entry to replace the one we just removed
					toPut.put(toSpan(getLower(r), prev), getValue(entry));
				}
			}
			if (cmpMax > 0) {
				if (sameVal) {
					// Expand the new entry to cover the one we just removed
					upper = getUpper(r);
				}
				else {
					// Create a truncated entry to replace the one we just removed
					toPut.put(toSpan(next, getUpper(r)), getValue(entry));
				}
			}
		}
		for (E entry : toRemove) {
			remove(entry);
		}
		E result = put(toSpan(lower, upper), value);
		assert toPut.size() <= 2;
		for (Entry<R, V> ent : toPut.entrySet()) {
			put(ent.getKey(), ent.getValue());
		}
		return result;
	}
}
