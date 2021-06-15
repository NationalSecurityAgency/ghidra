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
package ghidra.trace.util;

import java.util.*;
import java.util.function.Function;

import com.google.common.collect.Range;

import ghidra.program.model.address.*;

/**
 * A convenience for tracking the time structure of a trace and querying the trace accordingly.
 */
public interface TraceTimeViewport {

	public interface Occlusion<T> {
		boolean occluded(T object, AddressRange range, Range<Long> span);

		void remove(T object, AddressSet remains, Range<Long> span);
	}

	public interface QueryOcclusion<T> extends Occlusion<T> {
		@Override
		default boolean occluded(T object, AddressRange range, Range<Long> span) {
			for (T found : query(range, span)) {
				if (found == object) {
					continue;
				}
				if (itemOccludes(range, found)) {
					return true;
				}
			}
			return false;
		}

		@Override
		default void remove(T object, AddressSet remains, Range<Long> span) {
			// TODO: Split query by parts of remains? Probably not worth it.
			for (T found : query(
				new AddressRangeImpl(remains.getMinAddress(), remains.getMaxAddress()), span)) {
				if (found == object) {
					continue;
				}
				removeItem(remains, found);
				if (remains.isEmpty()) {
					return;
				}
			}
		}

		Iterable<? extends T> query(AddressRange range, Range<Long> span);

		boolean itemOccludes(AddressRange range, T t);

		void removeItem(AddressSet remains, T t);
	}

	public interface RangeQueryOcclusion<T> extends QueryOcclusion<T> {
		@Override
		default boolean itemOccludes(AddressRange range, T t) {
			return range(t).intersects(range);
		}

		@Override
		default void removeItem(AddressSet remains, T t) {
			remains.delete(range(t));
		}

		AddressRange range(T t);
	}

	public interface SetQueryOcclusion<T> extends QueryOcclusion<T> {
		@Override
		default boolean itemOccludes(AddressRange range, T t) {
			return set(t).intersects(range.getMinAddress(), range.getMaxAddress());
		}

		@Override
		default void removeItem(AddressSet remains, T t) {
			for (AddressRange range : set(t)) {
				remains.delete(range);
				if (remains.isEmpty()) {
					return;
				}
			}
		}

		AddressSetView set(T t);
	}

	void addChangeListener(Runnable l);

	void removeChangeListener(Runnable l);

	/**
	 * Check if this view is forked
	 * 
	 * <p>
	 * The view is considered forked if any snap previous to this has a schedule with an initial
	 * snap other than the immediately-preceding one. Such forks "break" the linearity of the
	 * trace's usual time line.
	 * 
	 * @return true if forked, false otherwise
	 */
	boolean isForked();

	/**
	 * Check if the given lifespan contains any upper snap among the involved spans
	 * 
	 * @param lifespan the lifespan to consider
	 * @return true if it contains any upper snap, false otherwise.
	 */
	boolean containsAnyUpper(Range<Long> lifespan);

	/**
	 * Check if any part of the given object is occluded by more-recent objects
	 * 
	 * @param <T> the type of the object
	 * @param range the address range of the object
	 * @param lifespan the lifespan of the object
	 * @param object optionally, the object to examine. Used to avoid "self occlusion"
	 * @param occlusion a mechanism for querying other like objects and checking for occlusion
	 * @return true if completely visible, false if even partially occluded
	 */
	<T> boolean isCompletelyVisible(AddressRange range, Range<Long> lifespan, T object,
			Occlusion<T> occlusion);

	/**
	 * Compute the parts of a given object that are visible past more-recent objects
	 * 
	 * @param <T> the type of the object
	 * @param set the addresses comprising the object
	 * @param lifespan the lifespan of the object
	 * @param object the object to examine
	 * @param occlusion a mechanism for query other like objects and removing occluded parts
	 * @return the set of visible addresses
	 */
	<T> AddressSet computeVisibleParts(AddressSetView set, Range<Long> lifespan, T object,
			Occlusion<T> occlusion);

	/**
	 * Get the snaps involved in the view in most-recent-first order
	 * 
	 * <p>
	 * The first is always this view's snap. Following are the source snaps of each previous
	 * snapshot's schedule where applicable.
	 * 
	 * @return the list of snaps
	 */
	List<Long> getOrderedSnaps();

	/**
	 * Get the snaps involved in the view in least-recent-first order
	 * 
	 * @return the list of snaps
	 */
	List<Long> getReversedSnaps();

	/**
	 * Get the first non-null result of the function, applied to the most-recent snaps first
	 * 
	 * <p>
	 * Typically, func both retrieves an object and tests for its suitability.
	 * 
	 * @param <T> the type of object to retrieve
	 * @param func the function on a snap to retrieve an object
	 * @return the first non-null result
	 */
	<T> T getTop(Function<Long, T> func);

	/**
	 * Merge iterators from each involved snap into a single iterator
	 * 
	 * <p>
	 * Typically, the resulting iterator is passed through a filter to test each objects
	 * suitability.
	 * 
	 * @param <T> the type of objects in each iterator
	 * @param iterFunc a function on a snap to retrieve each iterator
	 * @param comparator the comparator for merging, which must yield the same order as each
	 *            iterator
	 * @return the merged iterator
	 */
	<T> Iterator<T> mergedIterator(Function<Long, Iterator<T>> iterFunc,
			Comparator<? super T> comparator);

	/**
	 * Union address sets from each involved snap
	 * 
	 * <p>
	 * The returned union is computed lazily.
	 * 
	 * @param setFunc a function on a snap to retrieve the address set
	 * @return the union
	 */
	AddressSetView unionedAddresses(Function<Long, AddressSetView> setFunc);
}
