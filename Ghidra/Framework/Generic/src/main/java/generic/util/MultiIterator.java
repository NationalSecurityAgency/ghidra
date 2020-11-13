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
package generic.util;

import java.util.*;

import ghidra.util.exception.AssertException;

/**
 * An iterator that is comprised of one or more {@link PeekableIterator}s.  The type <code>T</code> of the 
 * the iterators must either implement {@link Comparable} directly or you must provide a 
 * {@link Comparator} for comparing the types.  Further, it is assumed that the iterators return
 * values in sorted order.  If the sorted order is reversed, then that must be indicated in 
 * the constructor of this class.
 * <p>
 * This class allows duplicate items in the iterators.  Thus, if you do not wish to process 
 * duplicate values, then you need to de-dup the data returned from {@link #next()}.  
 * Alternatively, you could subclass this iterator and de-dup the returned values.
 * <p>
 * This class also does not handle null items returned during the iteration process.
 *
 * @param <T> the type of this iterator
 */
public class MultiIterator<T> implements Iterator<T> {

	protected List<PeekableIterator<T>> iterators;
	private Comparator<T> comparator;

	/**
	 * Use this constructor when the items of the iterators are naturally comparable (i.e., 
	 * they implement {@link Comparable}).
	 * 
	 * @param iterators the iterators that provide the data
	 * @param forward true if the iterators provide data sorted ascending; false for descending
	 */
	public MultiIterator(List<PeekableIterator<T>> iterators, boolean forward) {
		this(iterators, new TComparator<T>(), forward);
	}

	/**
	 * Use this constructor when the items of the iterators are not naturally comparable (i.e., 
	 * they do not implement {@link Comparable}).
	 * 
	 * @param iterators the iterators that provide the data
	 * @param comparator the comparator used to find the next item
	 * @param forward true if the iterators provide data sorted ascending; false for descending
	 */
	public MultiIterator(List<PeekableIterator<T>> iterators, Comparator<T> comparator,
			boolean forward) {
		this.iterators = iterators;
		this.comparator = forward ? comparator : new ReverseComparatorWrapper<>(comparator);
	}

	@Override
	public void remove() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean hasNext() {
		for (PeekableIterator<T> iterator : iterators) {
			if (iterator.hasNext()) {
				return true;
			}
		}
		return false;
	}

	@Override
	public T next() {

		// find the best result
		T lowest = null;
		for (PeekableIterator<T> iterator : iterators) {
			if (!iterator.hasNext()) {
				continue;
			}

			T t = iterator.peek();
			if (lowest == null) {
				lowest = t;
				continue;
			}

			int result = comparator.compare(lowest, t);
			if (result > 0) {
				lowest = t;
			}
		}

		if (lowest == null) {
			throw new AssertException(
				"next() has no more items to give!  Call hasNext() before calling next()");
		}

		// now increment the iterator that gave us the best result
		for (PeekableIterator<T> iterator : iterators) {
			if (!iterator.hasNext()) {
				continue;
			}

			T t = iterator.peek();
			int result = comparator.compare(lowest, t);
			if (result == 0) {
				iterator.next();
				return lowest;
			}
		}

		throw new AssertException(
			"next() has no more items to give!  Call hasNext() before calling next()");
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private static class TComparator<T> implements Comparator<T> {

		@SuppressWarnings("unchecked")
		// we checked that the types are Comparable
		@Override
		public int compare(T t1, T t2) {
			if (!(t1 instanceof Comparable) || !(t2 instanceof Comparable)) {
				throw new AssertException(
					"T must be comparable if you do not supply your own comparator");
			}

			return ((Comparable<T>) t1).compareTo(t2);
		}
	}

	private static class ReverseComparatorWrapper<T> implements Comparator<T> {

		private Comparator<T> delegate;

		ReverseComparatorWrapper(Comparator<T> delegate) {
			this.delegate = delegate;
		}

		@Override
		public int compare(T t1, T t2) {
			return -delegate.compare(t1, t2);
		}
	}
}
