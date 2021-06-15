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
package ghidra.util;

import java.util.*;
import java.util.Map.Entry;

import com.google.common.collect.*;

import generic.util.PeekableIterator;

/**
 * An iterator which merges sorted iterators according to a comparator
 * 
 * <P>
 * TODO: This may be replaceable with {@link Iterators#mergeSorted(Iterable, Comparator)}. I
 * hesitate, since I benefit from this implementation complying with {@link PeekableIterator}, while
 * Guava's does not -- though, they would use {@link PeekingIterator} instead. Currently, my
 * {@link UnionAddressRangeIterator} takes advantage of the {@link PeekableIterator} interface of
 * this implementation. I could use {@link Iterators#peekingIterator(Iterator)}, but this would
 * introduce a wrapper.
 * 
 * @param <T> the type of elements in each iterator
 */
public class MergeSortingIterator<T> implements PeekableIterator<T> {
	protected static class LabeledIterator<L, T> implements PeekableIterator<Entry<L, T>> {
		protected final PeekableIterator<? extends T> it;
		protected final MyEntry<L, T> entryNext;
		protected final MyEntry<L, T> entryPeek;

		protected static <L, T> LabeledIterator<L, T> create(
				Entry<L, ? extends Iterator<? extends T>> entry) {
			return new LabeledIterator<L, T>(entry.getKey(),
				PeekableIterators.castOrWrap(entry.getValue()));
		}

		public LabeledIterator(L label, PeekableIterator<? extends T> it) {
			this.it = it;
			this.entryNext = new MyEntry<>(label);
			this.entryPeek = new MyEntry<>(label);
		}

		@Override
		public boolean hasNext() {
			return it.hasNext();
		}

		@Override
		public Entry<L, T> next() {
			entryNext.value = it.next();
			return entryNext;
		}

		@Override
		public Entry<L, T> peek() throws NoSuchElementException {
			entryPeek.value = it.peek();
			return entryPeek;
		}
	}

	protected static class MyEntry<L, T> implements Entry<L, T> {
		final L label;
		T value;

		public MyEntry(L label) {
			this.label = label;
		}

		@Override
		public L getKey() {
			return label;
		}

		@Override
		public T getValue() {
			return value;
		}

		@Override
		public T setValue(T value) {
			throw new UnsupportedOperationException();
		}
	}

	/**
	 * Construct a merge-sorting iterator which generates labeled values
	 * 
	 * <p>
	 * The map of iterators is a map of entries, each giving a label and an iterator to be merged.
	 * Each iterator must return values as sorted by the given comparator. The entries returned by
	 * the combined iterator give the values in sorted order, but each has a the key indicating
	 * which given iterator returned that value. Note that the returned entry may be re-used by the
	 * underlying implementation, so users needing to keep the entry should create a copy.
	 * 
	 * @param iterMap a map of labeled iterators
	 * @param comparator the comparator of values
	 * @return an iterator which returns labeled values in sorted order
	 */
	public static <L, T> MergeSortingIterator<Entry<L, T>> withLabels(
			Map<L, ? extends Iterator<? extends T>> iterMap, Comparator<T> comparator) {
		Collection<LabeledIterator<L, T>> iterators =
			Collections2.transform(iterMap.entrySet(), LabeledIterator::create);
		Comparator<Entry<L, T>> comp = Comparator.comparing(Entry::getValue, comparator);
		return new MergeSortingIterator<Map.Entry<L, T>>(iterators, comp);
	}

	protected final Comparator<? super T> comparator;
	protected final PriorityQueue<PeekableIterator<? extends T>> queue;

	public MergeSortingIterator(Iterable<? extends Iterator<? extends T>> iterators,
			Comparator<? super T> comparator) {
		this.comparator = comparator;
		this.queue = new PriorityQueue<>(Comparator.comparing(PeekableIterator::peek, comparator));

		for (Iterator<? extends T> it : iterators) {
			if (it.hasNext()) {
				queue.add(PeekableIterators.castOrWrap(it));
			}
		}
	}

	@Override
	public boolean hasNext() {
		return !queue.isEmpty();
	}

	@Override
	public T next() {
		PeekableIterator<? extends T> it = queue.poll();
		if (it == null) {
			return null;
		}
		T result = it.next();
		if (it.hasNext()) {
			queue.add(it);
		}
		return result;
	}

	@Override
	public T peek() throws NoSuchElementException {
		return queue.peek().peek();
	}
}
