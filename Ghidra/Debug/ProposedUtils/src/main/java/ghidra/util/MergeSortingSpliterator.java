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
import java.util.function.Consumer;

public class MergeSortingSpliterator<T> implements Spliterator<T> {
	static class SpliteratorEntry<T> {
		final Spliterator<? extends T> spliterator;
		T next;
		boolean hasNext;

		SpliteratorEntry(Spliterator<? extends T> spliterator) {
			this.spliterator = spliterator;
			tryNext();
		}

		boolean tryNext() {
			return hasNext = spliterator.tryAdvance(n -> next = n);
		}
	}

	private final Comparator<? super T> comparator;
	private final PriorityQueue<SpliteratorEntry<T>> queue;

	public MergeSortingSpliterator(Iterable<? extends Spliterator<? extends T>> spliterators,
			Comparator<? super T> comparator) {
		this.comparator = comparator;
		this.queue = new PriorityQueue<>(Comparator.comparing(se -> se.next, comparator));
		for (Spliterator<? extends T> s : spliterators) {
			SpliteratorEntry<T> se = new SpliteratorEntry<>(s);
			if (se.hasNext) {
				queue.add(se);
			}
		}
	}

	@Override
	public boolean tryAdvance(Consumer<? super T> action) {
		SpliteratorEntry<T> se = queue.poll();
		if (se == null) {
			return false;
		}
		T next = se.next;
		if (se.tryNext()) {
			queue.add(se);
		}
		action.accept(next);
		return true;
	}

	@Override
	public Spliterator<T> trySplit() {
		return null;
	}

	@Override
	public long estimateSize() {
		return queue.stream().mapToLong(se -> se.spliterator.estimateSize()).sum() +
			queue.size();
	}

	@Override
	public int characteristics() {
		return Spliterator.ORDERED | Spliterator.SORTED;
	}

	@Override
	public Comparator<? super T> getComparator() {
		return comparator;
	}
}
