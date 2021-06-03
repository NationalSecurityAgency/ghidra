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

import java.util.ListIterator;

/**
 * Wraps a {@link ListIterator} so that the operations are reversed.
 * 
 * NOTE: you must obtain an iterator that is already at its end. E.g., if you wish to traverse a
 * list in reverse, you would use
 * {@code new ReversedListIterator<>(list.listIterator(list.size()))}.
 *
 * @param <E> the type of each element
 */
public class ReversedListIterator<E> implements ListIterator<E> {
	private ListIterator<E> it;

	public ReversedListIterator(ListIterator<E> it) {
		this.it = it;
	}

	@Override
	public boolean hasNext() {
		return it.hasPrevious();
	}

	@Override
	public E next() {
		return it.previous();
	}

	@Override
	public boolean hasPrevious() {
		return it.hasNext();
	}

	@Override
	public E previous() {
		return it.next();
	}

	@Override
	public int nextIndex() {
		return it.previousIndex();
	}

	@Override
	public int previousIndex() {
		return it.nextIndex();
	}

	@Override
	public void remove() {
		it.remove();
	}

	@Override
	public void set(E e) {
		it.set(e);
	}

	@Override
	public void add(E e) {
		it.add(e);
	}
}
