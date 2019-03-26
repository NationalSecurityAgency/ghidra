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

import java.util.Iterator;
import java.util.function.Predicate;

public class FilteredIterator<T> implements Iterator<T>, Iterable<T> {
	private Iterator<T> it;
	private Predicate<T> filter;
	private T nextThing;

	/**
	 * Construct a new FilteredIterator.
	 * @param it the iterator to filter
	 * @param filter the filter on T
	 */
	public FilteredIterator(Iterator<T> it, Predicate<T> filter) {
		this.it = it;
		this.filter = filter;
	}

	@Override
	public boolean hasNext() {
		if (nextThing != null) {
			return true;
		}
		return findNext();
	}

	@Override
	public T next() {
		if (hasNext()) {
			T t = nextThing;
			nextThing = null;
			return t;
		}
		return null;
	}

	private boolean findNext() {
		while (it.hasNext()) {
			T t = it.next();
			if (filter.test(t)) {
				nextThing = t;
				return true;
			}
		}
		return false;
	}

	@Override
	public void remove() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Iterator<T> iterator() {
		return this;
	}
}
