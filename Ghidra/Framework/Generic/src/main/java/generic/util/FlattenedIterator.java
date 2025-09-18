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

import java.util.Iterator;
import java.util.function.Function;

/**
 * Given an "outer" iterator and a mapping from its elements to "inner" iterators, this is a
 * flattened iterator over elements from the inner iterators.
 * 
 * @param <O> the type of elements in the outer iterator
 * @param <I> the type of elements in the inner and flattened iterators
 */
public class FlattenedIterator<O, I> implements Iterator<I> {
	/**
	 * Create a flattened iterator
	 * <p>
	 * This iterates over each element of {@code outer} and applies the given {@code innerFactory}
	 * to generate an "inner" iterator. The returned iterator will produce elements from the inner
	 * iterators as if concatentated. This is essentially a flat-map operation on iterators. Note
	 * the {@code innerFactory} may return null to skip an outer element.
	 * 
	 * @param <O> the type of elements in the outer iterator
	 * @param <I> the type of elements in the inner and flattened iterators
	 * @param outer the outer iterator
	 * @param innerFactory a mapping from outer elements to inner iterators
	 * @return the flattened iterator
	 */
	public static <O, I> Iterator<I> start(Iterator<O> outer,
			Function<O, Iterator<? extends I>> innerFactory) {
		return new FlattenedIterator<>(outer, innerFactory);
	}

	protected final Iterator<O> outer;
	protected final Function<O, Iterator<? extends I>> innerFactory;

	protected Iterator<? extends I> inner;
	protected Iterator<? extends I> preppedInner;

	protected FlattenedIterator(Iterator<O> outer,
			Function<O, Iterator<? extends I>> innerFactory) {
		this.outer = outer;
		this.innerFactory = innerFactory;
	}

	private Iterator<? extends I> prepNextIterator() {
		while (outer.hasNext()) {
			Iterator<? extends I> candidate = innerFactory.apply(outer.next());
			if (candidate != null && candidate.hasNext()) {
				return candidate;
			}
		}
		return null;
	}

	@Override
	public boolean hasNext() {
		if (inner != null && inner.hasNext() || preppedInner != null && preppedInner.hasNext()) {
			return true;
		}
		preppedInner = prepNextIterator();
		return preppedInner != null;
	}

	@Override
	public I next() {
		if (inner == null || !inner.hasNext()) {
			if (preppedInner == null) {
				preppedInner = prepNextIterator();
			}
			if (preppedInner == null) { // Still
				return null;
			}
			inner = preppedInner;
			preppedInner = null;
		}
		return inner.next();
	}

	@Override
	public void remove() {
		inner.remove();
	}
}
