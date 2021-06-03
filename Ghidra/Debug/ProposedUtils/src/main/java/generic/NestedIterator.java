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
import java.util.function.Function;

/**
 * TODO Document me
 * 
 * Note the innerFactory may return null to skip an outer element.
 * 
 * TODO: Test innerFactory returning null.
 * 
 * @param <O>
 * @param <I>
 */
public class NestedIterator<O, I> implements Iterator<I> {
	public static <O, I> Iterator<I> start(Iterator<O> outer,
			Function<O, Iterator<? extends I>> innerFactory) {
		return new NestedIterator<>(outer, innerFactory);
	}

	protected final Iterator<O> outer;
	protected final Function<O, Iterator<? extends I>> innerFactory;

	protected Iterator<? extends I> inner;
	protected Iterator<? extends I> preppedInner;

	protected NestedIterator(Iterator<O> outer, Function<O, Iterator<? extends I>> innerFactory) {
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
