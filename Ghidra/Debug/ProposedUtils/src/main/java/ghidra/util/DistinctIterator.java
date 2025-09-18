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

import java.util.Iterator;
import java.util.Objects;

import generic.util.AbstractPeekableIterator;
import generic.util.PeekableIterator;
import generic.util.PeekableIterators;

/**
 * A filtering iterator which removes repeated objects
 * <p>
 * This iterator only removes immediate repeats (similar to the uniq command on UNIX). To obtain a
 * truly distinct iteration, the wrapped iterator must visit elements in sorted order.
 * 
 * @param <T> the type of elements
 */
public class DistinctIterator<T> extends AbstractPeekableIterator<T> {
	protected boolean first;
	protected T last;
	protected final PeekableIterator<T> wrapped;

	public DistinctIterator(Iterator<T> wrapped) {
		this.wrapped = PeekableIterators.castOrWrap(wrapped);
	}

	@Override
	protected T seekNext() {
		if (first) {
			first = false;
			return last = wrapped.hasNext() ? wrapped.peek() : null;
		}
		while (wrapped.hasNext() && Objects.equals(last, wrapped.peek())) {
			wrapped.next();
		}
		return last = wrapped.hasNext() ? wrapped.peek() : null;
	}
}
