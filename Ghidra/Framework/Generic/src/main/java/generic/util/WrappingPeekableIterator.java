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
import java.util.NoSuchElementException;

/**
 * An implementation of {@link PeekableIterator} that can take a Java {@link Iterator} and 
 * wrap it to implement the {@link PeekableIterator} interface.
 *
 * @param <T> the type of the iterator
 */
public class WrappingPeekableIterator<T> implements PeekableIterator<T> {

	private Iterator<T> iterator;
	private T peek;
	private boolean peeked;

	public WrappingPeekableIterator(Iterator<T> iterator) {
		this.iterator = iterator;
	}

	@Override
	public boolean hasNext() {
		if (peeked) {
			return true;
		}
		return iterator.hasNext();
	}

	@Override
	public T next() {
		if (peeked) {
			peeked = false;
			return peek;
		}
		return iterator.next();
	}

	@Override
	public void remove() {
		throw new UnsupportedOperationException();
	}

	@Override
	public T peek() throws NoSuchElementException {
		if (peeked) {
			return peek;
		}

		if (!hasNext()) {
			throw new NoSuchElementException();
		}

		peek = next();
		peeked = true;
		return peek;
	}

}
