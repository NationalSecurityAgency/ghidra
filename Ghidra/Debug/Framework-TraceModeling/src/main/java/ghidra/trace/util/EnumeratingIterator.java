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

import java.util.Iterator;

public interface EnumeratingIterator<T> extends Iterator<T> {
	public static class WrappingEnumeratingIterator<T> implements EnumeratingIterator<T> {
		protected final Iterator<T> it;

		protected int index = -1;

		public WrappingEnumeratingIterator(Iterator<T> it) {
			this.it = it;
		}

		@Override
		public int getIndex() {
			return index;
		}

		@Override
		public boolean hasNext() {
			return it.hasNext();
		}

		@Override
		public T next() {
			T result = it.next();
			index++;
			return result;
		}
	}

	public static <T> EnumeratingIterator<T> castOrWrap(Iterator<T> it) {
		if (it instanceof EnumeratingIterator) {
			return (EnumeratingIterator<T>) it;
		}
		return new WrappingEnumeratingIterator<T>(it);
	}

	/**
	 * Get the index of the last element returned by {@link #next()}.
	 * 
	 * @return the index of the last iterated element.
	 */
	int getIndex();
}
