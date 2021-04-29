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

import java.util.NoSuchElementException;

import generic.util.PeekableIterator;

public abstract class AbstractPeekableIterator<T> implements PeekableIterator<T> {
	protected T next = null;
	protected boolean soughtNext = false;

	protected abstract T seekNext();

	private void checkSeekNext() {
		if (!soughtNext) {
			soughtNext = true;
			next = seekNext();
		}
	}

	@Override
	public boolean hasNext() {
		checkSeekNext();
		return next != null;
	}

	@Override
	public T next() {
		checkSeekNext();
		soughtNext = false;
		return next;
	}

	@Override
	public T peek() throws NoSuchElementException {
		if (!hasNext()) {
			throw new NoSuchElementException();
		}
		return next;
	}

}
