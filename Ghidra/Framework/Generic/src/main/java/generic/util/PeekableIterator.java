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
 * An iterator that allows you to peek at the next item on the iterator.
 *
 * @param <T> The type of this iterator.
 */
public interface PeekableIterator<T> extends Iterator<T> {

	/**
	 * Returns the item that would be returned by calling {@link #next()}, but does not 
	 * increment the iterator as <code>next</code> would.
	 * 
	 * @return the item that would be returned by calling {@link #next()}
	 */
	public T peek() throws NoSuchElementException;
}
