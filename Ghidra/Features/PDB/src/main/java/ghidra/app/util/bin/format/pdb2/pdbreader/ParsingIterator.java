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
package ghidra.app.util.bin.format.pdb2.pdbreader;

import java.util.NoSuchElementException;

import ghidra.util.exception.CancelledException;

/**
 * Parsing Iterator, which allows CancelledException.
 * <p>
 * Has {@link #hasNext()} and {@link #next()}.
 * <p>
 * Also has {@link #peek()}, which performs the same operation as {@link #next()} without advancing
 * the iterator.
 * <p>
 * Does not have {@code remove()} and {@code forEachRemaining()} that are in {@code Iterator}.
 * <p>
 *@param <E> the iterator type
 */
interface ParsingIterator<E> {

	/**
	 * Returns {@code true} if more elements exist
	 * @return {@code true} if more elements exist
	 * @throws CancelledException upon user cancellation
	 */
	boolean hasNext() throws CancelledException;

	/**
	 * Returns the next element in the iteration.
	 * @return the next element in the iteration
	 * @throws CancelledException upon user cancellation
	 * @throws NoSuchElementException if the iteration has no more elements
	 */
	E next() throws CancelledException, NoSuchElementException;

	/**
	 * Returns the next element in the iteration without advancing the iterator.
	 * @return the next element in the iteration
	 * @throws CancelledException upon user cancellation
	 * @throws NoSuchElementException if the iteration has no more elements
	 */
	E peek() throws CancelledException, NoSuchElementException;

}
