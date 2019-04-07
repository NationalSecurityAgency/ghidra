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
package ghidra.program.model.listing;

import java.util.Iterator;
import java.util.NoSuchElementException;

import util.CollectionUtils;

/**
 * Interface to define an iterator over over some set of Data.
 *
 * @see CollectionUtils#asIterable
 */
public interface DataIterator extends Iterator<Data>, Iterable<Data> {
	public static final DataIterator EMPTY = createEmptyIterator();

	@Override
	public boolean hasNext();

	@Override
	public Data next();

	@Override
	default Iterator<Data> iterator() {
		return this;
	}

	// --------------------------------------------------------------------------------
	// Helper static methods
	// --------------------------------------------------------------------------------
	public static DataIterator createEmptyIterator() {
		return new DataIterator() {
			//@formatter:off
			@Override public Data next() { throw new NoSuchElementException(); }
			@Override public void remove() { throw new IllegalStateException(); }
			@Override public boolean hasNext() { return false; }
			//@formatter:on
		};
	}
}
