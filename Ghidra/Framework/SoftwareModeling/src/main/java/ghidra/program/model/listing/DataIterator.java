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

import java.util.Arrays;
import java.util.Iterator;

import util.CollectionUtils;

/**
 * Interface to define an iterator over over some set of Data.
 *
 * @see CollectionUtils#asIterable
 */
public interface DataIterator extends Iterator<Data>, Iterable<Data>  {
	public static final DataIterator EMPTY = of(/*nothing*/);

	/**
	 * Create a DataIterator that returns a sequence of the specified items.
	 * 
	 * @param dataInstances variable length list of items that will be iterated
	 * @return new Iterator 
	 */
	public static DataIterator of(Data... dataInstances) {
		return new IteratorWrapper(Arrays.asList(dataInstances).iterator());
	}

	@Override
	public boolean hasNext();

	@Override
	public Data next();

	@Override
	default Iterator<Data> iterator() {
		return this;
	}

	// --------------------------------------------------------------------------------
	// Helper static stuff
	// --------------------------------------------------------------------------------

	static class IteratorWrapper implements DataIterator {
		private Iterator<Data> it;

		IteratorWrapper(Iterator<Data> it) {
			this.it = it;
		}

		@Override
		public boolean hasNext() {
			return it.hasNext();
		}

		@Override
		public Data next() {
			return it.next();
		}

	}
}
