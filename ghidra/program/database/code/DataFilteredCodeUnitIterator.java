/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.program.database.code;

import ghidra.program.model.listing.*;

/**
 * Converts a code unit iterator into a data iterator.
 */
public class DataFilteredCodeUnitIterator implements DataIterator {
	private CodeUnitIterator it;
	private Data nextData;

	/**
	 * Constructs a new DataFilteredCodeUnitIterator.
	 * @param it the codeunit iterator to filter on. 
	 */
	public DataFilteredCodeUnitIterator(CodeUnitIterator it) {
		this.it = it;
	}

	/**
	 * @see java.util.Iterator#remove()
	 */
	public void remove() {
		throw new UnsupportedOperationException();
	}

	/**
	 * @see ghidra.program.model.listing.DataIterator#hasNext()
	 */
	public boolean hasNext() {
		if (nextData == null) {
			findNext();
		}
		return nextData != null;
	}

	/**
	 * @see ghidra.program.model.listing.DataIterator#next()
	 */
	public Data next() {
		if (hasNext()) {
			Data ret = nextData;
			nextData = null;
			return ret;
		}
		return null;
	}

	private void findNext() {
		while (nextData == null && it.hasNext()) {
			CodeUnit cu = it.next();
			if (cu instanceof Data) {
				nextData = (Data) cu;
			}
		}
	}

}
