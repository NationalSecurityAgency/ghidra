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
package ghidra.program.database.code;

import java.io.IOException;

import db.DBRecord;
import db.RecordIterator;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;

/**
 * Converts a record iterator into a DataIterator.
 */
class DataRecordIterator implements DataIterator {
	private CodeUnitCache cache;
	private RecordIterator it;
	private Data nextData;
	private boolean forward;

	/**
	 * Constructs a new DataRecordIterator
	 * @param cache the code unit cache
	 * @param it the record iterator
	 * @param forward the direction of the iterator.
	 */
	DataRecordIterator(CodeUnitCache cache, RecordIterator it, boolean forward) {
		this.cache = cache;
		this.it = it;
		this.forward = forward;

	}

	/**
	 * @see java.util.Iterator#remove()
	 */
	@Override
	public void remove() {
		throw new UnsupportedOperationException();
	}

	/**
	 * @see ghidra.program.model.listing.CodeUnitIterator#hasNext()
	 */
	@Override
	public boolean hasNext() {
		if (nextData == null) {
			findNext();
		}
		return nextData != null;
	}

	/**
	 * @see ghidra.program.model.listing.CodeUnitIterator#next()
	 */
	@Override
	public Data next() {
		if (hasNext()) {
			Data ret = nextData;
			nextData = null;
			return ret;
		}
		return null;
	}

	private void findNext() {
		try {
			while (nextData == null && (forward ? it.hasNext() : it.hasPrevious())) {
				DBRecord record = forward ? it.next() : it.previous();
				nextData = cache.getData(record);
			}
		}
		catch (IOException e) {
		}
	}

}
