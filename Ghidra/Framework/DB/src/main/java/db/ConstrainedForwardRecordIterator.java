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
package db;

import java.io.IOException;
import java.util.function.Function;

/**
 * {@link ConstrainedForwardRecordIterator} provides the ability to both filter and 
 * translate records returned from an underlying {@link RecordIterator}.
 */
public class ConstrainedForwardRecordIterator implements RecordIterator {
	private DBRecord nextConvertedRecord;

	private final RecordIterator it;
	private final Function<DBRecord, DBRecord> recordPredicateAndTranslate;

	/**
	 * Construct a constrained/filtered record iterator.
	 * @param it source record iterator
	 * @param recordPredicateAndTranslate function which enables both filtering of records
	 * (null returned if record should be skipped) and the ability to translate the record
	 * to an alternate table/record schema.
	 */
	public ConstrainedForwardRecordIterator(RecordIterator it,
			Function<DBRecord, DBRecord> recordPredicateAndTranslate) {
		this.it = it;
		this.recordPredicateAndTranslate = recordPredicateAndTranslate;
	}

	@Override
	public boolean hasPrevious() {
		throw new UnsupportedOperationException();
	}

	@Override
	public DBRecord previous() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean delete() throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean hasNext() throws IOException {
		if (nextConvertedRecord != null) {
			return true;
		}
		while (nextConvertedRecord == null && it.hasNext()) {
			nextConvertedRecord = recordPredicateAndTranslate.apply(it.next());
		}
		return nextConvertedRecord != null;
	}

	@Override
	public DBRecord next() throws IOException {
		if (hasNext()) {
			DBRecord returnedRecord = nextConvertedRecord;
			nextConvertedRecord = null;
			return returnedRecord;
		}
		return null;
	}
}
