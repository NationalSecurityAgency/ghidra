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

/**
 * <code>ConvertedRecordIterator</code> provides a RecordIterator wrapper
 * for performing record conversion frequently required when using older
 * data.
 */
public abstract class ConvertedRecordIterator implements RecordIterator {

	private RecordIterator originalIterator;
	private boolean deleteAllowed;
	
	/**
	 * Constructor.
	 * @param originalIterator
	 * @param deleteAllowed if false and delete is attempted, delete will throw an
	 * UnsupportedOperationException
	 */
	protected ConvertedRecordIterator(RecordIterator originalIterator, boolean deleteAllowed) {
		this.originalIterator = originalIterator;
		this.deleteAllowed = deleteAllowed;
	}
	
	/**
	 * @see db.RecordIterator#delete()
	 */
	public boolean delete() throws IOException {
		if (!deleteAllowed) {
			throw new UnsupportedOperationException("record delete not allowed");
		}
		return originalIterator.delete();
	}

	/**
	 * @see db.RecordIterator#hasNext()
	 */
	public boolean hasNext() throws IOException {
		return originalIterator.hasNext();
	}

	/**
	 * @see db.RecordIterator#hasPrevious()
	 */
	public boolean hasPrevious() throws IOException {
		return originalIterator.hasPrevious();
	}

	/**
	 * @see db.RecordIterator#next()
	 */
	public DBRecord next() throws IOException {
		return convertRecord(originalIterator.next());
	}

	/**
	 * @see db.RecordIterator#previous()
	 */
	public DBRecord previous() throws IOException {
		return convertRecord(originalIterator.previous());
	}
	
	/**
	 * Convert a record supplied by the underlying RecordIterator.
	 * @param record
	 * @return converted record
	 */
	protected abstract DBRecord convertRecord(DBRecord record);
	
}
