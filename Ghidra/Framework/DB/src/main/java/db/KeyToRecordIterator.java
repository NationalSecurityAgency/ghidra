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
import java.util.NoSuchElementException;

/**
 * 
 */
public class KeyToRecordIterator implements RecordIterator {

	private DBFieldIterator keyIter;
	private Table table;
	private DBHandle db;

	/**
	 * Construct a record iterator from a secondary index key iterator.
	 * @param keyIter key iterator.
	 */
	public KeyToRecordIterator(Table table, DBFieldIterator keyIter) {
		this.table = table;
		this.db = table.getDBHandle();
		this.keyIter = keyIter;
	}

	/**
	 * @see db.RecordIterator#hasNext()
	 */
	@Override
	public boolean hasNext() throws IOException {
		synchronized (db) {
			return keyIter.hasNext();
		}
	}

	/**
	 * @see db.RecordIterator#hasPrevious()
	 */
	@Override
	public boolean hasPrevious() throws IOException {
		synchronized (db) {
			return keyIter.hasPrevious();
		}
	}

	/**
	 * @see db.RecordIterator#next()
	 */
	@Override
	public DBRecord next() throws IOException {
		synchronized (db) {
			try {
				return table.getRecord(keyIter.next());
			}
			catch (NoSuchElementException e) {
				return null;
			}
		}
	}

	/**
	 * @see db.RecordIterator#previous()
	 */
	@Override
	public DBRecord previous() throws IOException {
		synchronized (db) {
			try {
				return table.getRecord(keyIter.previous());
			}
			catch (NoSuchElementException e) {
				return null;
			}
		}
	}

	/**
	 * @see db.RecordIterator#delete()
	 */
	@Override
	public boolean delete() throws IOException {
		return keyIter.delete();
	}
}
