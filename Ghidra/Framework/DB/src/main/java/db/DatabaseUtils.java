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
 * <code>DatabaseUtils</code> provides a collection of database related utilities.
 */
public class DatabaseUtils {

	private DatabaseUtils() {
	}

	/**
	 * Reassign the long key assigned to a contiguous group of records within a table.
	 * A shift in the key value is computed as the difference of oldStart and newStart.
	 * Existing records whose keys lie within the new range will be removed prior to
	 * moving the target set of records.
	 * @param table table within which records should be moved.
	 * @param oldStart old key value for start of range
	 * @param newStart new key value for start of range
	 * @param size determines the range of keys to be moved (oldStart to oldStart+size-1, inclusive)
	 * @throws IOException if there is an error moving the records
	 */
	public static void moveRecords(Table table, long oldStart, long newStart, long size)
			throws IOException {
		if (oldStart == newStart) {
			return;
		}
		if (size <= 0) {
			throw new IllegalArgumentException("size must be > 0");
		}
		if ((oldStart + size - 1 < 0) || (newStart + size - 1 < 0)) {
			throw new IllegalArgumentException("Illegal range: end range overflow");
		}

		DBHandle tmp = new DBHandle();
		Table tmpTable = tmp.createTable("tmp", table.getSchema());
		long txID = tmp.startTransaction();

		long keyDiff = newStart - oldStart;
		RecordIterator it = table.iterator(oldStart, oldStart + size - 1, oldStart);
		while (it.hasNext()) {
			DBRecord rec = it.next();
			rec.setKey(rec.getKey() + keyDiff);
			tmpTable.putRecord(rec);
		}

		table.deleteRecords(oldStart, oldStart + size - 1);
		table.deleteRecords(newStart, newStart + size - 1);

		it = tmpTable.iterator(newStart, newStart + size - 1, newStart);
		while (it.hasNext()) {
			DBRecord rec = it.next();
			table.putRecord(rec);
		}

		tmp.endTransaction(txID, false);
		tmp.close();
	}
}
