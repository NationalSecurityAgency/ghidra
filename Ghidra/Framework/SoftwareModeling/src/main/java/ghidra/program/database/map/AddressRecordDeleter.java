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
package ghidra.program.database.map;

import java.io.IOException;
import java.util.Iterator;
import java.util.List;

import db.*;
import ghidra.program.database.util.RecordFilter;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.KeyRange;

/**
 * Static methods to delete records from a table. Handles subtle issues with image base causing
 * address to "wrap".
 */
public class AddressRecordDeleter {

	private AddressRecordDeleter() {
	}

	/**
	 * Deletes the records the fall within the given range. Uses the address map to convert the
	 * address range into 1 or more key ranges. (Address ranges may not be continuous after
	 * converting to long space).
	 * NOTE: Absolute key encodings are not handled currently !!
	 * @param table the database table to delete records from.
	 * @param addrMap the address map used to convert addresses into long keys.
	 * @param start the start address in the range.
	 * @param end the end address in the range.
	 * @throws IOException if a database io error occurs.
	 */

	public static boolean deleteRecords(Table table, AddressMap addrMap, Address start, Address end)
			throws IOException {
		List<KeyRange> keyRangeList = addrMap.getKeyRanges(start, end, false);
		boolean success = false;
		Iterator<KeyRange> it = keyRangeList.iterator();
		while (it.hasNext()) {
			KeyRange kr = it.next();
			success |= table.deleteRecords(kr.minKey, kr.maxKey);
		}
		return success;
	}

	/**
	 * Deletes the records that have indexed address fields that fall within the given range.
	 * Uses the address map to convert the
	 * address range into 1 or more key ranges. (Address ranges may not be continuous after
	 * converting to long space).
	 * NOTE: Absolute key encodings are not handled currently !!
	 * @param table the database table to delete records from.
	 * @param colIx the column that has indexed addresses.
	 * @param addrMap the address map used to convert addresses into long keys.
	 * @param start the start address in the range.
	 * @param end the end address in the range.
	 * @throws IOException if a database io error occurs.
	 */
	public static boolean deleteRecords(Table table, int colIx, AddressMap addrMap, Address start,
			Address end, RecordFilter filter) throws IOException {

		boolean success = false;
		DBFieldIterator iter =
			new AddressIndexPrimaryKeyIterator(table, colIx, addrMap, start, end, true);
		while (iter.hasNext()) {
			Field next = iter.next();
			if (filter != null) {
				DBRecord record = table.getRecord(next);
				if (!filter.matches(record)) {
					continue;
				}
			}
			success |= iter.delete();
		}
		return success;
	}
}
