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
package ghidra.program.database.map;

import ghidra.program.model.address.*;

import java.io.IOException;
import java.util.List;
import java.util.NoSuchElementException;

import db.*;

/**
 * Iterator of indexed fields that are addresses. The longs returned are the address longs.
 */
public class AddressIndexKeyIterator implements DBLongIterator {

	private Table table;

	private List<KeyRange> keyRangeList;
	private DBFieldIterator it;
	private int keyRangeIndex = -1;
	private int indexCol;

	/**
	 * Empty iterator.
	 *
	 */
	public AddressIndexKeyIterator() {
	}

	/**
	 * Constructs a new AddressIndexKeyIterator.
	 * Memory addresses encoded as Absolute are not included.
	 * @param table the database table containing indexed addresses.
	 * @param indexCol the column that contains indexed addresses.
	 * @param addrMap the address map
	 * @param atStart if true, iterates forward, otherwise iterates backwards.
	 * @throws IOException if a database io error occurs.
	 */
	public AddressIndexKeyIterator(Table table, int indexCol, AddressMap addrMap, boolean atStart)
			throws IOException {
		this(table, indexCol, addrMap, false, (AddressSetView) null, atStart);
	}

	/**
	 * Constructs a new AddressIndexKeyIterator for a range of addresses.
	 * Memory addresses encoded as Absolute are not included.
	 * @param table the database table containing indexed addresses.
	 * @param indexCol the column that contains indexed addresses.
	 * @param addrMap the address map
	 * @param minAddr the first address in the range to iterate over.
	 * @param maxAddr the last address in the range to iterator over.
	 * @param atStart if true, iterates forward, otherwise iterates backwards.
	 * @throws IOException if a database io error occurs.
	 */
	public AddressIndexKeyIterator(Table table, int indexCol, AddressMap addrMap, Address minAddr,
			Address maxAddr, boolean atStart) throws IOException {
		this(table, indexCol, addrMap, false, new AddressSet(minAddr, maxAddr), atStart);
	}

	/**
	 * Constructs a new AddressIndexKeyIterator for a set of addresses.
	 * Memory addresses encoded as Absolute are not included.
	 * @param table the database table containing indexed addresses.
	 * @param indexCol the column that contains indexed addresses.
	 * @param addrMap the address map
	 * @param set the set of addresses to iterator over.
	 * @param atStart if true, iterates forward, otherwise iterates backwards.
	 * @throws IOException if a database io error occurs.
	 */
	public AddressIndexKeyIterator(Table table, int indexCol, AddressMap addrMap,
			AddressSetView set, boolean atStart) throws IOException {
		this(table, indexCol, addrMap, false, set, atStart);
	}

	/**
	 * Constructs a new AddressIndexKeyIterator for a set of addresses
	 * @param table the database table containing indexed addresses.
	 * @param indexCol the column that contains indexed addresses.
	 * @param addrMap the address map
	 * @param absolute if true, only absolute memory address encodings are considered, otherwise 
	 * only standard/relocatable address encodings are considered.
	 * @param set the set of addresses to iterator over.
	 * @param atStart if true, iterates forward, otherwise iterates backwards.
	 * @throws IOException if a database io error occurs.
	 */
	public AddressIndexKeyIterator(Table table, int indexCol, AddressMap addrMap, boolean absolute,
			AddressSetView set, boolean atStart) throws IOException {
		this.table = table;
		this.indexCol = indexCol;

		keyRangeList = addrMap.getKeyRanges(set, absolute, false);
		if (keyRangeList.size() == 0) {
			return;
		}

		if (atStart) {
			keyRangeIndex = 0;
			KeyRange keyRange = keyRangeList.get(keyRangeIndex);
			it =
				table.indexFieldIterator(new LongField(keyRange.minKey), new LongField(
					keyRange.maxKey), true, indexCol);
		}
		else {
			keyRangeIndex = keyRangeList.size() - 1;
			KeyRange keyRange = keyRangeList.get(keyRangeIndex);
			it =
				table.indexFieldIterator(new LongField(keyRange.minKey), new LongField(
					keyRange.maxKey), false, indexCol);
		}
	}

	/**
	 * Constructs a new AddressIndexKeyIterator starting at a given address.
	 * Memory addresses encoded as Absolute are not included.
	 * @param table the database table containing indexed addresses.
	 * @param indexCol the column that contains indexed addresses.
	 * @param addrMap the address map
	 * @param start the starting address for the iterator.
	 * @param before if true, positions the iterator before start, otherwise positions it after start.
	 * @throws IOException if a database io error occurs.
	 */
	public AddressIndexKeyIterator(Table table, int indexCol, AddressMap addrMap, Address start,
			boolean before) throws IOException {
		this(table, indexCol, addrMap, false, start, before);
	}

	/**
	 * Constructs a new AddressIndexKeyIterator starting at a given address
	 * @param table the database table containing indexed addresses.
	 * @param indexCol the column that contains indexed addresses.
	 * @param addrMap the address map
	 * @param absolute if true, only absolute memory address encodings are considered, otherwise 
	 * only standard/relocatable address encodings are considered.
	 * @param start the starting address for the iterator.
	 * @param before if true, positions the iterator before start, otherwise positions it after start.
	 * @throws IOException if a database io error occurs.
	 */
	AddressIndexKeyIterator(Table table, int indexCol, AddressMap addrMap, boolean absolute,
			Address start, boolean before) throws IOException {
		this.table = table;
		this.indexCol = indexCol;

		keyRangeList = addrMap.getKeyRanges(null, absolute, false);
		keyRangeIndex = addrMap.findKeyRange(keyRangeList, start);
		if (keyRangeList.size() == 0) {
			return;
		}

		if (keyRangeIndex < 0) {
			// start address NOT contained within keyRangeList
			keyRangeIndex = -keyRangeIndex - 1;
			if (keyRangeIndex == 0) {
				KeyRange keyRange = keyRangeList.get(keyRangeIndex);
				it =
					table.indexFieldIterator(new LongField(keyRange.minKey), new LongField(
						keyRange.maxKey), true, indexCol);
			}
			else {
				KeyRange keyRange = keyRangeList.get(--keyRangeIndex);
				it =
					table.indexFieldIterator(new LongField(keyRange.minKey), new LongField(
						keyRange.maxKey), false, indexCol);
			}
		}
		else {
			// start address is contained within keyRangeList
			KeyRange keyRange = keyRangeList.get(keyRangeIndex);
			long startKey =
				absolute ? addrMap.getAbsoluteEncoding(start, false) : addrMap.getKey(start, false);
			it =
				table.indexFieldIterator(new LongField(keyRange.minKey), new LongField(
					keyRange.maxKey), new LongField(startKey), before, indexCol);
		}
	}

	/**
	 * @see db.DBLongIterator#hasNext()
	 */
	public boolean hasNext() throws IOException {
		if (it == null) {
			return false;
		}
		else if (!it.hasNext()) {
			while (keyRangeIndex < (keyRangeList.size() - 1)) {
				KeyRange keyRange = keyRangeList.get(++keyRangeIndex);
				it =
					table.indexFieldIterator(new LongField(keyRange.minKey), new LongField(
						keyRange.maxKey), true, indexCol);
				if (it.hasPrevious()) {
					it.previous();
				}
				if (it.hasNext()) {
					return true;
				}
			}
			return false;
		}
		return true;
	}

	/**
	 * @see db.DBLongIterator#hasPrevious()
	 */
	public boolean hasPrevious() throws IOException {
		if (it == null) {
			return false;
		}
		else if (!it.hasPrevious()) {
			while (keyRangeIndex > 0) {
				KeyRange keyRange = keyRangeList.get(--keyRangeIndex);
				it =
					table.indexFieldIterator(new LongField(keyRange.minKey), new LongField(
						keyRange.maxKey), false, indexCol);
				if (it.hasNext()) {
					it.next();
				}
				if (it.hasPrevious()) {
					return true;
				}
			}
			return false;
		}
		return true;
	}

	/**
	 * @see db.DBLongIterator#next()
	 */
	public long next() throws IOException {
		if (hasNext()) {
			return ((LongField) it.next()).getLongValue();
		}
		throw new NoSuchElementException();
	}

	/**
	 * @see db.DBLongIterator#previous()
	 */
	public long previous() throws IOException {
		if (hasPrevious()) {
			return ((LongField) it.previous()).getLongValue();
		}
		throw new NoSuchElementException();
	}

	/**
	 * @see db.DBLongIterator#delete()
	 */
	public boolean delete() throws IOException {
		if (it != null) {
			return it.delete();
		}
		return false;
	}
}
