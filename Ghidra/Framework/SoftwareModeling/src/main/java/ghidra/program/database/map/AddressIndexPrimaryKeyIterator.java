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
import java.util.List;
import java.util.NoSuchElementException;

import db.*;
import ghidra.program.model.address.*;

/**
 * Long iterator over indexed addresses. The longs are primary keys returned ordered and restrained
 * by the address field they contain
 */
public class AddressIndexPrimaryKeyIterator implements DBFieldIterator {

	private Table table;

	private List<KeyRange> keyRangeList;
	private DBFieldIterator it;
	private int keyRangeIndex = -1;
	private int indexCol;

	/**
	 * Empty iterator constructor
	 */
	public AddressIndexPrimaryKeyIterator() {
	}

	/**
	 * Constructs a new AddressIndexPrimaryKeyIterator.
	 * Memory addresses encoded as Absolute are not included.
	 * @param table the database table containing indexed addresses.
	 * @param indexCol the column that contains indexed addresses.
	 * @param addrMap the address map
	 * @param atStart if true, iterates forward, otherwise iterates backwards.
	 * @throws IOException if a database io error occurs.
	 */
	public AddressIndexPrimaryKeyIterator(Table table, int indexCol, AddressMap addrMap,
			boolean atStart) throws IOException {
		this(table, indexCol, addrMap, false, (AddressSetView) null, atStart);
	}

	/**
	 * Constructs a new AddressIndexPrimaryKeyIterator for a range of addresses.
	 * Memory addresses encoded as Absolute are not included.
	 * @param table the database table containing indexed addresses.
	 * @param indexCol the column that contains indexed addresses.
	 * @param addrMap the address map
	 * @param minAddr the first address in the range to iterate over.
	 * @param maxAddr the last address in the range to iterator over.
	 * @param atStart if true, iterates forward, otherwise iterates backwards.
	 * @throws IOException if a database io error occurs.
	 */
	public AddressIndexPrimaryKeyIterator(Table table, int indexCol, AddressMap addrMap,
			Address minAddr, Address maxAddr, boolean atStart) throws IOException {
		this(table, indexCol, addrMap, false, new AddressSet(minAddr, maxAddr), atStart);
	}

	/**
	 * Constructs a new AddressIndexPrimaryKeyIterator for a set of addresses.
	 * Memory addresses encoded as Absolute are not included.
	 * @param table the database table containing indexed addresses.
	 * @param indexCol the column that contains indexed addresses.
	 * @param addrMap the address map
	 * @param set the set of addresses to iterator over.
	 * @param atStart if true, iterates forward, otherwise iterates backwards.
	 * @throws IOException if a database io error occurs.
	 */
	public AddressIndexPrimaryKeyIterator(Table table, int indexCol, AddressMap addrMap,
			AddressSetView set, boolean atStart) throws IOException {
		this(table, indexCol, addrMap, false, set, atStart);
	}

	/**
	 * Constructs a new AddressIndexPrimaryKeyIterator for a set of addresses.
	 * @param table the database table containing indexed addresses.
	 * @param indexCol the column that contains indexed addresses.
	 * @param addrMap the address map
	 * @param absolute if true, only absolute memory address encodings are considered, otherwise 
	 * only standard/relocatable address encodings are considered.
	 * @param set the set of addresses to iterator over or null for all addresses.
	 * @param atStart if true, iterates forward, otherwise iterates backwards.
	 * @throws IOException if a database io error occurs.
	 */
	AddressIndexPrimaryKeyIterator(Table table, int indexCol, AddressMap addrMap, boolean absolute,
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
			it = table.indexKeyIterator(indexCol, new LongField(keyRange.minKey),
				new LongField(keyRange.maxKey), true);
		}
		else {
			keyRangeIndex = keyRangeList.size() - 1;
			KeyRange keyRange = keyRangeList.get(keyRangeIndex);
			it = table.indexKeyIterator(indexCol, new LongField(keyRange.minKey),
				new LongField(keyRange.maxKey), false);
		}
	}

	/**
	 * Constructs a new AddressIndexPrimaryKeyIterator starting at a given address.
	 * Memory addresses encoded as Absolute are not included.
	 * @param table the database table containing indexed addresses.
	 * @param indexCol the column that contains indexed addresses.
	 * @param addrMap the address map
	 * @param start the starting address for the iterator.
	 * @param before if true, positions the iterator before start, otherwise positions it after start.
	 * @throws IOException if a database io error occurs.
	 */
	public AddressIndexPrimaryKeyIterator(Table table, int indexCol, AddressMap addrMap,
			Address start, boolean before) throws IOException {
		this(table, indexCol, addrMap, false, start, before);
	}

	/**
	 * Constructs a new AddressIndexPrimaryKeyIterator starting at a given address
	 * @param table the database table containing indexed addresses.
	 * @param indexCol the column that contains indexed addresses.
	 * @param addrMap the address map
	 * @param absolute if true, only absolute memory address encodings are considered, otherwise 
	 * only standard/relocatable address encodings are considered.
	 * @param start the starting address for the iterator.
	 * @param before if true, positions the iterator before start, otherwise positions it after start.
	 * @throws IOException if a database io error occurs.
	 */
	AddressIndexPrimaryKeyIterator(Table table, int indexCol, AddressMap addrMap, boolean absolute,
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
				it = table.indexKeyIterator(indexCol, new LongField(keyRange.minKey),
					new LongField(keyRange.maxKey), true);
			}
			else {
				KeyRange keyRange = keyRangeList.get(--keyRangeIndex);
				it = table.indexKeyIterator(indexCol, new LongField(keyRange.minKey),
					new LongField(keyRange.maxKey), false);
			}
		}
		else {
			// start address is contained within keyRangeList
			KeyRange keyRange = keyRangeList.get(keyRangeIndex);
			long startKey =
				absolute ? addrMap.getAbsoluteEncoding(start, false) : addrMap.getKey(start, false);
			it = table.indexKeyIterator(indexCol, new LongField(keyRange.minKey),
				new LongField(keyRange.maxKey), new LongField(startKey), before);
		}
	}

	@Override
	public boolean hasNext() throws IOException {
		if (it == null) {
			return false;
		}
		else if (!it.hasNext()) {
			while (keyRangeIndex < (keyRangeList.size() - 1)) {
				KeyRange keyRange = keyRangeList.get(++keyRangeIndex);
				it = table.indexKeyIterator(indexCol, new LongField(keyRange.minKey),
					new LongField(keyRange.maxKey), true);
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

	@Override
	public boolean hasPrevious() throws IOException {
		if (it == null) {
			return false;
		}
		else if (!it.hasPrevious()) {
			while (keyRangeIndex > 0) {
				KeyRange keyRange = keyRangeList.get(--keyRangeIndex);
				it = table.indexKeyIterator(indexCol, new LongField(keyRange.minKey),
					new LongField(keyRange.maxKey), false);
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

	@Override
	public Field next() throws IOException {
		if (hasNext()) {
			return it.next();
		}
		throw new NoSuchElementException();
	}

	@Override
	public Field previous() throws IOException {
		if (hasPrevious()) {
			return it.previous();
		}
		throw new NoSuchElementException();
	}

	@Override
	public boolean delete() throws IOException {
		if (it != null) {
			return it.delete();
		}
		return false;
	}

}
