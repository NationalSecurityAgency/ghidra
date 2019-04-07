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

import db.DBLongIterator;
import db.Table;

/**
 * Iterator of primary keys that are addresses. The longs returned are the address longs.
 */

public class AddressKeyIterator implements DBLongIterator {

	private Table table;

	private List<KeyRange> keyRangeList;
	private DBLongIterator it;
	private int keyRangeIndex = -1;

	/**
	 * Constructs an empty iterator.
	 */
	public AddressKeyIterator() {
	}

	/**
	 * Constructs  new AddressKeyIterator that iterates over all addresses.
	 * Memory addresses encoded as Absolute are not included.
	 * @param table the database table key by addresses
	 * @param addrMap the address map
	 * @param before positions the iterator before the min value,otherwise after the max value.
	 * @throws IOException if a database error occurs.
	 */
	public AddressKeyIterator(Table table, AddressMap addrMap, boolean before) throws IOException {
		this(table, addrMap, false, null, null, before);
	}

	/**
	 * Constructs  new AddressKeyIterator that iterates overal all addresses and is initially
	 * positioned at startAddr.  Memory addresses encoded as Absolute are not included.
	 * @param table the database table key by addresses
	 * @param addrMap the address map
	 * @param startAddr the address at which to position the iterator.
	 * @param before positions the iterator before the start address,otherwise after
	 * the start address. If the start address is null, then before positions the iterator before
	 * the lowest address, !before positions the iterater after the largest address.
	 * @throws IOException if a database error occurs.
	 */
	public AddressKeyIterator(Table table, AddressMap addrMap, Address startAddr, boolean before)
			throws IOException {
		this(table, addrMap, false, null, startAddr, before);
	}

	/**
	 * Constructs  new AddressKeyIterator that iterates over an address range.
	 * Memory addresses encoded as Absolute are not included.
	 * @param table the database table key by addresses
	 * @param addrMap the address map
	 * @param minAddr the first address in the range.
	 * @param maxAddr the last address in the range.
	 * @param startAddr the address at which to position the iterator, can be null. The exact
	 * position of the iterator depends on the before parameter.
	 * @param before positions the iterator before the start address,otherwise after
	 * the start address. If the start address is null, then before positions the iterator before
	 * the lowest address, !before positions the iterater after the largest address.
	 * @throws IOException if a database error occurs.
	 */
	public AddressKeyIterator(Table table, AddressMap addrMap, Address minAddr, Address maxAddr,
			Address startAddr, boolean before) throws IOException {
		this(table, addrMap, false, addrMap.getAddressFactory().getAddressSet(minAddr, maxAddr),
			startAddr, before);
	}

	/**
	 * Constructs  new AddressKeyIterator to iterate over an address set.
	 * Memory addresses encoded as Absolute are not included.
	 * @param table the database table key by addresses
	 * @param addrMap the address map
	 * @param set the address set to iterator over
	 * @param startAddr the address at which to position the iterator, can be null. The exact
	 * position of the iterator depends on the before parameter.
	 * @param before positions the iterator before the start address,otherwise after
	 * the start address. If the start address is null, then before positions the iterator before
	 * the lowest address, !before positions the iterater after the largest address.
	 * @throws IOException if a database error occurs.
	 */
	public AddressKeyIterator(Table table, AddressMap addrMap, AddressSetView set,
			Address startAddr, boolean before) throws IOException {
		this(table, addrMap, false, set, startAddr, before);
	}

	/**
	 * Constructs  new AddressKeyIterator to iterate over an address set.
	 * @param table the database table key by addresses
	 * @param addrMap the address map
	 * @param absolute if true, only absolute memory address encodings are considered, otherwise 
	 * only standard/relocatable address encodings are considered.
	 * @param set the address set to iterator over
	 * @param startAddr the address at which to position the iterator, can be null. The exact
	 * position of the iterator depends on the before parameter.
	 * @param before positions the iterator before the start address,otherwise after
	 * the start address. If the start address is null, then before positions the iterator before
	 * the lowest address, !before positions the iterator after the largest address.
	 * @throws IOException if a database error occurs.
	 */
	AddressKeyIterator(Table table, AddressMap addrMap, boolean absolute, AddressSetView set,
			Address startAddr, boolean before) throws IOException {

		this.table = table;

		keyRangeList = addrMap.getKeyRanges(set, absolute, false);
		if (keyRangeList.size() == 0) {
			return;
		}

		if (startAddr == null) {
			keyRangeIndex = before ? -1 : (-keyRangeList.size() - 1);
		}
		else {
			keyRangeIndex = addrMap.findKeyRange(keyRangeList, startAddr);
		}

		if (keyRangeIndex >= 0) {
			// start address is contained within keyRangeList
			KeyRange keyRange = keyRangeList.get(keyRangeIndex);
			long key =
				absolute ? addrMap.getAbsoluteEncoding(startAddr, false) : addrMap.getKey(
					startAddr, false);
			it = table.longKeyIterator(keyRange.minKey, keyRange.maxKey, key);
			if (table.hasRecord(key)) {
				if (before) {
					it.previous();
				}
				else {
					it.next();
				}
			}
		}
		else {
			// start address NOT contained within keyRangeList
			keyRangeIndex = -keyRangeIndex - 1;	//keyRange index is the index of the range the startAddr is BEFORE.
			if (keyRangeIndex < keyRangeList.size()) {
				KeyRange keyRange = keyRangeList.get(keyRangeIndex);
				it = table.longKeyIterator(keyRange.minKey, keyRange.maxKey, keyRange.minKey);
				if (hasPrevious()) {
					it.previous();
				}
			}
			else {
				--keyRangeIndex;
				KeyRange keyRange = keyRangeList.get(keyRangeIndex);
				it = table.longKeyIterator(keyRange.minKey, keyRange.maxKey, keyRange.maxKey);
				if (hasNext()) {
					it.next();
				}
			}
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
				it = table.longKeyIterator(keyRange.minKey, keyRange.maxKey, keyRange.minKey);
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
				it = table.longKeyIterator(keyRange.minKey, keyRange.maxKey, keyRange.maxKey);
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
			return it.next();
		}
		throw new NoSuchElementException();
	}

	/**
	 * @see db.DBLongIterator#previous()
	 */
	public long previous() throws IOException {
		if (hasPrevious()) {
			return it.previous();
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
