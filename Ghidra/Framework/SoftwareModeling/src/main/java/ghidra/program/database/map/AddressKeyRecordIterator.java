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
import ghidra.program.model.address.*;

/**
 * Returns a RecordIterator over records that are address keyed.  Various constructors allow
 * the iterator to be restricted to an address range or address set and optionally to be
 * positioned at some starting address.
 */
public class AddressKeyRecordIterator implements RecordIterator {

	private Table table;

	private List<KeyRange> keyRangeList;
	private RecordIterator it;
	private int keyRangeIndex = -1;

	/**
	 * Construcs a new AddressKeyRecordIterator that iterates over all records in ascending order.
	 * Memory addresses encoded as Absolute are not included.
	 * @param table the table to iterate.
	 * @param addrMap the address map
	 * @throws IOException if a database io error occurs.
	 */
	public AddressKeyRecordIterator(Table table, AddressMap addrMap) throws IOException {
		this(table, addrMap, false, null, null, true);
	}

	/**
	 * Construcs a new AddressKeyRecordIterator that iterates over records starting at given 
	 * start address.  Memory addresses encoded as Absolute are not included.
	 * @param table the table to iterate.
	 * @param addrMap the address map
	 * @param startAddr the address at which to position the iterator.  The iterator will be positioned 
	 * either before or after the start address depending on the before parameter.
	 * @param before if true, the iterator will be positioned before the start address, otherwise
	 * it will be positioned after the start address.
	 * @throws IOException if a database io error occurs.
	 */
	public AddressKeyRecordIterator(Table table, AddressMap addrMap, Address startAddr,
			boolean before) throws IOException {
		this(table, addrMap, false, null, startAddr, before);
	}

	/**
	 * Constructs a new AddressKeyRecordIterator that iterates over records that are within an
	 * address range with an optional start address within that range.  
	 * Memory addresses encoded as Absolute are not included.
	 * @param table the table to iterate.
	 * @param addrMap the address map
	 * @param minAddr the minimum address in the range.
	 * @param maxAddr tha maximum address in the range.
	 * @param startAddr the address at which to position the iterator.  The iterator will be positioned 
	 * either before or after the start address depending on the before parameter. If this parameter
	 * is null, then the iterator will start either before the min address or after the max address 
	 * depending on the before parameter.
	 * @param before if true, the iterator will be positioned before the start address, otherwise
	 * it will be positioned after the start address. If the start address is null, then if the before
	 * parameter is true, the iterator is positioned before the min. Otherwise the iterator is 
	 * positioned after the max address.
	 * @throws IOException if a database io error occurs.
	 */
	public AddressKeyRecordIterator(Table table, AddressMap addrMap, Address minAddr,
			Address maxAddr, Address startAddr, boolean before) throws IOException {
		this(table, addrMap, false, addrMap.getAddressFactory().getAddressSet(minAddr, maxAddr),
			startAddr, before);
	}

	/**
	 * Construcs a new AddressKeyRecordIterator that iterates over records that are contained in
	 * an address set with an optional start address within that set.  
	 * Memory addresses encoded as Absolute are not included.
	 * @param table the table to iterate.
	 * @param addrMap the address map
	 * @param set the address set to iterate over.
	 * @param startAddr the address at which to position the iterator.  The iterator will be positioned 
	 * either before or after the start address depending on the before parameter. If this parameter
	 * is null, then the iterator will start either before the min address or after the max address 
	 * depending on the before parameter.
	 * @param before if true, the iterator will be positioned before the start address, otherwise
	 * it will be positioned after the start address. If the start address is null, then if the before
	 * parameter is true, the iterator is positioned before the min. Otherwise the iterator is 
	 * postioned after the max address.
	 * @throws IOException if a database io error occurs.
	 */
	public AddressKeyRecordIterator(Table table, AddressMap addrMap, AddressSetView set,
			Address startAddr, boolean before) throws IOException {
		this(table, addrMap, false, set, startAddr, before);
	}

	/**
	 * Construcs a new AddressKeyRecordIterator that iterates over records that are contained in
	 * an address set with an optional start address within that set.  
	 * @param table the table to iterate.
	 * @param addrMap the address map
	 * @param absolute if true, only absolute memory address encodings are considered, otherwise 
	 * only standard/relocatable address encodings are considered.
	 * @param set the address set to iterate over or null for all addresses
	 * @param startAddr the address at which to position the iterator.  The iterator will be positioned 
	 * either before or after the start address depending on the before parameter. If this parameter
	 * is null, then the iterator will start either before the min address or after the max address 
	 * depending on the before parameter.
	 * @param before if true, the iterator will be positioned before the start address, otherwise
	 * it will be positioned after the start address. If the start address is null, then if the before
	 * parameter is true, the iterator is positioned before the min. Otherwise the iterator is 
	 * postioned after the max address.
	 * @throws IOException if a database io error occurs.
	 */
	AddressKeyRecordIterator(Table table, AddressMap addrMap, boolean absolute, AddressSetView set,
			Address startAddr, boolean before) throws IOException {

		this.table = table;

		keyRangeList = addrMap.getKeyRanges(set, absolute, false);
		keyRangeIndex = addrMap.findKeyRange(keyRangeList, startAddr);
		if (keyRangeList.size() == 0) {
			return;
		}

		if (keyRangeIndex >= 0) {
			// start address is contained within keyRangeList
			KeyRange keyRange = keyRangeList.get(keyRangeIndex);
			long key =
				absolute ? addrMap.getAbsoluteEncoding(startAddr, false) : addrMap.getKey(
					startAddr, false);
			it = table.iterator(keyRange.minKey, keyRange.maxKey, key);
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
				it = table.iterator(keyRange.minKey, keyRange.maxKey, keyRange.minKey);
				it.previous();
			}
			else {
				--keyRangeIndex;
				KeyRange keyRange = keyRangeList.get(keyRangeIndex);
				it = table.iterator(keyRange.minKey, keyRange.maxKey, keyRange.maxKey);
				it.next();
			}
		}
	}

	/**
	 * @see db.RecordIterator#hasNext()
	 */
	@Override
	public boolean hasNext() throws IOException {
		if (it == null) {
			return false;
		}
		else if (!it.hasNext()) {
			while (keyRangeIndex < (keyRangeList.size() - 1)) {
				KeyRange keyRange = keyRangeList.get(++keyRangeIndex);
				it = table.iterator(keyRange.minKey, keyRange.maxKey, keyRange.minKey);
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
	 * @see db.RecordIterator#hasPrevious()
	 */
	@Override
	public boolean hasPrevious() throws IOException {
		if (it == null) {
			return false;
		}
		else if (!it.hasPrevious()) {
			while (keyRangeIndex > 0) {
				KeyRange keyRange = keyRangeList.get(--keyRangeIndex);
				it = table.iterator(keyRange.minKey, keyRange.maxKey, keyRange.maxKey);
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
	 * @see db.RecordIterator#next()
	 */
	@Override
	public DBRecord next() throws IOException {
		if (hasNext()) {
			return it.next();
		}
		return null;
	}

	/**
	 * @see db.RecordIterator#previous()
	 */
	@Override
	public DBRecord previous() throws IOException {
		if (hasPrevious()) {
			return it.previous();
		}
		return null;
	}

	/**
	 * @see db.RecordIterator#delete()
	 */
	@Override
	public boolean delete() throws IOException {
		if (it != null) {
			return it.delete();
		}
		return false;
	}

	public Iterator<DBRecord> iterator() {
		// TODO Auto-generated method stub
		return null;
	}

}
