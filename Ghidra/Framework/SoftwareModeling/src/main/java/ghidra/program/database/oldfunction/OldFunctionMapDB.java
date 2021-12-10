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
package ghidra.program.database.oldfunction;

import db.DBHandle;
import ghidra.program.database.map.AddressMap;
import ghidra.program.database.util.SharedRangeMapDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.util.datastruct.IndexRange;
import ghidra.util.datastruct.IndexRangeIterator;

/**
 * 
 */
@SuppressWarnings("deprecation")
class OldFunctionMapDB {

	private AddressMap addrMap;
	private SharedRangeMapDB rangeMap;

	OldFunctionMapDB(DBHandle dbHandle, OldFunctionManager fnMgr, AddressMap addrMap) {

		this.addrMap = addrMap;

		rangeMap = new SharedRangeMapDB(dbHandle, "Functions", fnMgr, false);
	}

	/**
	 * Permanently dispose map and all resource data
	 */
	synchronized void dispose() {
		if (rangeMap != null) {
			rangeMap.dispose();
			rangeMap = null;
		}
	}

	/**
	 * Get the address set which makes up a function.
	 * @param functionKey the function key
	 * @return the addresses
	 */
	synchronized AddressSetView getBody(long functionKey) {
		AddressSet body = new AddressSet();
		IndexRangeIterator iter = rangeMap.getValueRangeIterator(functionKey);
		while (iter.hasNext()) {
			IndexRange range = iter.next();
			body.addRange(addrMap.decodeAddress(range.getStart()),
				addrMap.decodeAddress(range.getEnd()));
		}
		return body;
	}

//	/**
//	 * Get the function key for the first function containing the specified address.
//	 * @param addr
//	 * @return function key.
//	 * @throws NotFoundException if no function exists for the addr specified.
//	 */
//	synchronized long getFirstFunctionContaining(Address addr) throws NotFoundException {
//		long index = addrMap.getKey(addr, false);
//		Iterator<Field> iter = rangeMap.getValueIterator(index, index);
//		if (!iter.hasNext()) {
//			throw new NotFoundException();
//		}
//		return ((LongField)iter.next()).getLongValue();
//	}
//
//	/**
//	 * Get all function keys whose body contains the specified address.
//	 * @param addr
//	 * @return a LongField function key iterator.
//	 */
//	synchronized Iterator<Field> getFunctionsContaining(Address addr) {
//		long index = addrMap.getKey(addr, false);
//		return rangeMap.getValueIterator(index, index);
//	}
//
//	/**
//	 * Get all function keys whose body overlaps the specified address set.
//	 * @param set
//	 * @return a LongField function key iterator.
//	 */
//	synchronized Iterator<Long> getFunctionsOverlapping(AddressSetView set) {
//
//		HashSet<Long> idSet = new HashSet<Long>();
//		for (KeyRange range : addrMap.getKeyRanges(set)) {
//			Iterator<Field> idIterator = rangeMap.getValueIterator(range.minKey, range.maxKey);
//			while (idIterator.hasNext()) {
//				LongField id = (LongField)idIterator.next();
//				idSet.add(id.getLongValue());
//			}
//		}
//		return idSet.iterator();
//	}

}
