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
package ghidra.program.database.references;

import java.io.IOException;

import ghidra.program.database.*;
import ghidra.program.database.map.AddressMap;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.*;
import ghidra.util.BigEndianDataConverter;
import ghidra.util.DataConverter;

/**
 *
 */
abstract class RefList extends DatabaseObject {

	static volatile int BIG_REFLIST_THRESHOLD = 1700;

	protected static DataConverter converter = BigEndianDataConverter.INSTANCE;

	protected Address address;
	protected RecordAdapter adapter;
	protected AddressMap addrMap;
	protected ProgramDB program;
	protected boolean isFrom;

	RefList(long key, Address address, RecordAdapter adapter, AddressMap addrMap, ProgramDB program,
			DBObjectCache<RefList> cache, boolean isFrom) {
		super(cache, key);
		this.address = addrMap.decodeAddress(key);
		this.adapter = adapter;
		this.addrMap = addrMap;
		this.program = program;
		this.isFrom = isFrom;
	}

	abstract void addRef(Address fromAddr, Address toAddr, RefType type, int opIndex, long symbolID,
			boolean isPrimary, SourceType sourceType, boolean isOffset, boolean isShift,
			long offsetOrShift) throws IOException;

	abstract void updateRefType(Address addr, int opIndex, RefType refType) throws IOException;

	abstract ReferenceDB getRef(Address address, int opIndex) throws IOException;

	abstract boolean removeRef(Address addr, int opIndex) throws IOException;

	abstract boolean isEmpty();

	abstract boolean setPrimary(Reference ref, boolean b) throws IOException;

	abstract ReferenceIterator getRefs() throws IOException;

	abstract Reference[] getAllRefs() throws IOException;

	abstract int getNumRefs();

	abstract Reference getPrimaryRef(int opIndex) throws IOException;

	abstract void removeAll() throws IOException;

	abstract boolean setSymbolID(Reference ref, long symbolID) throws IOException;

	/**
	 * Returns true if the specified opIndex has a corresponding reference.
	 * NOTE: This is only of value for the From Refs
	 * @param opIndex
	 */
	abstract boolean hasReference(int opIndex) throws IOException;

	abstract byte getReferenceLevel();

	/**
	 * Check to see if RefList should be transitioned to a BigRefList.
	 * A replacement RefList will be returned and the corresponding adapter record
	 * updated if a transition is performed, otherwise the original
	 * RefList is returned.
	 * @param cache RefList object cache
	 * @param newSpaceRequired number of references to be added.
	 * @return original or replacement RefList
	 * @throws IOException
	 */
	public RefList checkRefListSize(DBObjectCache<RefList> cache, int newSpaceRequired)
			throws IOException {
		if (adapter != null && (getNumRefs() + newSpaceRequired) >= BIG_REFLIST_THRESHOLD) {
			cache.delete(getKey()); // remove smaller list from cache
			BigRefListV0 refList =
				new BigRefListV0(address, adapter, addrMap, program, cache, isFrom);
			refList.addRefs(getRefs());
			return refList;
		}
		return this;
	}

}
