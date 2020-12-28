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
package ghidra.program.database.symbol;

import db.DBRecord;
import ghidra.program.database.DBObjectCache;
import ghidra.program.database.DatabaseObject;
import ghidra.program.database.map.AddressMap;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.EquateReference;

/**
 * Database object for the equate references.
 * 
 * 
 */
class EquateRefDB extends DatabaseObject implements EquateReference {

	private DBRecord record;
	private EquateManager equateMgr;
	private AddressMap addrMap;

	/**
	 * Constructor
	 * @param equateMgr
	 * @param cache
	 * @param record
	 */
	EquateRefDB(EquateManager equateMgr, DBObjectCache<EquateRefDB> cache, DBRecord record) {
		super(cache, record.getKey());
		addrMap = equateMgr.getAddressMap();
		this.equateMgr = equateMgr;
		this.record = record;
	}

	@Override
	protected boolean refresh() {
		DBRecord rec = equateMgr.getEquateRefRecord(key);
		if (rec == null) {
			return false;
		}
		record = rec;
		return true;
	}

	long getEquateID() {
		return record.getLongValue(EquateRefDBAdapter.EQUATE_ID_COL);
	}

	public Address getAddress() {
		checkIsValid();
		long addr = record.getLongValue(EquateRefDBAdapter.ADDR_COL);
		return addrMap.decodeAddress(addr);
	}

	public short getOpIndex() {
		checkIsValid();
		return record.getShortValue(EquateRefDBAdapter.OP_INDEX_COL);
	}

	public long getDynamicHashValue() {
		checkIsValid();
		return record.getLongValue(EquateRefDBAdapter.HASH_COL);
	}

	DBRecord getRecord() {
		return record;
	}
}
