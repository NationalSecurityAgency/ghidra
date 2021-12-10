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
package ghidra.program.database.code;

import java.io.IOException;

import db.*;
import ghidra.program.database.map.*;
import ghidra.program.database.util.DatabaseTableUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 * Version 0 adapter for the instruction table.
 */
class InstDBAdapterV1 extends InstDBAdapter {
	private static final int VERSION = 1;
	private Table instTable;
	private AddressMap addrMap;

	/**
	 * Constructor
	 * @param handle database handle
	 */
	public InstDBAdapterV1(DBHandle handle, AddressMap addrMap, boolean create) throws IOException,
			VersionException {
		this.addrMap = addrMap;
		if (create) {
			instTable = handle.createTable(INSTRUCTION_TABLE_NAME, INSTRUCTION_SCHEMA);
		}
		else {
			instTable = handle.getTable(INSTRUCTION_TABLE_NAME);
			if (instTable == null) {
				throw new VersionException("Missing Table: " + INSTRUCTION_TABLE_NAME);
			}
			if (instTable.getSchema().getVersion() != VERSION) {
				int version = instTable.getSchema().getVersion();
				if (version < VERSION) {
					throw new VersionException(true);
				}
				throw new VersionException(VersionException.NEWER_VERSION, false);
			}
		}
	}

	/**
	 * @see ghidra.program.database.code.InstDBAdapter#createInstruction(long, int)
	 */
	@Override
	void createInstruction(long addr, int protoID, byte flags) throws IOException {
		DBRecord record = INSTRUCTION_SCHEMA.createRecord(addr);
		record.setIntValue(PROTO_ID_COL, protoID);
		record.setByteValue(FLAGS_COL, flags);
		instTable.putRecord(record);
	}

	/**
	 * @see ghidra.program.database.code.InstDBAdapter#removeInstruction(long)
	 */
	@Override
	void deleteRecord(long addr) throws IOException {
		instTable.deleteRecord(addr);
	}

	/**
	 * @see ghidra.program.database.code.InstDBAdapter#getRecordAtOrAfter(long)
	 */
	@Override
	DBRecord getRecordAtOrAfter(Address addr) throws IOException {
		AddressKeyRecordIterator it = new AddressKeyRecordIterator(instTable, addrMap, addr, true);
		return it.next();
	}

	/**
	 * @see ghidra.program.database.code.InstDBAdapter#getRecord(long)
	 */
	@Override
	DBRecord getRecord(long addr) throws IOException {
		return instTable.getRecord(addr);
	}

	/**
	 * @see ghidra.program.database.code.InstDBAdapter#getRecord(ghidra.program.model.address.Address)
	 */
	@Override
	DBRecord getRecord(Address addr) throws IOException {
		return instTable.getRecord(addrMap.getKey(addr, false));
	}

	/**
	 * @see ghidra.program.database.code.InstDBAdapter#getRecordAfter(long)
	 */
	@Override
	DBRecord getRecordAfter(Address addr) throws IOException {
		AddressKeyRecordIterator it = new AddressKeyRecordIterator(instTable, addrMap, addr, false);
		return it.next();
	}

	/**
	 * @see ghidra.program.database.code.InstDBAdapter#getRecordBefore(long)
	 */
	@Override
	DBRecord getRecordBefore(Address addr) throws IOException {
		AddressKeyRecordIterator it = new AddressKeyRecordIterator(instTable, addrMap, addr, true);
		return it.previous();
	}

	/**
	 * @see ghidra.program.database.code.InstDBAdapter#getRecords(ghidra.program.model.address.Address, boolean)
	 */
	@Override
	RecordIterator getRecords(Address addr, boolean forward) throws IOException {
		return new AddressKeyRecordIterator(instTable, addrMap, addr, forward);
	}

	/**
	 * @see ghidra.program.database.code.InstDBAdapter#getRecords(ghidra.program.model.address.AddressSetView, boolean)
	 */
	@Override
	RecordIterator getRecords(AddressSetView set, boolean forward) throws IOException {
		return new AddressKeyRecordIterator(instTable, addrMap, set, forward ? set.getMinAddress()
				: set.getMaxAddress(), forward);
	}

	/**
	 * @see ghidra.program.database.code.MoveRangeAdapter#getRecords(long, long, boolean)
	 */
	@Override
	RecordIterator getRecords(Address start, Address end, boolean atStart) throws IOException {
		if (atStart) {
			return new AddressKeyRecordIterator(instTable, addrMap, start, end, start, true);
		}
		return new AddressKeyRecordIterator(instTable, addrMap, start, end, end, false);
	}

	/**
	 * @see ghidra.program.database.code.InstDBAdapter#getRecordAtOrBefore(long)
	 */
	@Override
	DBRecord getRecordAtOrBefore(Address addr) throws IOException {
		AddressKeyRecordIterator it = new AddressKeyRecordIterator(instTable, addrMap, addr, false);
		return it.previous();
	}

	/**
	 * @see ghidra.program.database.code.InstDBAdapter#getRecordCount()
	 */
	@Override
	int getRecordCount() throws IOException {
		return instTable.getRecordCount();
	}

	/**
	 * @see ghidra.program.database.code.InstDBAdapter#getKeys(long, long)
	 */
	@Override
	AddressKeyIterator getKeys(Address start, Address end, boolean atStart) throws IOException {
		if (atStart) {
			return new AddressKeyIterator(instTable, addrMap, start, end, start, true);
		}
		return new AddressKeyIterator(instTable, addrMap, start, end, end, false);
	}

	/**
	 * @see ghidra.program.database.code.InstDBAdapter#getKeys(ghidra.program.model.address.AddressSetView, boolean)
	 */
	@Override
	AddressKeyIterator getKeys(AddressSetView set, boolean forward) throws IOException {
		if (forward) {
			return new AddressKeyIterator(instTable, addrMap, set, set.getMinAddress(), true);
		}
		return new AddressKeyIterator(instTable, addrMap, set, set.getMaxAddress(), false);
	}

	/**
	 * @see ghidra.program.database.code.MoveRangeAdapter#deleteRecords(long, long)
	 */
	@Override
	boolean deleteRecords(Address start, Address end) throws IOException {
		return AddressRecordDeleter.deleteRecords(instTable, addrMap, start, end);
	}

	/**
	 * @see ghidra.program.database.code.MoveRangeAdapter#putRecord(ghidra.framework.store.db.DBRecord)
	 */
	@Override
	void putRecord(DBRecord record) throws IOException {
		instTable.putRecord(record);
	}

	/**
	 * @see ghidra.program.database.code.InstDBAdapter#getRecords()
	 */
	@Override
	RecordIterator getRecords() throws IOException {
		return new AddressKeyRecordIterator(instTable, addrMap);
	}

	/**
	 * @see ghidra.program.database.code.InstDBAdapter#updateFlags(long, byte)
	 */
	@Override
	void updateFlags(long addr, byte flags) throws IOException {
		DBRecord rec = instTable.getRecord(addr);
		rec.setByteValue(FLAGS_COL, flags);
		instTable.putRecord(rec);
	}

	/**
	 * @see ghidra.program.database.code.InstDBAdapter#moveAddressRange(ghidra.program.model.address.Address, ghidra.program.model.address.Address, long, ghidra.util.task.TaskMonitor)
	 */
	@Override
	void moveAddressRange(Address fromAddr, Address toAddr, long length, TaskMonitor monitor)
			throws CancelledException, IOException {
		DatabaseTableUtils.updateAddressKey(instTable, addrMap, fromAddr, toAddr, length, monitor);
	}

	/**
	 * @see ghidra.program.database.code.InstDBAdapter#deleteAll()
	 */
	@Override
	void deleteAll() throws IOException {
		instTable.deleteAll();
	}

}
