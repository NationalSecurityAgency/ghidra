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

import ghidra.program.database.map.*;
import ghidra.program.model.address.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;

import db.*;

/**
 * Version 0 adapter for the instruction table.
 */
class InstDBAdapterV0 extends InstDBAdapter {

	private Table instTable;
	private AddressMap addrMap;

	/**
	 * Constructor
	 * @param handle database handle
	 */
	@SuppressWarnings("unused")
	InstDBAdapterV0(DBHandle handle, AddressMap addrMap) throws IOException, VersionException {
		this.addrMap = addrMap.getOldAddressMap();
		instTable = handle.getTable(INSTRUCTION_TABLE_NAME);
		if (instTable == null) {
			throw new VersionException("Missing Table: " + INSTRUCTION_TABLE_NAME);
		}
		if (instTable.getSchema().getVersion() != 0) {
			throw new VersionException(VersionException.NEWER_VERSION, false);
		}
	}

	/**
	 * @see ghidra.program.database.code.InstDBAdapter#createInstruction(long, int)
	 */
	@Override
	void createInstruction(long addr, int protoID, byte flags) throws IOException {
		throw new UnsupportedOperationException();
	}

	/**
	 * @see ghidra.program.database.code.InstDBAdapter#removeInstruction(long)
	 */
	@Override
	void deleteRecord(long addr) throws IOException {
		throw new UnsupportedOperationException();
	}

	/**
	 * @see ghidra.program.database.code.InstDBAdapter#deleteAll()
	 */
	@Override
	void deleteAll() throws IOException {
		throw new UnsupportedOperationException();
	}

	/**
	 * @see ghidra.program.database.code.InstDBAdapter#getRecordAtOrAfter(long)
	 */
	@Override
	DBRecord getRecordAtOrAfter(Address start) throws IOException {
		RecordIterator it = new AddressKeyRecordIterator(instTable, addrMap, start, true);
		return adaptRecord(it.next());
	}

	/**
	 * @see ghidra.program.database.code.InstDBAdapter#getRecordAtOrBefore(long)
	 */
	@Override
	DBRecord getRecordAtOrBefore(Address addr) throws IOException {
		RecordIterator it = new AddressKeyRecordIterator(instTable, addrMap, addr, false);
		return adaptRecord(it.previous());
	}

	/**
	 * @see ghidra.program.database.code.InstDBAdapter#getRecord(long)
	 */
	@Override
	DBRecord getRecord(Address addr) throws IOException {
		return getRecord(addrMap.getKey(addr, false));
	}

	/**
	 * @see ghidra.program.database.code.InstDBAdapter#getRecord(long)
	 */
	@Override
	DBRecord getRecord(long addr) throws IOException {
		return adaptRecord(instTable.getRecord(addr));
	}

	/**
	 * @see ghidra.program.database.code.InstDBAdapter#getRecordAfter(long)
	 */
	@Override
	DBRecord getRecordAfter(Address addr) throws IOException {
		RecordIterator it = new AddressKeyRecordIterator(instTable, addrMap, addr, false);
		return adaptRecord(it.next());
	}

	/**
	 * @see ghidra.program.database.code.InstDBAdapter#getRecordBefore(long)
	 */
	@Override
	DBRecord getRecordBefore(Address addr) throws IOException {
		RecordIterator it = new AddressKeyRecordIterator(instTable, addrMap, addr, true);
		return adaptRecord(it.previous());
	}

	/**
	 * @see ghidra.program.database.code.InstDBAdapter#getRecords(long)
	 */
	@Override
	RecordIterator getRecords(Address addr, boolean forward) throws IOException {
		return new RecordIteratorAdapter(new AddressKeyRecordIterator(instTable, addrMap, addr,
			forward));
	}

	/**
	 * @see ghidra.program.database.code.MoveRangeAdapter#getRecords(long, long, boolean)
	 */
	@Override
	RecordIterator getRecords(Address start, Address end, boolean atStart) throws IOException {
		return new RecordIteratorAdapter(new AddressKeyRecordIterator(instTable, addrMap,
			atStart ? start : end, atStart ? true : false));
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
		throw new UnsupportedOperationException();
	}

	/**
	 * @see ghidra.program.database.code.MoveRangeAdapter#putRecord(ghidra.framework.store.db.DBRecord)
	 */
	@Override
	void putRecord(DBRecord record) throws IOException {
		throw new UnsupportedOperationException();
	}

	/**
	 * @see ghidra.program.database.code.InstDBAdapter#getRecords()
	 */
	@Override
	RecordIterator getRecords() throws IOException {
		return new RecordIteratorAdapter(new AddressKeyRecordIterator(instTable, addrMap));
	}

	/**
	 * @see ghidra.program.database.code.InstDBAdapter#getRecords(ghidra.program.model.address.AddressSetView, boolean)
	 */
	@Override
	RecordIterator getRecords(AddressSetView set, boolean forward) throws IOException {
		return new RecordIteratorAdapter(new AddressKeyRecordIterator(instTable, addrMap, set,
			forward ? set.getMinAddress() : set.getMaxAddress(), forward));
	}

	private DBRecord adaptRecord(DBRecord rec) {
		if (rec == null)
			return null;
		DBRecord newRec = INSTRUCTION_SCHEMA.createRecord(rec.getKey());
		newRec.setIntValue(0, rec.getIntValue(0));
		newRec.setByteValue(1, (byte) 0);
		return newRec;
	}

	class RecordIteratorAdapter implements RecordIterator {
		RecordIterator it;

		RecordIteratorAdapter(RecordIterator it) {
			this.it = it;
		}

		/**
		 * @see ghidra.framework.store.db.RecordIterator#delete()
		 */
		public boolean delete() throws IOException {
			return false;
		}

		/**
		 * @see ghidra.framework.store.db.RecordIterator#hasNext()
		 */
		public boolean hasNext() throws IOException {
			return it.hasNext();
		}

		/**
		 * @see ghidra.framework.store.db.RecordIterator#hasPrevious()
		 */
		public boolean hasPrevious() throws IOException {
			return it.hasPrevious();
		}

		/**
		 * @see ghidra.framework.store.db.RecordIterator#next()
		 */
		public DBRecord next() throws IOException {
			DBRecord rec = it.next();
			return adaptRecord(rec);
		}

		/**
		 * @see ghidra.framework.store.db.RecordIterator#previous()
		 */
		public DBRecord previous() throws IOException {
			DBRecord rec = it.previous();
			return adaptRecord(rec);
		}

	}

	/**
	 * @see ghidra.program.database.code.InstDBAdapter#updateFlags(long, byte)
	 */
	@Override
	void updateFlags(long addr, byte flags) throws IOException {
		throw new UnsupportedOperationException();
	}

	/**
	 * @see ghidra.program.database.code.InstDBAdapter#moveAddressRange(ghidra.program.model.address.Address, ghidra.program.model.address.Address, long, ghidra.util.task.TaskMonitor)
	 */
	@Override
	void moveAddressRange(Address fromAddr, Address toAddr, long length, TaskMonitor monitor)
			throws CancelledException, IOException {
		throw new UnsupportedOperationException();
	}

}
