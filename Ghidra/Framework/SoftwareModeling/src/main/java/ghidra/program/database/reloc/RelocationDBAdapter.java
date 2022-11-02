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
package ghidra.program.database.reloc;

import java.io.IOException;

import db.*;
import ghidra.program.database.map.AddressMap;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

abstract class RelocationDBAdapter {

	// History:
	//  V1 - added Type
	//  V2 - added Value
	//  V3 - added Bytes
	//  V4 - added Name, switched Value to binary coded long[] from long
	//  V5 - moved Addr key to column and indexed, use one-up key

	final static int ADDR_COL = 0; // indexed
	final static int TYPE_COL = 1;
	final static int VALUE_COL = 2;
	final static int BYTES_COL = 3;
	final static int SYMBOL_NAME_COL = 4;

	final static String TABLE_NAME = "Relocations";

	final static Schema SCHEMA = new Schema(
		RelocationDBAdapterV5.VERSION, "Index", new Field[] { LongField.INSTANCE, IntField.INSTANCE,
			BinaryField.INSTANCE, BinaryField.INSTANCE, StringField.INSTANCE },
		new String[] { "Address", "Type", "Values", "Bytes", "Symbol Name" });

	static RelocationDBAdapter getAdapter(DBHandle dbHandle, int openMode, AddressMap addrMap,
			TaskMonitor monitor) throws VersionException, IOException {
		try {
			return new RelocationDBAdapterV5(dbHandle, addrMap, openMode == DBConstants.CREATE);
		}
		catch (VersionException e) {
			if (!e.isUpgradable() || openMode == DBConstants.UPDATE) {
				throw e;
			}
			RelocationDBAdapter adapter = findReadOnlyAdapter(dbHandle, addrMap);
			if (openMode == DBConstants.UPGRADE) {
				adapter = upgrade(dbHandle, addrMap, adapter, monitor);
			}
			return adapter;
		}
	}

	private static RelocationDBAdapter findReadOnlyAdapter(DBHandle handle, AddressMap addrMap)
			throws IOException, VersionException {
		try {
			return new RelocationDBAdapterV4(handle, addrMap);
		}
		catch (VersionException e) {
			// try the next version
		}
		try {
			return new RelocationDBAdapterV3(handle, addrMap);
		}
		catch (VersionException e) {
			// try the next version
		}
		try {
			return new RelocationDBAdapterV2(handle, addrMap);
		}
		catch (VersionException e) {
			// try the next version			
		}
		try {
			return new RelocationDBAdapterV1(handle, addrMap);
		}
		catch (VersionException e) {
			// try the next version			
		}
		return new RelocationDBAdapterNoTable(handle);
	}

	private static RelocationDBAdapter upgrade(DBHandle dbHandle, AddressMap addrMap,
			RelocationDBAdapter oldAdapter, TaskMonitor monitor)
			throws VersionException, IOException {

		AddressMap oldAddrMap = addrMap.getOldAddressMap();

		DBHandle tmpHandle = new DBHandle();
		try {
			tmpHandle.startTransaction();

			RelocationDBAdapter tmpAdapter = new RelocationDBAdapterV5(tmpHandle, addrMap, true);
			RecordIterator iter = oldAdapter.iterator();
			while (iter.hasNext()) {
				DBRecord rec = iter.next();
				// decode with old address map
				Address addr = oldAddrMap.decodeAddress(rec.getLongValue(ADDR_COL));
				BinaryCodedField values =
					new BinaryCodedField((BinaryField) rec.getFieldValue(VALUE_COL));
				tmpAdapter.add(addr, rec.getIntValue(TYPE_COL),
					values.getLongArray(), rec.getBinaryData(BYTES_COL),
					rec.getString(SYMBOL_NAME_COL));
			}

			dbHandle.deleteTable(TABLE_NAME);

			RelocationDBAdapterV5 newAdapter = new RelocationDBAdapterV5(dbHandle, addrMap, true);

			iter = tmpAdapter.iterator();
			while (iter.hasNext()) {
				DBRecord rec = iter.next();
				newAdapter.add(rec);
			}
			return newAdapter;
		}
		finally {
			tmpHandle.close();
		}
	}

//==================================================================================================
// Adapter Required Methods
//==================================================================================================	

	/**
	 * Add new relocation record
	 * @param addr relocation address
	 * @param type relocation type
	 * @param values relocation value (e.g., symbol index)
	 * @param bytes original memory bytes
	 * @param symbolName symbol name
	 * @throws IOException if a database error occurs
	 */
	abstract void add(Address addr, int type, long[] values, byte[] bytes, String symbolName)
			throws IOException;

	/**
	 * Iterator over all records in address order.
	 * @return record iterator
	 * @throws IOException if a database error occurs
	 */
	abstract RecordIterator iterator() throws IOException;

	/**
	 * Iterator over all relocation records in address order constrained by the specified address set.
	 * @param set address set constraint
	 * @return record iterator
	 * @throws IOException if a database error occurs
	 */
	abstract RecordIterator iterator(AddressSetView set) throws IOException;

	/**
	 * Iterate over relocation records starting at specified start address.
	 * @param start start address
	 * @return relocation record iterator
	 * @throws IOException if a database error occurs
	 */
	abstract RecordIterator iterator(Address start) throws IOException;

	/**
	 * Get the total number of relocation records
	 * @return total number of relocation records
	 */
	abstract int getRecordCount();

	/**
	 * Translate relocation record to latest schema format
	 * @param rec old record requiring translation
	 * @return translated relocation record
	 */
	abstract DBRecord adaptRecord(DBRecord rec);

//==================================================================================================
// Inner Classes
//==================================================================================================	

	class RecordIteratorAdapter implements RecordIterator {
		RecordIterator it;

		RecordIteratorAdapter(RecordIterator it) {
			this.it = it;
		}

		@Override
		public boolean delete() throws IOException {
			return it.delete();
		}

		@Override
		public boolean hasNext() throws IOException {
			return it.hasNext();
		}

		@Override
		public boolean hasPrevious() throws IOException {
			return it.hasPrevious();
		}

		@Override
		public DBRecord next() throws IOException {
			DBRecord rec = it.next();
			return adaptRecord(rec);
		}

		@Override
		public DBRecord previous() throws IOException {
			DBRecord rec = it.previous();
			return adaptRecord(rec);
		}

	}
}
