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

	final static int TYPE_COL = 0;
	final static int VALU_COL = 1;
	final static int BYTES_COL = 2;
	final static int SYMBOL_NAME_COL = 3;

	final static String TABLE_NAME = "Relocations";

	final static Schema SCHEMA = new Schema(
		RelocationDBAdapterV4.VERSION, "Address", new Field[] { IntField.INSTANCE,
			BinaryField.INSTANCE, BinaryField.INSTANCE, StringField.INSTANCE },
		new String[] { "Type", "Values", "Bytes", "Symbol Name" });

	static RelocationDBAdapter getAdapter(DBHandle dbHandle, int openMode, AddressMap addrMap,
			TaskMonitor monitor) throws VersionException, IOException {

		if (openMode == DBConstants.CREATE) {
			return new RelocationDBAdapterV4(dbHandle, addrMap, true);
		}

		try {
			RelocationDBAdapter adapter = new RelocationDBAdapterV4(dbHandle, addrMap, false);
			if (addrMap.isUpgraded()) {
				throw new VersionException(true);
			}
			return adapter;
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
			throws IOException {
		try {
			return new RelocationDBAdapterV3(handle, addrMap, false);
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
		return new RelocationDBAdapterNoTable();
	}

	private static RelocationDBAdapter upgrade(DBHandle dbHandle, AddressMap addrMap,
			RelocationDBAdapter oldAdapter, TaskMonitor monitor)
			throws VersionException, IOException {

		AddressMap oldAddrMap = addrMap.getOldAddressMap();

		DBHandle tmpHandle = new DBHandle();
		try {
			tmpHandle.startTransaction();

			RelocationDBAdapter tmpAdapter = new RelocationDBAdapterV4(tmpHandle, addrMap, true);
			RecordIterator iter = oldAdapter.iterator();
			while (iter.hasNext()) {
				DBRecord rec = iter.next();
				Address addr = oldAddrMap.decodeAddress(rec.getKey());
				BinaryCodedField values =
					new BinaryCodedField((BinaryField) rec.getFieldValue(VALU_COL));
				tmpAdapter.add(addrMap.getKey(addr, true), rec.getIntValue(TYPE_COL),
					values.getLongArray(), null /* bytes */, null /* symbol name */);
			}

			dbHandle.deleteTable(TABLE_NAME);
			RelocationDBAdapter newAdapter = new RelocationDBAdapterV4(dbHandle, addrMap, true);

			iter = tmpAdapter.iterator();
			while (iter.hasNext()) {
				DBRecord rec = iter.next();
				BinaryCodedField values =
					new BinaryCodedField((BinaryField) rec.getFieldValue(VALU_COL));
				newAdapter.add(rec.getKey(), rec.getIntValue(TYPE_COL), values.getLongArray(),
					null /* bytes */, null /* symbol name */);
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

	abstract void add(long addrKey, int type, long[] values, byte[] bytes, String symbolName)
			throws IOException;

	abstract void remove(long addrKey) throws IOException;

	abstract DBRecord get(long addrKey) throws IOException;

	abstract RecordIterator iterator() throws IOException;

	abstract RecordIterator iterator(AddressSetView set) throws IOException;

	abstract RecordIterator iterator(Address start) throws IOException;

	abstract int getVersion();

	abstract int getRecordCount();

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
