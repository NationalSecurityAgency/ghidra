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
package ghidra.program.database.function;

import java.io.IOException;

import db.*;
import ghidra.program.database.map.AddressMap;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 * Database adapter for functions.
 */
abstract class FunctionAdapter {

	static final String FUNCTIONS_TABLE_NAME = "Function Data";

	static final int CURRENT_VERSION = FunctionAdapterV3.SCHEMA_VERSION;

	static final int RETURN_DATA_TYPE_ID_COL = 0;
	static final int STACK_PURGE_COL = 1;
	static final int STACK_RETURN_OFFSET_COL = 2;
	static final int STACK_LOCAL_SIZE_COL = 3;
	static final int FUNCTION_FLAGS_COL = 4;
	static final int CALLING_CONVENTION_ID_COL = 5;
	static final int RETURN_STORAGE_COL = 6;

	static final byte FUNCTION_VARARG_FLAG = (byte) 0x1; // Bit 0 is flag for "has vararg".
	static final byte FUNCTION_INLINE_FLAG = (byte) 0x2; // Bit 1 is flag for "is inline".
	static final byte FUNCTION_NO_RETURN_FLAG = (byte) 0x4; // Bit 2 is flag for "has no return".
	static final byte FUNCTION_CUSTOM_PARAM_STORAGE_FLAG = (byte) 0x8; // Bit 3 is flag for "has custom storage"
	static final byte FUNCTION_SIGNATURE_SOURCE = (byte) 0x30; // Bits 4-5 are storage for "signature SourceType"

	static final int FUNCTION_SIGNATURE_SOURCE_SHIFT = 4; // bit shift for flag storage of "signature SourceType"

	final static Schema FUNCTION_SCHEMA = new Schema(CURRENT_VERSION, "ID",
		new Field[] { LongField.INSTANCE, IntField.INSTANCE, IntField.INSTANCE, IntField.INSTANCE,
			ByteField.INSTANCE, ByteField.INSTANCE, StringField.INSTANCE },
		new String[] { "Return DataType ID", "StackPurge", "StackReturnOffset", "StackLocalSize",
			"Flags", "Calling Convention ID", "Return Storage" });

	protected AddressMap addrMap;

	static FunctionAdapter getAdapter(DBHandle handle, int openMode, AddressMap map,
			TaskMonitor monitor) throws VersionException, CancelledException, IOException {

		if (openMode == DBConstants.CREATE) {
			return new FunctionAdapterV3(handle, map, true);
		}
		try {
			FunctionAdapter adapter = new FunctionAdapterV3(handle, map, false);
			if (map.isUpgraded()) {
				throw new VersionException(true);
			}
			return adapter;
		}
		catch (VersionException e) {
			if (!e.isUpgradable() || openMode == DBConstants.UPDATE) {
				throw e;
			}
			FunctionAdapter adapter = findReadOnlyAdapter(handle, map);
			if (openMode == DBConstants.UPGRADE) {
				adapter = upgrade(handle, adapter, map, monitor);
			}
			return adapter;
		}
	}

	static int getVersion(DBHandle handle, AddressMap map, TaskMonitor monitor)
			throws VersionException, IOException {
		FunctionAdapter oldAdapter = FunctionAdapter.findReadOnlyAdapter(handle, map);
		return oldAdapter.getVersion();
	}

	FunctionAdapter(AddressMap map) {
		addrMap = map;
	}

	static byte getSignatureSourceFlagBits(SourceType signatureSource) {
		return (byte) (signatureSource.ordinal() << FunctionAdapter.FUNCTION_SIGNATURE_SOURCE_SHIFT);
	}

	static FunctionAdapter findReadOnlyAdapter(DBHandle handle, AddressMap map)
			throws VersionException, IOException {
		try {
			return new FunctionAdapterV3(handle, map.getOldAddressMap(), false);
		}
		catch (VersionException e1) {
		}

		try {
			return new FunctionAdapterV2(handle, map.getOldAddressMap());
		}
		catch (VersionException e1) {
		}

		try {
			return new FunctionAdapterV1(handle, map.getOldAddressMap());
		}
		catch (VersionException e1) {
		}

		return new FunctionAdapterV0(handle, map.getOldAddressMap());
	}

	static FunctionAdapter upgrade(DBHandle handle, FunctionAdapter oldAdapter, AddressMap map,
			TaskMonitor monitor) throws VersionException, IOException, CancelledException {

		DBHandle tmpHandle = new DBHandle();
		try {
			tmpHandle.startTransaction();

			monitor.setMessage("Upgrading Functions...");
			monitor.initialize(oldAdapter.getRecordCount() * 2);
			int count = 0;

			FunctionAdapter tmpAdapter = new FunctionAdapterV3(tmpHandle, map, true);
			RecordIterator it = oldAdapter.iterateFunctionRecords();
			while (it.hasNext()) {
				monitor.checkCanceled();
				DBRecord rec = it.next();
				tmpAdapter.updateFunctionRecord(rec);
				monitor.setProgress(++count);
			}
			oldAdapter.deleteTable(handle);
			FunctionAdapter newAdapter = new FunctionAdapterV3(handle, map, true);
			it = tmpAdapter.iterateFunctionRecords();
			while (it.hasNext()) {
				monitor.checkCanceled();
				DBRecord rec = it.next();
				newAdapter.updateFunctionRecord(rec);
				monitor.setProgress(++count);
			}
			return newAdapter;
		}
		finally {
			tmpHandle.close();
		}
	}

	abstract RecordIterator iterateFunctionRecords() throws IOException;

	/**
	 * @param handle
	 */
	abstract protected void deleteTable(DBHandle handle) throws IOException;

	abstract int getVersion();

	/**
	 * Returns a count of functions records.
	 * @return a count of functions records
	 */
	abstract int getRecordCount();

	/**
	 * Remove a function record.
	 * @param functionKey function key.
	 */
	abstract void removeFunctionRecord(long functionKey) throws IOException;

	/**
	 * Get a function record.
	 * @param functionKey
	 * @return Record
	 */
	abstract DBRecord getFunctionRecord(long functionKey) throws IOException;

	/**
	 * Update/Insert the specified function record.
	 * @param functionRecord
	 */
	abstract void updateFunctionRecord(DBRecord functionRecord) throws IOException;

	abstract DBRecord createFunctionRecord(long symbolID, long returnDataTypeId) throws IOException;

	abstract DBRecord translateRecord(DBRecord record);

	class TranslatedRecordIterator implements RecordIterator {
		private RecordIterator it;

		TranslatedRecordIterator(RecordIterator it) {
			this.it = it;
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
			return translateRecord(it.next());
		}

		@Override
		public DBRecord previous() throws IOException {
			return translateRecord(it.previous());
		}

		@Override
		public boolean delete() throws IOException {
			return false;
		}
	}
}
