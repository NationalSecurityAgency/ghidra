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
/*
 * Created on May 4, 2004
 *
 * To change the template for this generated file go to
 * Window&gt;Preferences&gt;Java&gt;Code Generation&gt;Code and Comments
 */
package ghidra.program.database.data;

import java.io.IOException;

import db.*;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 * Adapter to access the Enumeration data type values tables.
 */
abstract class EnumValueDBAdapter implements RecordTranslator {

	static final String ENUM_VALUE_TABLE_NAME = "Enumeration Values";
	static final Schema ENUM_VALUE_SCHEMA = EnumValueDBAdapterV1.SCHEMA;

	// Enum Value Columns
	static final int ENUMVAL_NAME_COL = 0;
	static final int ENUMVAL_VALUE_COL = 1;
	static final int ENUMVAL_ID_COL = 2;
	static final int ENUMVAL_COMMENT_COL = 3;

	/**
	 * Gets an adapter for working with the enumeration data type values database table. The adapter is based
	 * on the version of the database associated with the specified database handle and the openMode.
	 * @param handle handle to the database to be accessed.
	 * @param openMode the mode this adapter is to be opened for (CREATE, UPDATE, READ_ONLY, UPGRADE).
	 * @param monitor the monitor to use for displaying status or for canceling.
	 * @return the adapter for accessing the table of enumeration data type values.
	 * @throws VersionException if the database handle's version doesn't match the expected version.
	 * @throws IOException if there is trouble accessing the database.
	 */
	static EnumValueDBAdapter getAdapter(DBHandle handle, int openMode, TaskMonitor monitor)
			throws VersionException, IOException {
		if (openMode == DBConstants.CREATE) {
			return new EnumValueDBAdapterV1(handle, true);
		}
		try {
			return new EnumValueDBAdapterV1(handle, false);
		}
		catch (VersionException e) {
			if (!e.isUpgradable() || openMode == DBConstants.UPDATE) {
				throw e;
			}
			EnumValueDBAdapter adapter = findReadOnlyAdapter(handle);
			if (openMode == DBConstants.UPGRADE) {
				adapter = upgrade(handle, adapter);
			}
			return adapter;
		}
	}

	static EnumValueDBAdapter findReadOnlyAdapter(DBHandle handle) {
		try {
			return new EnumValueDBAdapterV0(handle);
		}
		catch (VersionException e) {
			return new EnumValueDBAdapterNoTable(handle);
		}
	}

	/**
	 * Upgrades the Enumeration Data Type Values table from the oldAdapter's version to the current
	 * version.
	 * @param handle handle to the database whose table is to be upgraded to a newer version.
	 * @param oldAdapter the adapter for the existing table to be upgraded.
	 * @return the adapter for the new upgraded version of the table.
	 * @throws VersionException if the the table's version does not match the expected version
	 * for this adapter.
	 * @throws IOException if the database can't be read or written.
	 */
	static EnumValueDBAdapter upgrade(DBHandle handle, EnumValueDBAdapter oldAdapter)
			throws VersionException, IOException {

		DBHandle tmpHandle = new DBHandle();
		long id = tmpHandle.startTransaction();
		EnumValueDBAdapter tmpAdapter = null;
		try {
			tmpAdapter = new EnumValueDBAdapterV1(tmpHandle, true);
			RecordIterator it = oldAdapter.getRecords();
			while (it.hasNext()) {
				DBRecord rec = it.next();
				tmpAdapter.updateRecord(rec);
			}
			oldAdapter.deleteTable(handle);
			EnumValueDBAdapter newAdapter = new EnumValueDBAdapterV1(handle, true);
			it = tmpAdapter.getRecords();
			while (it.hasNext()) {
				DBRecord rec = it.next();
				newAdapter.updateRecord(rec);
			}
			return newAdapter;
		}
		finally {
			tmpHandle.endTransaction(id, true);
			tmpHandle.close();
		}
	}

	/**
	 * Create new enum value record corresponding to specified enum datatype ID
	 * @param enumID enum datatype ID
	 * @param name value name
	 * @param value numeric value
	 * @param comment the field comment
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract void createRecord(long enumID, String name, long value, String comment)
			throws IOException;

	/**
	 * Get enum value record which corresponds to specified value record ID
	 * @param valueID value record ID
	 * @return value record or null
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract DBRecord getRecord(long valueID) throws IOException;

	/**
	 * Returns an iterator over the value records inside of this Enum
	 * @return the iterator
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract RecordIterator getRecords() throws IOException;

	/**
	 * Deletes the table; used when upgrading
	 * @param handle the handle used to delete the table
	 * @throws IOException if there was a problem accessing the database
	 */
	void deleteTable(DBHandle handle) throws IOException {
		handle.deleteTable(ENUM_VALUE_TABLE_NAME);
	}

	/**
	 * Remove the record for the given enum Value ID.
	 * @param valueID ID of the value record to delete
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract void removeRecord(long valueID) throws IOException;

	/**
	 * Updates the enum data type values table with the provided record.
	 * @param record the new record
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract void updateRecord(DBRecord record) throws IOException;

	/**
	 * Get enum value record IDs which correspond to specified enum datatype ID
	 * @param enumID enum datatype ID
	 * @return enum value record IDs as LongField values within Field array
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract Field[] getValueIdsInEnum(long enumID) throws IOException;
}
