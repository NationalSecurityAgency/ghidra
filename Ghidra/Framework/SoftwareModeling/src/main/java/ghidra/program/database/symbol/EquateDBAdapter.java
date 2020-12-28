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

import java.io.IOException;

import db.*;
import ghidra.util.exception.NotFoundException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 *
 * Adpapter to access records in the Equate table.
 *  
 * 
 */
abstract class EquateDBAdapter {

	final static String EQUATES_TABLE_NAME = "Equates";

	static final Schema EQUATES_SCHEMA =
		new Schema(0, "Key", new Field[] { StringField.INSTANCE, LongField.INSTANCE },
			new String[] { "Equate Name", "Equate Value" });

	final static int NAME_COL = 0;
	final static int VALUE_COL = 1;

	static EquateDBAdapter getAdapter(DBHandle dbHandle, int openMode, TaskMonitor monitor)
			throws VersionException, IOException {

		if (openMode == DBConstants.CREATE) {
			return new EquateDBAdapterV0(dbHandle, true);
		}

		return new EquateDBAdapterV0(dbHandle, false);
	}

	/**
	 * Get the record key for the given name.
	 * @param name name to match
	 * @throws IOException if there was a problem accessing the database
	 * @throws NotFoundException if there is no equate with the given
	 * name
	 */
	abstract long getRecordKey(String name) throws IOException, NotFoundException;

	/**
	 * Get the record for the given key.
	 * @param key the key to look up the record.
	 * @throws IOException if there is no equate with the given
	 */
	abstract DBRecord getRecord(long key) throws IOException;

	/**
	 * Remove the record with the given key.
	 * @param the key whose record is to be removed.
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract void removeRecord(long key) throws IOException;

	/**
	 * Update the table with the given record.
	 * @param record the record to update.
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract void updateRecord(DBRecord record) throws IOException;

	/**
	 * Create a new record for the equate.
	 * @param name name of the equate
	 * @param value value of the equate
	 * @return new record
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract DBRecord createEquate(String name, long value) throws IOException;

	/**
	 * Get an iterator over all the equate records.
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract RecordIterator getRecords() throws IOException;

	/**
	 * Returns true if an equate record exists with the given name
	 * @param name the name to lookup.
	 * @throws IOException if there was a problem accessing the database
	 */
	abstract boolean hasRecord(String name) throws IOException;

}
