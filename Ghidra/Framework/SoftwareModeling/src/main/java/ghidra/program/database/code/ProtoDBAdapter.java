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

import db.DBRecord;
import db.RecordIterator;

/**
 * Database adapter interface for instruction prototypes.
 */
interface ProtoDBAdapter {

	/**
	 * Returns the record associated with a specific prototype ID
	 * @param protoId
	 * @return
	 */
	DBRecord getRecord(int protoId) throws IOException;

	/**
	 * Returns a record iterator over all records.
	 * @throws IOException if a database io error occurs.
	 */
	RecordIterator getRecords() throws IOException;

	/**
	 * Returns the database version for this adapter.
	 */
	int getVersion();

	/**
	 * Returns the next key to use.
	 * @throws IOException if a database io error occurs.
	 */
	long getKey() throws IOException;

	/**
	 * Creates a new prototype record in the database.
	 * @param protoID the id for the new prototype.
	 * @param addr the address of the bytes for the prototype.
	 * @param b the bytes use to form the prototype.
	 * @param inDelaySlot true if the prototype is in a delay slot.
	 * @throws IOException if a database io error occurs.
	 */
	void createRecord(int protoID, long addr, byte[] b, boolean inDelaySlot) throws IOException;

	/**
	 * Returns the total number of prototypes in the database.
	 * @throws IOException if a database io error occurs.
	 */
	int getNumRecords() throws IOException;

	/**
	 * Deletes all prototype records from the database.
	 */
	void deleteAll() throws IOException;
}
