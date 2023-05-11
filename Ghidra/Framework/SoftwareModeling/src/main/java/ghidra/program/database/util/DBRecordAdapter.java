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
package ghidra.program.database.util;

import java.io.IOException;

import db.RecordIterator;

/**
 * Interface to get a record iterator. 
 * 
 */
public interface DBRecordAdapter {

	/**
	 * Get a record iterator for all records.
	 * @return record iterator
	 * @throws IOException if there was a problem accessing the database
	 */
	public RecordIterator getRecords() throws IOException;

	/**
	 * Get the number of records in table
	 * @return total record count
	 */
	public int getRecordCount();
}
