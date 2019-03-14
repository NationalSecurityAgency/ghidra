/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import ghidra.program.model.address.Address;

import java.io.IOException;

import db.RecordIterator;

/**
 * Interface to get a record iterator. 
 * 
 */
public interface DBRecordAdapter {

	/**
	 * Get a record iterator.
	 * @param start start of iterator
	 * @param end end of iterator
	 * @param colIndex index column
	 * @throws IOException if there was a problem accessing the database
	 */
	public RecordIterator getRecords(Address start, Address end, int colIndex) throws IOException;
}
