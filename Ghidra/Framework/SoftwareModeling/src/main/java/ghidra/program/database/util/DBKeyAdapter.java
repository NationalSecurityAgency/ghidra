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

import db.DBLongIterator;

/**
 * Adapter to get an iterator over keys in a table.
 * 
 * 
 */
public interface DBKeyAdapter {

	/**
	 * Get an iterator over the keys in the given range.
	 * @param start start of range
	 * @param end end of range (inclusive)
	 * @throws IOException if there was a problem accessing the database
	 */
	public DBLongIterator getKeys(Address start, Address end) throws IOException;
}
