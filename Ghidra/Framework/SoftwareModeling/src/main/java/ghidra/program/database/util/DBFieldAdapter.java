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

import java.io.IOException;

import db.DBFieldIterator;

/**
 *
 * Interface to get a field adapter where the Field is the primary
 * key in the table.
 *  
 * 
 */
public interface DBFieldAdapter {

	/**
	 * Get the iterator over the primary key.
	 * @param start start of iterator
	 * @param end end of iterator
	 * @throws IOException if there was a problem accessing the database
	 */
	public DBFieldIterator getFields(long start, long end) throws IOException;
}
