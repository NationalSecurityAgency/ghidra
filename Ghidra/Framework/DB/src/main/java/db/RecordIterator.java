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
package db;

import java.io.IOException;

/**
 * <code>RecordIterator</code> provides the ability to iterate over
 * data records within a table.
 */
public interface RecordIterator {
	
	/**
	 * Return true if a Record is available in the forward direction.
	 * @throws IOException thrown if an IO error occurs
	 */
	public boolean hasNext() throws IOException;
	
	/**
	 * Return true if a Record is available in the reverse direction
	 * @throws IOException thrown if an IO error occurs
	 */
	public boolean hasPrevious() throws IOException;
	
	/**
	 * Return the nexy Record or null if one is not available.
	 * @throws IOException thrown if an IO error occurs
	 */
	public DBRecord next() throws IOException;
	
	/**
	 * Return the previous Record or null if one is not available.
	 * @throws IOException thrown if an IO error occurs
	 */
	public DBRecord previous() throws IOException;
	
	/**
	 * Delete the last Record read via the next or previous methods.
	 * @return true if record was successfully deleted.
	 * @throws IOException thrown if an IO error occurs.
	 */
	public boolean delete() throws IOException;
}
