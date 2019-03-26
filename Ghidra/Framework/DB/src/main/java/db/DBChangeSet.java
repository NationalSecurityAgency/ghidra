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
 * <code>DBChangeSet</code> facilitates the reading and writing of application
 * level change data associated with BufferFile.
 */
public interface DBChangeSet {

	/**
	 * Read into this change set from the specified database handle.
	 * The database handle will not be retained and should be closed
	 * by the invoker of this method.
	 * @param dbh database handle
	 * @throws IOException if IO error occurs
	 */
	void read(DBHandle dbh) throws IOException;

	/**
	 * Write this change set to the specified database handle.
	 * The database handle will not be retained and should be closed
	 * by the invoker of this method.
	 * @param dbh database handle
	 * @param isRecoverySave true if this write is because of a recovery snapshot or false
	 * if due to a user save action.
	 * @throws IOException if IO error occurs
	 */
	void write(DBHandle dbh, boolean isRecoverySave) throws IOException;

}
