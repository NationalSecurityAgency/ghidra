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
package ghidra.program.database.sourcemap;

import java.io.IOException;

import db.*;
import ghidra.framework.data.OpenMode;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 * Base class for adapters to access the Source File table.  The table has one column, which stores
 * the path of the source file (as a String).
 */
abstract class SourceFileAdapter {

	static final String TABLE_NAME = "SourceFiles";
	static final int PATH_COL = SourceFileAdapterV0.V0_PATH_COL;
	static final int ID_TYPE_COL = SourceFileAdapterV0.V0_ID_TYPE_COL;
	static final int ID_COL = SourceFileAdapterV0.V0_ID_COL;

	/**
	 * Creates an adapter for the source file table.
	 * @param handle database handle
	 * @param openMode open mode
	 * @param monitor task monitor
	 * @return adapter for table
	 * @throws VersionException if version incompatible
	 */
	static SourceFileAdapter getAdapter(DBHandle handle, OpenMode openMode, TaskMonitor monitor)
			throws VersionException {
		return new SourceFileAdapterV0(handle, openMode);
	}

	/**
	 * Returns a {@link RecordIterator} for this table.
	 * @return record iterator
	 * @throws IOException on db error
	 */
	abstract RecordIterator getRecords() throws IOException;

	/**
	 * Returns the {@link DBRecord} corresponding to {@code sourceFile}, or {@code null} if
	 * no such record exists.
	 * @param sourceFile source file
	 * @return record or null
	 * @throws IOException on db error
	 */
	abstract DBRecord getRecord(SourceFile sourceFile) throws IOException;

	/**
	 * Returns the {@link DBRecord} with key {@code id}, or {@code null} if no such record exists.
	 * @param id id
	 * @return record or null
	 * @throws IOException on db error
	 */
	abstract DBRecord getRecord(long id) throws IOException;

	/**
	 * Creates a {@link DBRecord} for {@link SourceFile} {@code sourceFile}. If a record for 
	 * that source file already exists, the existing record is returned.  
	 * @param sourceFile source file
	 * @return db record
	 * @throws IOException on db error
	 */
	abstract DBRecord createSourceFileRecord(SourceFile sourceFile) throws IOException;

	/**
	 * Deletes the record with id {@code id} from the database.
	 * @param id id to delete
	 * @return true if deleted successfully
	 * @throws IOException on database error
	 */
	abstract boolean removeSourceFileRecord(long id) throws IOException;

}
