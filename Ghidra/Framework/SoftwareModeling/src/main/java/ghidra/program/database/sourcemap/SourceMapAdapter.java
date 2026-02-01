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
import ghidra.program.database.map.AddressMapDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.sourcemap.SourceFileManager;
import ghidra.program.model.sourcemap.SourceMapEntry;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 * Base class for adapters to access the Source Map table.
 * <p>
 *  Each entry in the table corresponds to a single {@link SourceMapEntry} and so records
 *  a {@link SourceFile}, a line number, a base address, and a length.
 *  <p>
 *  There are a number of restrictions on a {@link SourceMapEntry}, which are listed in that 
 *  interface's top-level documentation.  It is the responsibility of the {@link SourceFileManager}
 *  to enforce these restrictions.
 */
abstract class SourceMapAdapter {

	static final String TABLE_NAME = "SourceMap";
	static final int FILE_LINE_COL = SourceMapAdapterV0.V0_FILE_LINE_COL;
	static final int BASE_ADDR_COL = SourceMapAdapterV0.V0_BASE_ADDR_COL;
	static final int LENGTH_COL = SourceMapAdapterV0.V0_LENGTH_COL;

	/**
	 * Creates an adapter for the Source Map table.
	 * @param dbh database handle
	 * @param addrMap address map
	 * @param openMode mode
	 * @param monitor task monitor
	 * @return adapter for table
	 * @throws VersionException if version incompatible
	 */
	static SourceMapAdapter getAdapter(DBHandle dbh, AddressMapDB addrMap, OpenMode openMode,
			TaskMonitor monitor) throws VersionException {
		return new SourceMapAdapterV0(dbh, addrMap, openMode);
	}

	/**
	 * Removes a record from the table
	 * @param key key of record to remove.
	 * @return true if the record was deleted successfully
	 * @throws IOException if database error occurs
	 */
	abstract boolean removeRecord(long key) throws IOException;

	/**
	 * Returns a {@link RecordIterator} based at {@code addr}.
	 * @param addr starting address
	 * @param before if true, initial position is before addr, otherwise after
	 * @return iterator
	 * @throws IOException if database error occurs
	 */
	abstract RecordIterator getSourceMapRecordIterator(Address addr, boolean before)
			throws IOException;

	/**
	 * Returns a {@link RecordIterator} over all records for the source file with
	 * id {@code id}, subject to the line bounds {@code minLine} and {@code maxLine}
	 * @param fileId id of source file
	 * @param minLine minimum line number
	 * @param maxLine maximum line number
	 * @return iterator
	 * @throws IOException if database error occurs
	 */
	abstract RecordIterator getRecordsForSourceFile(long fileId, int minLine, int maxLine)
			throws IOException;

	/**
	 * Adds an entry to the source map table.  This method assumes that no address
	 * in the associated range has already been associated with this source file and
	 * line number.
	 * @param fileId source file id
	 * @param lineNum line number
	 * @param baseAddr minimum address of range
	 * @param length number of addresses in range
	 * @return record
	 * @throws IOException if database error occurs
	 */
	abstract DBRecord addMapEntry(long fileId, int lineNum, Address baseAddr, long length)
			throws IOException;

	/**
	 * Updates all appropriate entries in the table when an address range is moved. 
	 * @param fromAddr from address
	 * @param toAddr to address
	 * @param length number of addresses in moved range
	 * @param monitor task monitor
	 * @throws CancelledException if task cancelled
	 * @throws IOException if database error occurs
	 */
	abstract void moveAddressRange(Address fromAddr, Address toAddr, long length,
			TaskMonitor monitor) throws CancelledException, IOException;
}
