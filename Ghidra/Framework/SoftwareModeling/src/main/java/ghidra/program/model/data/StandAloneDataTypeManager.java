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
package ghidra.program.model.data;

import java.io.IOException;
import java.util.LinkedList;

import db.DBConstants;
import generic.jar.ResourceFile;
import ghidra.program.database.data.DataTypeManagerDB;
import ghidra.util.InvalidNameException;
import ghidra.util.task.TaskMonitor;

/**
 * Basic implementation of the DataTypeManger interface
 */
public class StandAloneDataTypeManager extends DataTypeManagerDB {

	protected String name;
	private int transactionCount;
	private Long transaction;

	/**
	 * Default constructor for temporary data-type manager.
	 * @param rootName Name of the root category.
	 */
	public StandAloneDataTypeManager(String rootName) {
		super();
		this.name = rootName;
	}

	/**
	 * Constructor for a data-type manager backed by a packed database file.
	 * When opening for UPDATE an automatic upgrade will be performed if required.
	 * @param packedDbfile packed datatype archive file (i.e., *.gdt resource).
	 * @param openMode open mode CREATE, READ_ONLY or UPDATE (see {@link DBConstants})
	 * @throws IOException a low-level IO error.  This exception may also be thrown
	 * when a version error occurs (cause is VersionException).
	 */
	protected StandAloneDataTypeManager(ResourceFile packedDbfile, int openMode)
			throws IOException {
		super(packedDbfile, openMode);
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public void setName(String name) throws InvalidNameException {
		if (name == null || name.length() == 0) {
			throw new InvalidNameException("Name is invalid: " + name);
		}
		this.name = name;

		defaultListener.categoryRenamed(this, CategoryPath.ROOT, CategoryPath.ROOT);
	}

	@Override
	public synchronized int startTransaction(String description) {
		if (transaction == null) {
			transaction = new Long(dbHandle.startTransaction());
		}
		transactionCount++;
		return transaction.intValue();

	}

	@Override
	public void flushEvents() {
		// do nothing
	}

	@Override
	public synchronized void endTransaction(int transactionID, boolean commit) {
		if (transaction == null) {
			throw new IllegalStateException("No Transaction Open");
		}
		if (transaction.intValue() != transactionID) {
			throw new IllegalArgumentException("Transaction id does not match current transaction");
		}
		if (--transactionCount == 0) {
			try {
				dbHandle.endTransaction(transaction.longValue(), commit);
				transaction = null;
			}
			catch (IOException e) {
				dbError(e);
			}
		}
	}

	@Override
	protected void replaceDataTypeIDs(long oldID, long newID) {
		// do nothing
	}

	@Override
	protected void deleteDataTypeIDs(LinkedList<Long> deletedIds, TaskMonitor monitor) {
		// do nothing
	}

	@Override
	public void close() {
		if (dbHandle != null) {
			dbHandle.close();
			dbHandle = null;
		}
		super.close();
	}

	@Override
	public void finalize() {
		close();
	}

	@Override
	protected String getDomainFileID() {
		return null;
	}

	@Override
	protected String getPath() {
		return null;
	}

	@Override
	public ArchiveType getType() {
		return ArchiveType.TEST;
	}
}
