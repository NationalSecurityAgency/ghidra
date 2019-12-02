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
package ghidra.framework.store.db;

import java.io.File;
import java.io.IOException;

import db.DBChangeSet;
import db.DBHandle;
import db.buffers.BufferFile;
import generic.jar.ResourceFile;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateFileException;
import ghidra.util.task.TaskMonitor;

/**
 * <code>DBHandle</code> provides access to a PackedDatabase.
 */
public class PackedDBHandle extends DBHandle {

	// NOTE: If saveAs is used to save to a non-packed database, pdb will become null and this handle
	// should behave like a normal DBHandle

	private PackedDatabase pdb;
	private String contentType;

	/**
	 * Constructs a temporary packed database handle.
	 * @param contentType user defined content type.
	 * @throws IOException
	 */
	public PackedDBHandle(String contentType) throws IOException {
		super();
		this.contentType = contentType;
	}

	/**
	 * Constructs a database handle for an existing packed database.
	 * Update mode is determined by bfile.
	 * @param database packed database
	 * @param bfile temporary unpacked database which corresponds to the
	 * specified packed database.
	 */
	PackedDBHandle(PackedDatabase pdb, BufferFile bfile) throws IOException {
		super(bfile);
		this.pdb = pdb;
		this.contentType = pdb.getContentType();
	}

	@Override
	public synchronized void save(String comment, DBChangeSet changeSet, TaskMonitor monitor)
			throws IOException, CancelledException {

		super.save(comment, changeSet, monitor);
		if (pdb != null && !pdb.isReadOnly()) {
			pdb.packDatabase(monitor);
		}
	}

	/**
	 * Saves the open database to the corresponding PackedDatabase file.
	 * @param monitor
	 * @throws IOException
	 * @throws CancelledException
	 */
	public synchronized void save(TaskMonitor monitor) throws IOException, CancelledException {

		save("", null, monitor);
	}

	@Override
	protected synchronized void saveAs(BufferFile outFile, Long newDatabaseId, TaskMonitor monitor)
			throws IOException, CancelledException {
		super.saveAs(outFile, newDatabaseId, monitor);
		if (pdb != null) {
			pdb.dispose();
			pdb = null;
		}
	}

	@Override
	public synchronized void saveAs(BufferFile outFile, boolean associateWithNewFile,
			TaskMonitor monitor) throws IOException, CancelledException {
		super.saveAs(outFile, associateWithNewFile, monitor);
		if (associateWithNewFile && pdb != null) {
			pdb.dispose();
			pdb = null;
		}
	}

	@Override
	public synchronized void close() {
		super.close();
		if (pdb != null) {
			pdb.dispose();
			pdb = null;
		}
	}

	/**
	 * Save open database to a new packed database.
	 * If another PackedDatabase was associated with this handle prior to this invocation
	 * it should be disposed to that the underlying database resources can be cleaned-up.
	 * @param itemName
	 * @param dir
	 * @param packedFileName
	 * @param monitor
	 * @return new packed Database object now associated with this handle.
	 * @throws CancelledException if task monitor cancelled operation.
	 * @throws IOException
	 * @throws DuplicateFileException
	 */
	public synchronized PackedDatabase saveAs(String itemName, File dir, String packedFileName,
			TaskMonitor monitor) throws IOException, DuplicateFileException, CancelledException {

		if (isTransactionActive())
			throw new IllegalStateException("Can't saveAs during transaction");
		ResourceFile packedDbFile = new ResourceFile(new File(dir, packedFileName));
		pdb = new PackedDatabase(this, packedDbFile, itemName, null, monitor);

		return pdb;
	}

	/**
	 * Save open database to a new packed database with a specified newDatabaseId.
	 * If another PackedDatabase was associated with this handle prior to this invocation
	 * it should be disposed to that the underlying database resources can be cleaned-up.
	 * NOTE: This method is intended for use in transforming one database to
	 * match another existing database.
	 * @param itemName
	 * @param dir
	 * @param packedFileName
	 * @param newDatabaseId database ID to be forced for new database or null to generate 
	 * new database ID
	 * @param monitor
	 * @return new packed Database object now associated with this handle.
	 * @throws CancelledException if task monitor cancelled operation.
	 * @throws IOException
	 * @throws DuplicateFileException
	 */
	public synchronized PackedDatabase saveAs(String itemName, File dir, String packedFileName,
			Long newDatabaseId, TaskMonitor monitor)
			throws IOException, DuplicateFileException, CancelledException {

		if (isTransactionActive())
			throw new IllegalStateException("Can't saveAs during transaction");
		ResourceFile packedDbFile = new ResourceFile(new File(dir, packedFileName));
		pdb = new PackedDatabase(this, packedDbFile, itemName, newDatabaseId, monitor);

		return pdb;
	}

	/**
	 * Returns user defined content type associated with this handle.
	 */
	public String getContentType() {
		return contentType;
	}

	/**
	 * Returns PackedDatabase associated with this handle, or null if
	 * this is a temporary handle which has not yet been saved to a
	 * PackedDatabase using saveAs.
	 */
	public PackedDatabase getPackedDatabase() {
		return pdb;
	}

}
