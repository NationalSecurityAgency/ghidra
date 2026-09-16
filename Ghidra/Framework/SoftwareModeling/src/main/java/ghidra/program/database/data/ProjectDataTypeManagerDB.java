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
package ghidra.program.database.data;

import java.io.IOException;

import db.DBHandle;
import db.util.ErrorHandler;
import ghidra.framework.data.OpenMode;
import ghidra.framework.model.DomainFile;
import ghidra.program.database.dtarchive.ProjectDtArchiveDB;
import ghidra.program.model.data.ArchiveType;
import ghidra.program.model.dtarchive.DataTypeArchive;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.Language;
import ghidra.util.Lock;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 * Class for managing data types in a project archive
 * NOTE: default data organization is used.
 */
public class ProjectDataTypeManagerDB extends ArchiveDataTypeManagerDB {

	/**
	 * Constructor for a data-type manager using a specified DBHandle.
	 * <p>
	 * <B>NOTE:</B> If archive has an assigned architecture, issues may arise due to a revised or
	 * missing {@link Language}/{@link CompilerSpec} which will result in a warning but not
	 * prevent the archive from being opened.  Such a warning condition will ne logged and may 
	 * result in missing or stale information for existing datatypes which have architecture related
	 * data.  In some case it may be appropriate to 
	 * {@link DataTypeArchive#getWarning() check for warnings} on the returned archive
	 * object prior to its use.
	 * 
	 * @param handle open database  handle
	 * @param openMode the program open mode
	 * @param errHandler the database I/O error handler
	 * @param lock the program synchronization lock
	 * @param monitor the progress monitor
	 * @throws CancelledException if the user cancels an upgrade
	 * @throws VersionException if the database does not match the expected version.
	 * @throws IOException if a database I/O error occurs.
	 */
	public ProjectDataTypeManagerDB(DBHandle handle,
			OpenMode openMode,
			ErrorHandler errHandler, Lock lock, TaskMonitor monitor)
			throws CancelledException, VersionException, IOException {
		super(handle, openMode, errHandler, lock, monitor);
	}

	@Override
	public ProjectDtArchiveDB getDataStore() {
		return (ProjectDtArchiveDB) super.getDataStore();
	}

	@Override
	public String getName() {
		return archive.getDomainFile().getName();
	}

	/**
	 * Get the domain file for the associated project archive.
	 * @return the associated domain file
	 */
	public DomainFile getDomainFile() {
		return archive.getDomainFile();
	}

	@Override
	protected String getDomainFileID() {
		DomainFile domainFile = getDomainFile(); // Can be null if it has never been saved.
		return (domainFile != null) ? domainFile.getFileID() : null;
	}

	@Override
	public String getPath() {
		return archive.getPath();
	}

	@Override
	public ArchiveType getType() {
		return ArchiveType.PROJECT;
	}

	@Override
	public synchronized void close() {
		// do nothing - cannot close a project data type manager
		// dispose should be invoked by the owner of the instance
	}

}
