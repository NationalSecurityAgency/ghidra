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
package ghidra.app.services;

import java.io.File;
import java.io.IOException;

import generic.jar.ResourceFile;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.plugin.core.datamgr.archive.Archive;
import ghidra.app.plugin.core.datamgr.archive.DuplicateIdException;
import ghidra.framework.model.DomainFile;
import ghidra.framework.plugintool.ServiceInfo;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.DataTypeArchive;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 * A service that manages a set of data type archives, allowing re-use of already open
 * archives.
 */
//@formatter:off
@ServiceInfo(
	defaultProvider = DataTypeManagerPlugin.class, 
	description = "Service to manipulate the set of active Data Type Managers"
)
//@formatter:on
public interface DataTypeArchiveService {

	/**
	 * Get the data type manager that has all of the built in types.
	 * @return data type manager for built in data types
	 */
	public DataTypeManager getBuiltInDataTypesManager();

	/**
	 * Gets the open data type managers.
	 * 
	 * @return the open data type managers.
	 */
	public DataTypeManager[] getDataTypeManagers();

	/**
	 * Closes the archive for the given {@link DataTypeManager}.  This will ignore request to 
	 * close the open Program's manager and the built-in manager.  
	 * 
	 * @param dtm the data type manager of the archive to close
	 */
	public void closeArchive(DataTypeManager dtm);

	/**
	 * Opens a data type archive that was built into the Ghidra installation.
	 * <p>
	 * NOTE: This is predicated upon all archive files having a unique name within the installation.
	 * <p>
	 * Any path prefix specified may prevent the file from opening (or reopening) correctly.
	 * 
	 * @param archiveName archive file name (i.e., "generic_C_lib")
	 * @return the data type archive or null if an archive with the specified name
	 * can not be found.
	 * @throws IOException if an i/o error occurs opening the data type archive
	 * @throws DuplicateIdException if another archive with the same ID is already open
	 */
	public DataTypeManager openDataTypeArchive(String archiveName)
			throws IOException, DuplicateIdException;

	/**
	 * Opens the specified gdt (file based) data type archive.
	 *  
	 * @param file gdt file
	 * @param acquireWriteLock true if write lock should be acquired (i.e., open for update)
	 * @return the data type archive 
	 * @throws IOException if an i/o error occurs opening the data type archive
	 * @throws DuplicateIdException if another archive with the same ID is already open
	 */
	public DataTypeManager openArchive(ResourceFile file, boolean acquireWriteLock)
			throws IOException, DuplicateIdException;

	/**
	 * Opens the specified project-located data type archive.
	 *  
	 * @param domainFile archive file located in the current project
	 * @param monitor {@link TaskMonitor} to display progess during the opening
	 * @return the data type archive 
	 * @throws IOException if an i/o error occurs opening the data type archive
	 * @throws DuplicateIdException if another archive with the same ID is already open
	 * @throws VersionException
	 * @throws CancelledException
	 */
	public DataTypeManager openArchive(DomainFile domainFile, TaskMonitor monitor)
			throws VersionException, CancelledException, IOException, DuplicateIdException;

	/** 
	 * A method to open an Archive for the given, pre-existing DataTypeArchive (like one that
	 * was opened during the import process.
	 * 
	 * @param dataTypeArchive the archive from which to create an Archive
	 * @return an Archive based upon the given DataTypeArchive
	 */
	@Deprecated
	public Archive openArchive(DataTypeArchive dataTypeArchive);

	/**
	 * A method to open an Archive for the given, pre-existing archive file (*.gdt)
	 * 
	 * @param file data type archive file
	 * @param acquireWriteLock true if write lock should be acquired (i.e., open for update)
	 * @return an Archive based upon the given archive files
	 * @throws IOException if an i/o error occurs opening the data type archive
	 * @throws DuplicateIdException if another archive with the same ID is already open
	 */
	@Deprecated
	public Archive openArchive(File file, boolean acquireWriteLock)
			throws IOException, DuplicateIdException;


}
