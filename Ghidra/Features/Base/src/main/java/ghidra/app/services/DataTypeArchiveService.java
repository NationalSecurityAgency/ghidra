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

import java.io.IOException;
import java.util.List;

import generic.jar.ResourceFile;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.plugin.core.datamgr.archive.DuplicateIdException;
import ghidra.framework.model.DomainFile;
import ghidra.framework.plugintool.ServiceInfo;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.dtarchive.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 * A service that manages a set of data type archives, allowing re-use of already open archives.
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
	 * Gets the open data type managers. (Includes DataTypeManagers from the built-in, program and
	 * all open archives in the tool.)
	 * 
	 * @return the open data type managers.
	 */
	public DataTypeManager[] getDataTypeManagers();

	/**
	 * {@return a list of all open ProjectDataTypeArchives or FileDataTypeArchives open in the tool}
	 */
	public List<PersistentDataTypeArchive> getDataTypeArchives();

	/**
	 * Close the given archive in the tool
	 * @param archive The DataTypeArchive to close in the tool
	 */
	public void closeArchive(PersistentDataTypeArchive archive);

	/**
	 * Opens a file data type archive that was included in the distribution
	 * <p>
	 * NOTE: This is predicated upon all archive files having a unique name within the installation.
	 * <p>
	 * Any path prefix specified may prevent the file from opening (or reopening) correctly.
	 * 
	 * @param archiveName archive file name (i.e., "generic_C_lib")
	 * @param monitor the TaskMonitor that can be used to cancel the open operation
	 * @return the data type archive or null if an archive with the specified name
	 * can not be found.
	 * @throws IOException if an i/o error occurs opening the data type archive
	 * @throws VersionException if there is a version exception that can't be upgraded (or the
	 * user chose not to upgrade to the latest version)
	 * @throws DuplicateIdException if another archive with the same ID is already open
	 * @throws CancelledException if the operation was cancelled via the TaskMonitor
	 */
	public FileDataTypeArchive openFileArchive(String archiveName, TaskMonitor monitor)
			throws IOException, VersionException, DuplicateIdException, CancelledException;

	/**
	 * Opens the specified file data type archive (gdt).
	 *  
	 * @param file archive file
	 * @param openForUpdate true if open for update, false for read-only
	 * @param upgradeStrategy Determines how to deal with a file that is not up to current version.
	 * if YES, then the archive will be upgraded to the latest version. If No then the file
	 * will NOT be upgraded to the current version and will throw a VersionException if the file
	 * is not at the current version. ASK will cause a dialog to popup for the user to choose. In
	 * headless mode, ASK will be treated as a NO. This option only applies if the openForUpdate
	 * is true.
	 * @param monitor the TaskMonitor that can be used to cancel the open operation
	 * @return the file data type archive 
	 * @throws IOException if an i/o error occurs opening the data type archive
	 * @throws VersionException if there is a version exception that can't be upgraded (or the
	 * user chose not to upgrade to the latest version)
	 * @throws DuplicateIdException if another archive with the same ID is already open
	 * @throws CancelledException if the operation was cancelled via the TaskMonitor
	 */
	public FileDataTypeArchive openFileArchive(ResourceFile file, boolean openForUpdate,
			Upgrade upgradeStrategy, TaskMonitor monitor)
			throws IOException, VersionException, DuplicateIdException, CancelledException;

	/**
	 * Opens the specified project-located data type archive.
	 *  
	 * @param domainFile archive file located in the current project
	 * @param upgradeStrategy Determines how to deal with a file that is not up to current version.
	 * if YES, then the archive will be upgraded to the latest version. If No then the file
	 * will NOT be upgraded to the current version and will throw a VersionException if the file
	 * is not at the current version. ASK will cause a dialog to popup for the user to choose. In
	 * headless mode, ASK will be treated as a NO. This option only applies if the openForUpdate
	 * is true.
	 * @param recoverStrategy Determines how to deal with a file that has crash data (changes that
	 * were not saved because Ghidra crashed (or was externally terminated). 
	 * if YES, then the recover crash data will be applied. If No then the crash data will be 
	 * ignored. ASK will cause a dialog to popup for the user to choose. In
	 * headless mode, ASK will be treated as a NO. 
	 * @param monitor the TaskMonitor that can be used to cancel the open operation
	 * @return the data type archive 
	 * @throws IOException if an i/o error occurs opening the data type archive
	 * @throws DuplicateIdException if another archive with the same ID is already open
	 * @throws VersionException if there is a version exception that can't be upgraded (or the
	 * user chose not to upgrade to the latest version)
	 * @throws CancelledException if the user cancels
	 */
	public ProjectDataTypeArchive openProjectArchive(DomainFile domainFile, Upgrade upgradeStrategy,
			Recover recoverStrategy, TaskMonitor monitor)
			throws VersionException, CancelledException, IOException, DuplicateIdException;

	/**
	 * Closes the archive for the given {@link DataTypeManager}.  This will ignore any request to 
	 * close the open Program's manager or the built-in manager.  
	 * 
	 * @param dtm the data type manager of the archive to close
	 * @deprecated use {@link #closeArchive(PersistentDataTypeArchive)} instead
	 */
	@Deprecated(forRemoval = true, since = "12.2")
	public void closeArchive(DataTypeManager dtm);

	/**
	 * Opens a data type archive that was built into the Ghidra installation.
	 * <p>
	 * NOTE: This is predicated upon all archive files having a unique name within the installation.
	 * <p>
	 * Any path prefix specified may prevent the file from opening (or reopening) correctly.
	 * 
	 * @param archiveName archive file name (i.e., "generic_C_lib")
	 * @return the data type manager or null if an archive with the specified name
	 * can not be found.
	 * @throws IOException if an i/o error occurs opening the data type archive
	 * @throws DuplicateIdException if another archive with the same ID is already open
	 * @deprecated use {@link #openFileArchive(String, TaskMonitor)} instead
	 */
	@Deprecated(forRemoval = true, since = "12.2")
	public default DataTypeManager openDataTypeArchive(String archiveName)
			throws IOException, DuplicateIdException {
		FileDataTypeArchive archive;
		try {
			archive = openFileArchive(archiveName, TaskMonitor.DUMMY);
			return archive == null ? null : archive.getDataTypeManager();
		}
		catch (CancelledException e) {
			// can't happen because using dummy monitor
		}
		catch (VersionException e) {
			throw new IOException(e);	// legacy didn't declare version exception
		}
		return null;
	}

	/**
	 * Opens the specified gdt (file based) data type archive.
	 *  
	 * @param file archive file
	 * @param openForUpdate true if open for update, false for read-only
	 * @return the data type archive 
	 * @throws IOException if an i/o error occurs opening the data type archive
	 * @throws DuplicateIdException if another archive with the same ID is already open
	 * @deprecated use {@link #openFileArchive(ResourceFile, boolean, Upgrade, TaskMonitor)} instead
	 */
	@Deprecated(forRemoval = true, since = "12.2")
	public default DataTypeManager openArchive(ResourceFile file, boolean openForUpdate)
			throws IOException, DuplicateIdException {
		FileDataTypeArchive archive;
		try {
			archive = openFileArchive(file, openForUpdate, Upgrade.NO, TaskMonitor.DUMMY);
			return archive == null ? null : archive.getDataTypeManager();
		}
		catch (CancelledException e) {
			// can't happen because using dummy monitor
		}
		catch (VersionException e) {
			throw new IOException(e);	// legacy didn't declare version exception
		}
		return null;
	}

	/**
	* Opens the specified project-located data type archive.
	*  
	* @param domainFile archive file located in the current project
	* @param monitor {@link TaskMonitor} to display progress during the opening
	* @return the data type archive 
	* @throws IOException if an i/o error occurs opening the data type archive
	* @throws DuplicateIdException if another archive with the same ID is already open
	* @throws VersionException if there is a version exception
	* @throws CancelledException if the user cancels
	* @deprecated use {@link #openProjectArchive(DomainFile, Upgrade, Recover, TaskMonitor)} instead
	*/
	@Deprecated(forRemoval = true, since = "12.2")
	public default DataTypeManager openArchive(DomainFile domainFile, TaskMonitor monitor)
			throws VersionException, CancelledException, IOException, DuplicateIdException {
		ProjectDataTypeArchive archive =
			openProjectArchive(domainFile, Upgrade.NO, Recover.NO, monitor);
		return archive == null ? null : archive.getDataTypeManager();
	}
}
