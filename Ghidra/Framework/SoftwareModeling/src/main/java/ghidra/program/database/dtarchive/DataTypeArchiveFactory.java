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
package ghidra.program.database.dtarchive;

import java.io.File;
import java.io.IOException;

import db.DBHandle;
import generic.jar.ResourceFile;
import ghidra.framework.data.OpenMode;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.store.db.PackedDatabase;
import ghidra.program.model.data.BuiltInDataTypeManager;
import ghidra.program.model.dtarchive.*;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;
import ghidra.util.InvalidNameException;
import ghidra.util.ReadOnlyException;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * Provides all the static methods for creating and opening {@link PersistentDataTypeArchive}s.
 */
public class DataTypeArchiveFactory {
	/**
	 * Creates a new FileDtArchive and stores it into the given output file.
	 * @param file the file to write the new FileDtArchive data to when saved
	 * @param consumer The object that is using this potentially shared archive. The caller of
	 * this method is expected to call {@link PersistentDataTypeArchive#release(Object)} using this same
	 * consumer when done using this archive.
	 * @return the newly created FileDtArchive
	 * @throws IOException if an I/O error occurs writing to the output file
	 */
	public static FileDataTypeArchive createFileArchive(File file, Object consumer)
			throws IOException {
		return FileDtArchiveDB.create(file, consumer);
	}

	/**
	 * Creates a new {@link FileDataTypeArchive} and stores it into the given output file.
	 * @param file the file to write the new FileDtArchive data to when saved
	 * @param languageId valid language ID (see appropriate *.ldefs file for defined IDs).  If null
	 * invocation will be deferred to {@link #createFileArchive(File, Object)}.
	 * @param compilerSpecId valid compiler spec ID which corresponds to the language ID.
	 * @param consumer The object that is using this potentially shared archive. The caller of
	 * this method is expected to call {@link PersistentDataTypeArchive#release(Object)} using this same
	 * consumer when done using this archive.
	 * @return the newly created FileDtArchive
	 * @throws IOException if an I/O error occurs writing to the output file
	 */
	public static FileDataTypeArchive createFileArchive(File file, String languageId,
			String compilerSpecId, Object consumer) throws IOException {
		return FileDtArchiveDB.create(file, languageId, compilerSpecId, consumer);
	}

	/**
	 * Creates a new {@link FileDataTypeArchive} and stores it into the given output file.
	 * @param file the file to write the new FileDtArchive data to when saved
	 * @param languageId the id of the language to use for determining datatype organization details
	 * @param compilerSpecId the id of the compilerSpec to use for determining datatype organization
	 * details
	 * @param consumer The object that is using this potentially shared archive. The caller of
	 * this method is expected to call {@link PersistentDataTypeArchive#release(Object)} using this same
	 * consumer when done using this archive.
	 * @return the newly created FileDtArchive
	 * @throws IOException if an I/O error occurs writing to the output file
	 */
	public static FileDataTypeArchive createFileArchive(File file, LanguageID languageId,
			CompilerSpecID compilerSpecId, Object consumer) throws IOException {
		return FileDtArchiveDB.create(file, languageId, compilerSpecId, consumer);
	}

	/**
	 * Creates a new {@link ProjectDataTypeArchive} in the given folder with the given name.
	 * @param folder the DomainFolder to store the project datatype archive
	 * @param name the name of the new project datatype archive
	 * @param consumer the consumer that is using the project datatype archive. The archive is
	 * closed when the last consumer is released.
	 * @return a new ProjectDataTypeArchive that is stored in the given domain folder with the
	 * given name.
	 * @throws DuplicateNameException if a DomainFile already exists in the given folder with the
	 * same name.
	 * @throws InvalidNameException if the given name is not a valid DomainFile name
	 * @throws IOException If an error occurs creating the database files for the new archive.
	 */
	public static ProjectDataTypeArchive createProjectArchive(DomainFolder folder, String name,
			Object consumer) throws DuplicateNameException, InvalidNameException, IOException {

		return new ProjectDtArchiveDB(folder, name, consumer);
	}

	/**
	 * Opens a {@link FileDataTypeArchive} that is stored in the given packed database file.
	 * @param file the file storing the archive's data as a packed database file
	 * @param consumer The object that is using this potentially shared archive. The caller of
	 * this method is expected to call {@link PersistentDataTypeArchive#release(Object)} using this same
	 * consumer when done using this archive.
	 * @param monitor the task monitor to use while opening the archive
	 * @return the newly opened FileDtArchive
	 * @throws CancelledException if the task to open the archive was cancelled
	 * @throws VersionException If the okToUpgrade is false and the file version is not the current
	 * version. If the okToUpgrade is true, then a version exception is only thrown if the file is
	 * an older version and there is no upgrade path to the current version.
	 * @throws IOException If an I/O error occurs reading from the database file
	 */
	public static FileDataTypeArchive openReadOnly(File file, Object consumer, TaskMonitor monitor)
			throws CancelledException, VersionException, IOException {
		return openReadOnly(new ResourceFile(file), consumer, monitor);
	}

	/**
	 * Opens a {@link FileDataTypeArchive} that is stored in the given packed database file.
	 * @param file the file storing the archive's data as a packed database file
	 * @param consumer The object that is using this potentially shared archive. The caller of
	 * this method is expected to call {@link PersistentDataTypeArchive#release(Object)} using this same
	 * consumer when done using this archive.
	 * @param monitor the task monitor to use while opening the archive
	 * @return the newly opened FileDtArchive
	 * @throws CancelledException if the task to open the archive was cancelled
	 * @throws VersionException If the okToUpgrade is false and the file version is not the current
	 * version. If the okToUpgrade is true, then a version exception is only thrown if the file is
	 * an older version and there is no upgrade path to the current version.
	 * @throws IOException If an I/O error occurs reading from the database file
	 */
	public static FileDataTypeArchive openReadOnly(ResourceFile file, Object consumer,
			TaskMonitor monitor) throws CancelledException, VersionException, IOException {
		return FileDtArchiveDB.openReadOnly(file, consumer, monitor);
	}

	/**
	 * Opens a {@link FileDataTypeArchive} that is stored in the given packed database file.
	 * @param packedDbFile the file storing the archive's data as a packed database file
	 * @param okToUpgrade true if the archive can be allowed to upgrade to a newer version
	 * @param consumer The object that is using this potentially shared archive. The caller of
	 * this method is expected to call {@link PersistentDataTypeArchive#release(Object)} using this same
	 * consumer when done using this archive.
	 * @param monitor the task monitor to use while opening the archive
	 * @return the newly opened FileDtArchive
	 * @throws CancelledException if the task to open the archive was cancelled
	 * @throws VersionException If the okToUpgrade is false and the file version is not the current
	 * version. If the okToUpgrade is true, then a version exception is only thrown if the file is
	 * an older version and there is no upgrade path to the current version.
	 * @throws IOException If an I/O error occurs reading from the database file
	 */
	public static FileDataTypeArchive openForUpdate(File packedDbFile, boolean okToUpgrade,
			Object consumer, TaskMonitor monitor)
			throws CancelledException, VersionException, IOException {
		return openForUpdate(new ResourceFile(packedDbFile), okToUpgrade, consumer, monitor);
	}

	/**
	 * Opens a {@link FileDataTypeArchive} that is stored in the given packed database file.
	 * @param packedDbFile the packed database resource file storing the archive's data
	 * @param okToUpgrade true if the archive can be allowed to upgrade to a newer version
	 * @param consumer The object that is using this potentially shared archive. The caller of
	 * this method is expected to call {@link PersistentDataTypeArchive#release(Object)} using this same
	 * consumer when done using this archive.
	 * @param monitor the task monitor to use while opening the archive
	 * @return the newly opened FileDtArchive
	 * @throws CancelledException if the task to open the archive was cancelled
	 * @throws VersionException If the okToUpgrade is false and the file version is not the current
	 * version. If the okToUpgrade is true, then a version exception is only thrown if the file is
	 * an older version and there is no upgrade path to the current version.
	 * @throws IOException If an I/O error occurs reading from the database file
	 */
	public static FileDataTypeArchive openForUpdate(ResourceFile packedDbFile, boolean okToUpgrade,
			Object consumer, TaskMonitor monitor)
			throws CancelledException, VersionException, IOException {
		return FileDtArchiveDB.openForUpdate(packedDbFile, okToUpgrade, consumer, monitor);
	}

	/**
	 * Opens a {@link ProjectDataTypeArchive} for updating that is stored in a project domain file.
	 * @param domainFile the project domain file containing the stored archive
	 * @param consumer the object used to mark the archive is in use by that object. Project
	 * archives don't have a close method, instead they are closed when the last consumer is
	 * released (using the {@link ProjectDataTypeArchive#release(Object)} method.
	 * @param okToUpgrade if true, the archive can be allowed to upgrade to a newer version
	 * @param okToRecover if true, then any crash unsaved changes can be recovered when the 
	 * archive is opened 
	 * @param monitor the task monitor to use while opening the archive
	 * @return the newly opened project data type archive
	 * @throws CancelledException if the task to open the archive was cancelled
	 * @throws VersionException If the okToUpgrade is false and the file version is not the current
	 * version. If the okToUpgrade is true, then a version exception is only thrown if the file is
	 * an older version and there is no upgrade path to the current version.
	 * @throws ReadOnlyException if domainFile is not checked-out or marked as read-only
	 * @throws IOException If an I/O error occurs reading from the database file
	 */
	public static ProjectDataTypeArchive openForUpdate(DomainFile domainFile,
			Object consumer, boolean okToUpgrade, boolean okToRecover, TaskMonitor monitor)
			throws VersionException, CancelledException, ReadOnlyException, IOException {
		if (domainFile.isReadOnly()) {
			throw new ReadOnlyException();
		}
		return (ProjectDataTypeArchive) domainFile.getDomainObject(consumer, okToUpgrade,
			okToRecover, monitor);
	}

	/**
	 * Opens a {@link ProjectDataTypeArchive} in a read-only mode that is stored in a project domain
	 * file.
	 * @param domainFile the project domain file containing the stored archive
	 * @param consumer the object used to mark the archive is in use by that object. Project
	 * archives don't have a close method, instead they are closed when the last consumer is
	 * released (using the {@link ProjectDataTypeArchive#release(Object)} method.
	 * @param monitor the task monitor to use while opening the archive
	 * @return the newly opened project data type archive
	 * @throws CancelledException if the task to open the archive was cancelled
	 * @throws VersionException If the okToUpgrade is false and the file version is not the current
	 * version. If the okToUpgrade is true, then a version exception is only thrown if the file is
	 * an older version and there is no upgrade path to the current version.
	 * @throws IOException If an I/O error occurs reading from the database file
	 */
	public static ProjectDataTypeArchive openReadOnly(DomainFile domainFile,
			Object consumer, TaskMonitor monitor)
			throws VersionException, CancelledException, IOException {
		return openReadOnly(domainFile, DomainFile.DEFAULT_VERSION, consumer, monitor);
	}

	/**
	 * Opens a specific version of a {@link ProjectDataTypeArchive} in a read-only mode.
	 * @param domainFile the project domain file containing the stored archive
	 * @param version the specific version to open (This only makes sense if the archive has
	 * been added to version control (Or use {@link DomainFile#DEFAULT_VERSION} to specify
	 * the current version)).
	 * @param consumer the object used to mark the archive is in use by that object. Project
	 * archives don't have a close method, instead they are closed when the last consumer is
	 * released (using the {@link ProjectDataTypeArchive#release(Object)} method.
	 * @param monitor the task monitor to use while opening the archive
	 * @return the newly opened project data type archive
	 * @throws CancelledException if the task to open the archive was cancelled
	 * @throws VersionException If the okToUpgrade is false and the file version is not the current
	 * version. If the okToUpgrade is true, then a version exception is only thrown if the file is
	 * an older version and there is no upgrade path to the current version.
	 * @throws IOException If an I/O error occurs reading from the database file
	 */
	public static ProjectDataTypeArchive openReadOnly(DomainFile domainFile, int version,
			Object consumer, TaskMonitor monitor)
			throws VersionException, CancelledException, IOException {
		// NOTE: use of getReadOnlyDomainObject allows any upgrade to be performed if needed
		return (ProjectDataTypeArchive) domainFile.getReadOnlyDomainObject(consumer, version,
			monitor);
	}

	/**
	 * Returns shared instance of built-in data type manager.
	 * @return the built-in data type manager
	 */
	public static BuiltInDataTypeManager getBuiltInDataTypeManager() {
		BuiltInDtArchiveDB builtInArchive = BuiltInDtArchiveDB.getDataTypeArchive();
		return builtInArchive.getDataTypeManager();
	}

	/**
	 * Creates an unsaved ProjectDataTypeArchive from the datatypes stored in a 
	 * {@link FileDataTypeArchive} packed database file. 
	 * @param file the file that contains a packed database file for a FileDataTypeArchive
	 * @param name the name for the new project datatype archive
	 * @param consumer the consumer keeping the project archive open. Project archives are closed
	 * when the last consumer is released using the {@link ProjectDataTypeArchive#release(Object)}
	 * method
	 * @param monitor that task monitor
	 * @return a new unsaved ProjectDataTypeArchive.
	 * @throws IOException if an I/O error occurs creating the project database
	 * @throws VersionException if the file contains a version that can't be upgraded.
	 * @throws CancelledException if the monitor is cancelled before the operation is complete
	 */
	public static ProjectDataTypeArchive importProjectArchive(File file, String name,
			Object consumer, TaskMonitor monitor)
			throws IOException, VersionException, CancelledException {

		PackedDatabase packedDatabase = PackedDatabase.getPackedDatabase(file, true, monitor);
		if (!DataTypeArchiveContentHandler.DATA_TYPE_ARCHIVE_CONTENT_TYPE
				.equals(packedDatabase.getContentType())) {
			throw new IOException("Given file is not a Datatype Archive: " + name);
		}

		monitor.setMessage("Loading " + name);
		DBHandle dbh = null;
		try {
			dbh = packedDatabase.open(monitor);
			return new ProjectDtArchiveDB(dbh, name, OpenMode.UPGRADE, monitor, consumer);
		}
		catch (CancelledException | VersionException | IOException e) {
			if (dbh != null) {
				dbh.close();
			}
			else {
				packedDatabase.dispose();
			}
			throw e;
		}
	}

}
