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

import java.io.File;
import java.io.IOException;

import generic.jar.ResourceFile;
import ghidra.program.database.dtarchive.DataTypeArchiveFactory;
import ghidra.program.database.dtarchive.DefaultConsumer;
import ghidra.program.model.dtarchive.FileDataTypeArchive;
import ghidra.program.model.dtarchive.PersistentDataTypeArchive;
import ghidra.program.model.lang.*;
import ghidra.util.UniversalID;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * DataTypeManager for a file. Can import categories from a file, or export
 * categories to a packed database.
 * @deprecated There is no longer any need to work with a specialized version of DataTypeManager.
 * Create or open a {@link FileDataTypeArchive}, then call 
 * {@link PersistentDataTypeArchive#getDataTypeManager()}.
 */
@Deprecated(since = "12.2", forRemoval = true)
public interface FileDataTypeManager extends ArchiveDataTypeManager, AutoCloseable {

	@Deprecated(since = "12.2", forRemoval = true)
	final static String OLD_EXTENSION = "dtf";

	@Deprecated(since = "12.2", forRemoval = true)
	final static String OLD_SUFFIX = "." + OLD_EXTENSION;

	/**
	 * Create a new data-type file archive using the default data organization
	 * @param packedDbfile archive file (filename must end with DataTypeFileManager.SUFFIX)
	 * @return data-type manager backed by specified packedDbFile
	 * @throws IOException if an IO error occurs
	 * @deprecated Use {@link DataTypeArchiveFactory#createFileArchive(File, Object)} to create a 
	 * file base archive, then call {@link PersistentDataTypeArchive#getDataTypeManager()}
	 */
	@Deprecated(since = "12.2", forRemoval = true)
	public static FileDataTypeManager createFileArchive(File packedDbfile) throws IOException {
		FileDataTypeArchive archive =
			DataTypeArchiveFactory.createFileArchive(packedDbfile, new DefaultConsumer());
		return archive != null ? (FileDataTypeManager) archive.getDataTypeManager() : null;
	}

	/**
	 * Create a new data-type file archive using the default data organization.
	 * @param packedDbFile archive file (filename must end with DataTypeFileManager.SUFFIX)
	 * @param languageId valid language ID (see appropriate *.ldefs file for defined IDs)
	 * @param compilerSpecId valid compiler spec ID which corresponds to the language ID.
	 * @return data-type manager backed by the specified packedDbFile
	 * @throws DuplicateFileException if {@code packedDbFile} already exists
	 * @throws LanguageNotFoundException if specified {@code languageId} not defined. 
	 * @throws CompilerSpecNotFoundException if specified {@code compilerSpecId} is not defined 
	 * for the specified language. 
	 * @throws IOException if an IO error occurs
	 * @deprecated Use 
	 * {@link DataTypeArchiveFactory#createFileArchive(File, LanguageID, CompilerSpecID, Object)} to
	 * create a file based archive, then call {@link PersistentDataTypeArchive#getDataTypeManager()}
	 */
	@Deprecated(since = "12.2", forRemoval = true)
	public static FileDataTypeManager createFileArchive(File packedDbFile, LanguageID languageId,
			CompilerSpecID compilerSpecId)
			throws LanguageNotFoundException, CompilerSpecNotFoundException, IOException {

		FileDataTypeArchive archive =
			DataTypeArchiveFactory.createFileArchive(packedDbFile, languageId, compilerSpecId,
				new DefaultConsumer());

		return archive != null ? (FileDataTypeManager) archive.getDataTypeManager() : null;
	}

	/**
	 * Create a new data-type file archive using the specified language/compiler spec
	 * @param packedDbfile archive file (filename must end with DataTypeFileManager.SUFFIX)
	 * @param languageId valid language ID (see appropriate *.ldefs file for defined IDs).  If null
	 * invocation will be deferred to {@link #createFileArchive(File)}.
	 * @param compilerSpecId valid compiler spec ID which corresponds to the language ID.
	 * @return data-type manager backed by the specified packedDbFile
	 * @throws LanguageNotFoundException if specified {@code languageId} not defined. 
	 * @throws CompilerSpecNotFoundException if specified {@code compilerSpecId} is not defined 
	 * for the specified language. 
	 * @throws IOException if an IO error occurs
	 * @deprecated Use 
	 * {@link DataTypeArchiveFactory#createFileArchive(File, String, String, Object)} to create
	 * a file based archive, then call {@link PersistentDataTypeArchive#getDataTypeManager()}
	 */
	@Deprecated(since = "12.2", forRemoval = true)
	public static FileDataTypeManager createFileArchive(File packedDbfile, String languageId,
			String compilerSpecId) throws IOException {
		FileDataTypeArchive archive =
			DataTypeArchiveFactory.createFileArchive(packedDbfile, languageId, compilerSpecId,
				new DefaultConsumer());
		return archive != null ? (FileDataTypeManager) archive.getDataTypeManager() : null;
	}

	/**
	 * Open an existing data-type file archive using the default data organization.
	 * <p>
	 * <B>NOTE:</B> If archive has an assigned architecture, issues may arise due to a revised or
	 * missing {@link Language}/{@link CompilerSpec} which will result in a warning but not
	 * prevent the archive from being opened.  Such a warning condition will be logged and may 
	 * result in missing or stale information for existing datatypes which have architecture related
	 * data.  Warnings may be checked via the associated archive object.
	 * 
	 * @param file archive file (filename must end with DataTypeFileManager.SUFFIX)
	 * @param openForUpdate if true archive will be open for update
	 * @return data-type manager backed by specified packedDbFile
	 * @throws IOException if an IO error occurs
	 * @deprecated Use {@link DataTypeArchiveFactory#openReadOnly(File, Object, TaskMonitor)} or
	 * {@link DataTypeArchiveFactory#openForUpdate(File, boolean, Object, TaskMonitor)} to open
	 * a file based archive, then call {@link PersistentDataTypeArchive#getDataTypeManager()}
	 */
	@Deprecated(since = "12.2", forRemoval = true)
	public static FileDataTypeManager openFileArchive(File file, boolean openForUpdate)
			throws IOException {
		return openFileArchive(new ResourceFile(file), openForUpdate);
	}

	/**
	 * Open an existing data-type file archive using the default data organization.
	 * <p>
	 * <B>NOTE:</B> If archive has an assigned architecture, issues may arise due to a revised or
	 * missing {@link Language}/{@link CompilerSpec} which will result in a warning but not
	 * prevent the archive from being opened.  Such a warning condition will be logged and may 
	 * result in missing or stale information for existing datatypes which have architecture related
	 * data .  Warnings may be checked via the associated archive object.
	 * 
	 * @param file archive file (filename must end with DataTypeFileManager.SUFFIX)
	 * @param openForUpdate if true archive will be open for update
	 * @return data-type manager backed by specified packedDbFile
	 * @throws IOException if an IO error occurs
	 * @deprecated Use {@link DataTypeArchiveFactory#openReadOnly(ResourceFile, Object, TaskMonitor)} 
	 * or {@link DataTypeArchiveFactory#openForUpdate(ResourceFile, boolean, Object, TaskMonitor)} 
	 * to open a file based archive, then call {@link PersistentDataTypeArchive#getDataTypeManager()}
	 */
	@Deprecated(since = "12.2", forRemoval = true)
	public static FileDataTypeManager openFileArchive(ResourceFile file,
			boolean openForUpdate) throws IOException {
		FileDataTypeArchive archive;
		try {
			archive = openArchive(file, openForUpdate);
			return (FileDataTypeManager) archive.getDataTypeManager();
		}
		catch (CancelledException | VersionException e) {
			throw new IOException(e);
		}
	}

	private static FileDataTypeArchive openArchive(ResourceFile file, boolean openForUpdate)
			throws CancelledException, VersionException, IOException {
		Object consumer = new DefaultConsumer();
		if (!openForUpdate) {
			return DataTypeArchiveFactory.openReadOnly(file, consumer, TaskMonitor.DUMMY);
		}
		try {
			return DataTypeArchiveFactory.openForUpdate(file, false, consumer, TaskMonitor.DUMMY);
		}
		catch (VersionException e) {
			if (e.isUpgradable()) {
				return DataTypeArchiveFactory.openForUpdate(file, true, consumer,
					TaskMonitor.DUMMY);
			}
			throw e;
		}
	}

	/**
	 * {@return true if the archive has changed}
	 * @deprecated Use {@link PersistentDataTypeArchive#isChanged}
	 */
	@Deprecated(since = "12.2", forRemoval = true)
	public boolean isChanged();

	/**
	 * {@return true if the archive containing this datatype manager has been closed}
	 * @deprecated Use {@link PersistentDataTypeArchive#isClosed()}
	 */
	@Deprecated(since = "12.2", forRemoval = true)
	public boolean isClosed();

	/**
	 * Save the archive back to its original file.
	 * @throws IOException if IO error occurs
	 * @deprecated Use {@link FileDataTypeArchive#save(String, TaskMonitor)}
	 */
	@Deprecated(since = "12.2", forRemoval = true)
	public void save() throws IOException;

	/**
	 * Save the archive to a new file.
	 * @param outFile the file to write to
	 * @param newFileID the Universal id to use for the file. (Specialty use for creating an 
	 * new version of an archive while maintaining the same old id.)
	 * @throws DuplicateFileException if a file with that name already exists.
	 * @throws IOException if IO error occurs
	 * @deprecated Use {@link FileDataTypeArchive#saveAs(File, UniversalID)}
	 */
	@Deprecated(since = "12.2", forRemoval = true)
	public void saveAs(File outFile, UniversalID newFileID)
			throws DuplicateFileException, IOException;

	/**
	 * Save the archive to a new file.
	 * @param outFile the file to write to
	 * @throws IOException if IO error occurs
	 * @throws DuplicateFileException if a file with that name already exists.
	 * @deprecated Use {@link FileDataTypeArchive#saveAs(File, TaskMonitor)}
	 */
	@Deprecated(since = "12.2", forRemoval = true)
	public void saveAs(File outFile) throws DuplicateFileException, IOException;

}
