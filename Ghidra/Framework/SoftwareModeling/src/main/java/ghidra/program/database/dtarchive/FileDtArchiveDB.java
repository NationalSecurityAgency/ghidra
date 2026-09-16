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

import static ghidra.program.database.dtarchive.DataTypeArchiveContentHandler.*;

import java.io.File;
import java.io.IOException;
import java.util.Objects;

import javax.help.UnsupportedOperationException;

import db.DBHandle;
import generic.jar.ResourceFile;
import ghidra.framework.data.DomainFileProxy;
import ghidra.framework.data.OpenMode;
import ghidra.framework.model.DomainObjectChangeRecord;
import ghidra.framework.model.DomainObjectEvent;
import ghidra.framework.store.LockException;
import ghidra.framework.store.db.PackedDBHandle;
import ghidra.framework.store.db.PackedDatabase;
import ghidra.program.database.data.FileDataTypeManagerDB;
import ghidra.program.model.data.ArchiveType;
import ghidra.program.model.data.FileDataTypeManager;
import ghidra.program.model.dtarchive.FileDataTypeArchive;
import ghidra.program.model.dtarchive.PersistentDataTypeArchive;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.IncompatibleLanguageException;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.UniversalID;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * Datatype archives that are stored in stand-alone files (packed database files).
 */
public class FileDtArchiveDB extends DataTypeArchiveDB implements FileDataTypeArchive {
	private FileDtArchiveDB(DBHandle dbh, String name, Object consumer)
			throws IOException {
		super(dbh, name, consumer);
	}

	private FileDtArchiveDB(DBHandle dbh, String name, OpenMode openMode, Object consumer,
			TaskMonitor monitor) throws IOException, VersionException, CancelledException {
		super(dbh, name, openMode, monitor, consumer);
	}

	@Override
	protected FileDataTypeManagerDB createDataTypeManager(DBHandle handle, OpenMode openMode,
			TaskMonitor monitor)
			throws VersionException, IOException, CancelledException {
		return new FileDataTypeManagerDB(handle, openMode, this, lock, monitor);
	}

	/**
	 * Used for backwards compatibility so the the deprecated {@link FileDataTypeManager#close()}
	 * can still work and close an archive regardless of its consumers. This method does not
	 * play well with others and will be removed in a future release.
	 * @deprecated this should be removed when the deprecated close() method is removed.
	 */
	@Deprecated
	public void releaseDefaultConsumers() {
		for (Object consumer : getConsumerList()) {
			if (consumer instanceof DefaultConsumer) {
				release(consumer);
			}
		}
	}

	@Override
	public boolean isTemporary() {
		return true;
	}

	@Override
	public ArchiveType getArchiveType() {
		return ArchiveType.FILE;
	}

	@Override
	public FileDataTypeManagerDB getDataTypeManager() {
		return (FileDataTypeManagerDB) super.getDataTypeManager();
	}

	@Override
	public UniversalID getUniversalID() {
		return dataTypeManager.getUniversalID();
	}

	@Override
	public String getDescription() {
		return "File Based Data Type Archive";
	}

	/**
	 * Saves the data type manager to the given file
	 * @param saveFile the file to save
	 * @throws DuplicateFileException if save file already exists
	 * @throws IOException if IO error occurs
	 * @throws CancelledException if cancelled
	 */
	@Override
	public void saveAs(File saveFile, TaskMonitor monitor)
			throws DuplicateFileException, IOException, CancelledException {
		ResourceFile resourceSaveFile = new ResourceFile(saveFile);
		validateFilename(resourceSaveFile);
		try {
			((PackedDBHandle) dbh).saveAs("DTArchive", saveFile.getParentFile(),
				saveFile.getName(), monitor);
			String fileName = saveFile.getName();
			if (fileName.endsWith(SUFFIX)) {
				fileName = fileName.substring(0, fileName.length() - SUFFIX.length());
			}
			setName(fileName);
			dataTypeManager.updateID();
		}
		finally {
			clearUndo();
		}
	}

	/**
	 * Saves the data type archive to the given file with a specific databaseId.
	 * NOTE: This method is intended for use in transforming one archive database to
	 * match another existing archive database.
	 * @param saveFile the file to save
	 * @param newUniversalId the new id to use
	 * @throws DuplicateFileException if save file already exists
	 * @throws IOException if IO error occurs
	 */
	@Override
	public void saveAs(File saveFile, UniversalID newUniversalId)
			throws DuplicateFileException, IOException {
		ResourceFile resourceSaveFile = new ResourceFile(saveFile);
		validateFilename(resourceSaveFile);
		try {
			((PackedDBHandle) dbh).saveAs("DTArchive", saveFile.getParentFile(),
				saveFile.getName(), newUniversalId.getValue(), TaskMonitor.DUMMY);
			String fileName = saveFile.getName();
			setName(fileName);
			dataTypeManager.updateID();
		}
		catch (CancelledException e) {
			// Cancel can't happen because we are using a dummy monitor
		}
		finally {
			clearUndo();
		}

	}

	@Override
	public void save(String comment, TaskMonitor monitor) throws IOException, CancelledException {
		if (!lock("save")) {
			throw new IOException("Unable to lock due to active transaction");
		}
		boolean wasSaved = false;
		try {
			((PackedDBHandle) dbh).save(monitor);
		}
		catch (CancelledException e) {
			// Cancel can't happen because we are using a dummy monitor
		}
		finally {
			clearUndo();
			unlock();
		}

		if (wasSaved) {
			fireEvent(new DomainObjectChangeRecord(DomainObjectEvent.SAVED));
		}
	}

	@Override
	public synchronized boolean canSave() {
		return isChangeable() && isChanged();
	}

	public String getFileName() {
		PackedDatabase packedDatabase = ((PackedDBHandle) dbh).getPackedDatabase();
		ResourceFile packedFile = packedDatabase.getPackedFile();
		return packedFile.getName();
	}

	@Override
	public ResourceFile getFile() {
		PackedDatabase packedDatabase = ((PackedDBHandle) dbh).getPackedDatabase();
		return packedDatabase.getPackedFile();
	}

	@Override
	public String getPath() {
		return getFile().getAbsolutePath();
	}

	@Override
	public void delete() throws IOException {
		PackedDatabase packedDB = ((PackedDBHandle) dbh).getPackedDatabase();
		super.close();
		if (packedDB != null) {
			packedDB.delete();
			packedDB = null;
		}
	}

	@Override
	public DomainFileProxy getDomainFile() {
		return (DomainFileProxy) super.getDomainFile();
	}

	@Override
	public void setName(String newName) {
		getDomainFile().setName(newName);
	}

//==================================================================================================
// Static methods
//==================================================================================================
	/**
	 * Opens the FileDtArchive stored in the given packed database file.
	 * @param packedDbFile the packed database resource file storing the archive's data
	 * @param consumer The object that is using this potentially shared archive. The caller of
	 * this method is expected to call {@link PersistentDataTypeArchive#release(Object)} using this same
	 * consumer when done using this archive.
	 * @param monitor the task monitor to use while opening the archive
	 * @return the newly opened FileDtArchive
	 * @throws CancelledException if the task to open the archive was cancelled
	 * @throws IOException If an I/O error occurs reading from the database file
	 * @throws VersionException if the file is not the current version and doesn't support read
	 * only mode for that file's stored version, or if the file's version is newer than the
	 * expected current version for the software running.
	 */
	static FileDtArchiveDB openReadOnly(ResourceFile packedDbFile, Object consumer,
			TaskMonitor monitor) throws CancelledException, IOException, VersionException {
		DBHandle dbh = openDb(packedDbFile, false, monitor);
		String name = getRootName(packedDbFile.getName());

		return new FileDtArchiveDB(dbh, name, OpenMode.IMMUTABLE, consumer, monitor);
	}

	/**
	 * Opens the FileDtArchive stored in the given packed database file.
	 * @param packedDbFile the packed database resource file storing the archive's data
	 * @param okToUpgrade If true, the file will be upgraded to the current version if it is not
	 * the current version and can be upgraded.
	 * @param consumer The object that is using this potentially shared archive. The caller of
	 * this method is expected to call {@link PersistentDataTypeArchive#release(Object)} using this same
	 * consumer when done using this archive.
	 * @param monitor the task monitor to use while opening the archive
	 * @return the newly opened FileDtArchive
	 * @throws CancelledException if the task to open the archive was cancelled
	 * @throws IOException If an I/O error occurs reading from the database file
	 * @throws VersionException If the okToUpgrade is false and the file version is not the current
	 * version. If the okToUpgrade is true, then a version exception is only thrown if the file is
	 * an older version and there is no upgrade path to the current version.
	 */
	static FileDtArchiveDB openForUpdate(ResourceFile packedDbFile, boolean okToUpgrade,
			Object consumer, TaskMonitor monitor)
			throws CancelledException, IOException, VersionException {
		DBHandle dbh = openDb(packedDbFile, true, monitor);
		String name = getRootName(packedDbFile.getName());

		OpenMode openMode = okToUpgrade ? OpenMode.UPGRADE : OpenMode.UPDATE;
		return new FileDtArchiveDB(dbh, name, openMode, consumer, monitor);
	}

	/**
	 * Creates a new FileDtArchive and stores it into the given output file.
	 * @param outputFile the file to write the new FileDtArchive data to when saved
	 * @param consumer The object that is using this potentially shared archive. The caller of
	 * this method is expected to call {@link PersistentDataTypeArchive#release(Object)} using this same
	 * consumer when done using this archive.
	 * @return the newly created FileDtArchive
	 * @throws IOException if an I/O error occurs writing to the output file
	 */
	static FileDtArchiveDB create(File outputFile, Object consumer) throws IOException {
		if (outputFile.exists()) {
			throw new DuplicateFileException("File already exists: " + outputFile);
		}

		PackedDBHandle dbh = new PackedDBHandle(DATA_TYPE_ARCHIVE_CONTENT_TYPE);
		FileDtArchiveDB archive =
			new FileDtArchiveDB(dbh, getRootName(outputFile.getName()), consumer);
		try {
			dbh.saveAs("Archive", outputFile.getParentFile(),
				outputFile.getName(), null, TaskMonitor.DUMMY);
		}
		catch (CancelledException e) {
			// can't happen with a DUMMY task monitor
		}
		return archive;
	}

	/**
	 * Creates a new FileDtArchive and stores it into the given output file.
	 * @param outputFile the file to write the new FileDtArchive data to when saved
	 * @param languageId the id of the language to use for determining datatype organization details
	 * @param compilerSpecId the id of the compilerSpec to use for determining datatype organization
	 * details
	 * @param consumer The object that is using this potentially shared archive. The caller of
	 * this method is expected to call {@link PersistentDataTypeArchive#release(Object)} using this same
	 * consumer when done using this archive.
	 * @return the newly created FileDtArchive
	 * @throws IOException if an I/O error occurs writing to the output file
	 */
	static FileDtArchiveDB create(File outputFile, LanguageID languageId,
			CompilerSpecID compilerSpecId, Object consumer) throws IOException {
		Objects.requireNonNull(languageId, "missing required languageId");
		Objects.requireNonNull(compilerSpecId, "missing required compilerSpecId");
		if (outputFile.exists()) {
			throw new DuplicateFileException("File already exists: " + outputFile);
		}
		FileDtArchiveDB archive = create(outputFile, consumer);
		try {
			// Verify that the specified language and compiler spec are valid 
			LanguageService languageService = DefaultLanguageService.getLanguageService();
			Language language = languageService.getLanguage(languageId);
			language.getCompilerSpecByID(compilerSpecId);

			archive.setProgramArchitecture(language, compilerSpecId, LanguageUpdateOption.CLEAR,
				TaskMonitor.DUMMY);
		}
		catch (CancelledException e) {
			// can't happen with a DUMMY task monitor
		}
		catch (LockException | IncompatibleLanguageException | UnsupportedOperationException e) {
			throw new RuntimeException(e); // unexpected for new archive
		}

		return archive;
	}

	/**
	 * Create a new data-type file archive using the specified language/compiler spec
	 * @param packedDbfile archive file (filename must end with DataTypeFileManager.SUFFIX)
	 * @param languageId valid language ID (see appropriate *.ldefs file for defined IDs).  If null
	 * invocation will be deferred to {@link #create(File, Object)}.
	 * @param compilerSpecId valid compiler spec ID which corresponds to the language ID.
	 * @param consumer The object that is using this potentially shared archive. The caller of
	 * this method is expected to call {@link PersistentDataTypeArchive#release(Object)} using this same
	 * consumer when done using this archive.
	 * @return data-type manager backed by the specified packedDbFile
	 * @throws LanguageNotFoundException if specified {@code languageId} not defined. 
	 * @throws CompilerSpecNotFoundException if specified {@code compilerSpecId} is not defined 
	 * for the specified language. 
	 * @throws IOException if an IO error occurs
	 */
	public static FileDataTypeArchive create(File packedDbfile, String languageId,
			String compilerSpecId, Object consumer) throws IOException {

		if (languageId == null && compilerSpecId != null) {
			throw new IllegalArgumentException("compilerSpecId specified without languageId");
		}
		if (languageId != null && compilerSpecId == null) {
			throw new IllegalArgumentException("languageId specified without compilerSpecId");
		}

		if (languageId == null) {
			return create(packedDbfile, consumer);
		}
		return create(packedDbfile, new LanguageID(languageId),
			new CompilerSpecID(compilerSpecId), consumer);
	}

	private static DBHandle openDb(ResourceFile packedDbFile, boolean openForUpdate,
			TaskMonitor monitor) throws IOException, CancelledException {
		validateFilename(packedDbFile);
		File file = packedDbFile.getFile(false);
		if (file == null && openForUpdate) {
			throw new IOException("Attempted to open for update a read-only Datatype Archive: " +
				packedDbFile.getAbsolutePath());
		}

		// Open packed database archive
		PackedDatabase pdb = null;
		DBHandle dbh = null;
		try {

			pdb = PackedDatabase.getPackedDatabase(packedDbFile, false, monitor);

			if (!DataTypeArchiveContentHandler.DATA_TYPE_ARCHIVE_CONTENT_TYPE
					.equals(pdb.getContentType())) {
				throw new IOException("File is not a Datatype Archive: " + packedDbFile.getName());
			}

			if (openForUpdate) {
				dbh = pdb.openForUpdate(monitor);
			}
			else {
				dbh = pdb.open(monitor);
			}
		}
		finally {
			if (dbh == null && pdb != null) {
				pdb.dispose(); // dispose on error
			}
		}
		return dbh;
	}

	private static String getRootName(String filename) {
		int pos = filename.lastIndexOf(SUFFIX);
		if (pos > 0) {
			filename = filename.substring(0, pos);
		}
		return filename;
	}

	private static ResourceFile validateFilename(ResourceFile packedDbfile) {
		if (!packedDbfile.getName().endsWith(SUFFIX)) {
			throw new IllegalArgumentException("Archive files must end with " + SUFFIX);
		}
		return packedDbfile;
	}

}
