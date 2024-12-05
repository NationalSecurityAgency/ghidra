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
import java.util.Objects;

import generic.jar.ResourceFile;
import ghidra.framework.data.OpenMode;
import ghidra.framework.store.LockException;
import ghidra.framework.store.db.PackedDBHandle;
import ghidra.framework.store.db.PackedDatabase;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.IncompatibleLanguageException;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.InvalidNameException;
import ghidra.util.UniversalID;
import ghidra.util.exception.*;
import ghidra.util.filechooser.ExtensionFileFilter;
import ghidra.util.filechooser.GhidraFileFilter;
import ghidra.util.task.TaskMonitor;

/**
 * DataTypeManager for a file. Can import categories from a file, or export
 * categories to a packed database.
 */
public class FileDataTypeManager extends StandAloneDataTypeManager
		implements FileArchiveBasedDataTypeManager {

	public final static String EXTENSION = "gdt"; // Ghidra Data Types
	public static final GhidraFileFilter GDT_FILEFILTER =
		ExtensionFileFilter.forExtensions("Ghidra Data Type Files", EXTENSION);

	/**
	 * Suffix for an archive file.
	 */
	public final static String SUFFIX = "." + EXTENSION;

	final static String OLD_EXTENSION = "dtf";
	final static String OLD_SUFFIX = "." + OLD_EXTENSION;

	private ResourceFile file;
	private PackedDatabase packedDB;

	/**
	 * Construct a new DataTypeFileManager using the default data organization.
	 * <p>
	 * <B>NOTE:</B> it may be appropriate to {@link #getWarning() check for warnings} after
	 * opening an existing archive file prior to use.  While an archive will remain useable 
	 * with a warning condition, architecture-specific data may not be available or up-to-date.
	 * 
	 * @param packedDbfile file to load or create based upon openMode
	 * @param openMode CREATE, READ_ONLY or UPDATE
	 * @param monitor the progress monitor
	 * @throws IOException if an IO error occurs
	 * @throws CancelledException if task cancelled
	 */
	private FileDataTypeManager(ResourceFile packedDbfile, OpenMode openMode, TaskMonitor monitor)
			throws IOException, CancelledException {
		super(validateFilename(packedDbfile), openMode, monitor);
		file = packedDbfile;
		name = getRootName(file.getName());
		packedDB = ((PackedDBHandle) dbHandle).getPackedDatabase();
		logWarning();
		if (openMode == OpenMode.IMMUTABLE) {
			setImmutable();
		}
	}

	private static ResourceFile validateFilename(ResourceFile packedDbfile) {
		if (!packedDbfile.getName().endsWith(SUFFIX)) {
			throw new IllegalArgumentException("Archive files must end with " + SUFFIX);
		}
		return packedDbfile;
	}

	/**
	 * Create a new data-type file archive using the default data organization
	 * @param packedDbfile archive file (filename must end with DataTypeFileManager.SUFFIX)
	 * @return data-type manager backed by specified packedDbFile
	 * @throws IOException if an IO error occurs
	 */
	public static FileDataTypeManager createFileArchive(File packedDbfile) throws IOException {
		try {
			return new FileDataTypeManager(new ResourceFile(packedDbfile), OpenMode.CREATE,
				TaskMonitor.DUMMY);
		}
		catch (CancelledException e) {
			throw new AssertException(e); // unexpected without task monitor use
		}
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
	 */
	public static FileDataTypeManager createFileArchive(File packedDbFile, LanguageID languageId,
			CompilerSpecID compilerSpecId)
			throws LanguageNotFoundException, CompilerSpecNotFoundException, IOException {
		Objects.requireNonNull(languageId, "missing required languageId");
		Objects.requireNonNull(compilerSpecId, "missing required compilerSpecId");
		try {
			if (packedDbFile.exists()) {
				throw new DuplicateFileException("File already exists: " + packedDbFile);
			}

			// Verify that the specified language and compiler spec are valid 
			LanguageService languageService = DefaultLanguageService.getLanguageService();
			Language language = languageService.getLanguage(languageId);
			language.getCompilerSpecByID(compilerSpecId);

			FileDataTypeManager dtm =
				new FileDataTypeManager(new ResourceFile(packedDbFile), OpenMode.CREATE,
					TaskMonitor.DUMMY);

			dtm.setProgramArchitecture(language, compilerSpecId, LanguageUpdateOption.CLEAR,
				TaskMonitor.DUMMY);

			return dtm;
		}
		catch (CancelledException e) {
			throw new AssertException(e); // unexpected without task monitor use
		}
		catch (LockException | IncompatibleLanguageException | UnsupportedOperationException e) {
			throw new RuntimeException(e); // unexpected for new archive
		}
	}

	/**
	 * Create a new data-type file archive using the default data organization.
	 * @param packedDbfile archive file (filename must end with DataTypeFileManager.SUFFIX)
	 * @param languageId valid language ID (see appropriate *.ldefs file for defined IDs).  If null
	 * invocation will be deferred to {@link #createFileArchive(File)}.
	 * @param compilerSpecId valid compiler spec ID which corresponds to the language ID.
	 * @return data-type manager backed by the specified packedDbFile
	 * @throws LanguageNotFoundException if specified {@code languageId} not defined. 
	 * @throws CompilerSpecNotFoundException if specified {@code compilerSpecId} is not defined 
	 * for the specified language. 
	 * @throws IOException if an IO error occurs
	 */
	public static FileDataTypeManager createFileArchive(File packedDbfile, String languageId,
			String compilerSpecId) throws IOException {
		if (languageId == null) {
			if (compilerSpecId != null) {
				throw new IllegalArgumentException("compilerSpecId specified without languageId");
			}
			return createFileArchive(packedDbfile);
		}
		if (compilerSpecId == null) {
			throw new IllegalArgumentException("languageId specified without compilerSpecId");
		}
		return createFileArchive(packedDbfile, new LanguageID(languageId),
			new CompilerSpecID(compilerSpecId));
	}

	/**
	 * Open an existing data-type file archive using the default data organization.
	 * <p>
	 * <B>NOTE:</B> If archive has an assigned architecture, issues may arise due to a revised or
	 * missing {@link Language}/{@link CompilerSpec} which will result in a warning but not
	 * prevent the archive from being opened.  Such a warning condition will ne logged and may 
	 * result in missing or stale information for existing datatypes which have architecture related
	 * data.  In some case it may be appropriate to 
	 * {@link FileDataTypeManager#getWarning() check for warnings} on the returned archive
	 * object prior to its use.
	 * 
	 * @param packedDbfile archive file (filename must end with DataTypeFileManager.SUFFIX)
	 * @param openForUpdate if true archive will be open for update
	 * @return data-type manager backed by specified packedDbFile
	 * @throws IOException if an IO error occurs
	 */
	public static FileDataTypeManager openFileArchive(File packedDbfile, boolean openForUpdate)
			throws IOException {
		return openFileArchive(new ResourceFile(packedDbfile), openForUpdate);
	}

	/**
	 * Open an existing data-type file archive using the default data organization.
	 * <p>
	 * <B>NOTE:</B> If archive has an assigned architecture, issues may arise due to a revised or
	 * missing {@link Language}/{@link CompilerSpec} which will result in a warning but not
	 * prevent the archive from being opened.  Such a warning condition will ne logged and may 
	 * result in missing or stale information for existing datatypes which have architecture related
	 * data.  In some case it may be appropriate to 
	 * {@link FileDataTypeManager#getWarning() check for warnings} on the returned archive
	 * object prior to its use.
	 * 
	 * @param packedDbfile archive file (filename must end with DataTypeFileManager.SUFFIX)
	 * @param openForUpdate if true archive will be open for update
	 * @return data-type manager backed by specified packedDbFile
	 * @throws IOException if an IO error occurs
	 */
	public static FileDataTypeManager openFileArchive(ResourceFile packedDbfile,
			boolean openForUpdate) throws IOException {
		OpenMode mode = openForUpdate ? OpenMode.UPDATE : OpenMode.IMMUTABLE;
		try {
			return new FileDataTypeManager(packedDbfile, mode, TaskMonitor.DUMMY);
		}
		catch (CancelledException e) {
			throw new AssertException(e); // unexpected without task monitor use
		}
	}

	/**
	 * Saves the data type manager to the given file with a specific databaseId.
	 * NOTE: This method is intended for use in transforming one archive database to
	 * match another existing archive database.
	 * @param saveFile the file to save
	 * @param newUniversalId the new id to use
	 * @throws DuplicateFileException if save file already exists
	 * @throws IOException if IO error occurs
	 */
	public void saveAs(File saveFile, UniversalID newUniversalId)
			throws DuplicateFileException, IOException {
		ResourceFile resourceSaveFile = new ResourceFile(saveFile);
		validateFilename(resourceSaveFile);
		try {
			universalID = newUniversalId;
			packedDB = ((PackedDBHandle) dbHandle).saveAs("DTArchive", saveFile.getParentFile(),
				saveFile.getName(), newUniversalId.getValue(), TaskMonitor.DUMMY);
			file = resourceSaveFile;
			updateRootCategoryName(resourceSaveFile, getRootCategory());
		}
		catch (CancelledException e) {
			// Cancel can't happen because we are using a dummy monitor
		}
		finally {
			clearUndo();
		}
	}

	/**
	 * Saves the data type manager to the given file
	 * @param saveFile the file to save
	 * @throws DuplicateFileException if save file already exists
	 * @throws IOException if IO error occurs
	 */
	public void saveAs(File saveFile) throws DuplicateFileException, IOException {
		ResourceFile resourceSaveFile = new ResourceFile(saveFile);
		validateFilename(resourceSaveFile);
		try {
			packedDB = ((PackedDBHandle) dbHandle).saveAs("DTArchive", saveFile.getParentFile(),
				saveFile.getName(), TaskMonitor.DUMMY);
			file = resourceSaveFile;
			updateRootCategoryName(resourceSaveFile, getRootCategory());
		}
		catch (CancelledException e) {
			// Cancel can't happen because we are using a dummy monitor
		}
		finally {
			clearUndo();
		}
	}

	/**
	 * Save the category to source file.
	 * @throws IOException if IO error occurs
	 */
	public void save() throws IOException {

		if (file == null) {
			throw new IllegalStateException("Output File was not specified: call saveAs(String)");
		}

		try {
			((PackedDBHandle) dbHandle).save(TaskMonitor.DUMMY);
		}
		catch (CancelledException e) {
			// Cancel can't happen because we are using a dummy monitor
		}
		finally {
			clearUndo();
		}
	}

	/**
	 * Get the filename for the current file.
	 * 
	 * @return String filename, or null if there is no current file.
	 */
	public String getFilename() {
		if (file != null) {
			return file.getAbsolutePath();
		}
		return null;
	}

	/**
	 * Convert the filename for the given file to have the packed database
	 * file extension.
	 * @param file file whose name is to be converted
	 * @return file if the filename already ends in the packed database
	 * file extension, or a new File object that has the packed database
	 * file extension
	 */
	public static File convertFilename(File file) {
		String fname = file.getName();
		if (file.getName().endsWith(SUFFIX)) {
			return file;
		}
		int pos = fname.indexOf(OLD_SUFFIX);
		if (pos > 0) {
			fname = fname.substring(0, pos);
		}
		fname = fname + SUFFIX;
		return new File(file.getParentFile(), fname);
	}

	private void updateRootCategoryName(ResourceFile newFile, Category root) {
		String newName = getRootName(newFile.getName());

		if (root.getName().equals(newName)) {
			return;
		}

		try {
			root.setName(newName);
		}
		catch (InvalidNameException | DuplicateNameException e) {
			// do nothing
		}
	}

	private String getRootName(String newName) {
		int pos = newName.lastIndexOf(SUFFIX);
		if (pos > 0) {
			newName = newName.substring(0, pos);
		}
		return newName;
	}

	public void delete() throws IOException {
		super.close();
		if (packedDB != null) {
			packedDB.delete();
			packedDB = null;
		}
	}

	@Override
	public synchronized void close() {
		if (packedDB != null) {
			super.close();
			packedDB.dispose();
			packedDB = null;
		}
	}

	public boolean isClosed() {
		return packedDB == null;
	}

	@Override
	public void finalize() {
		close();
	}

	public static void delete(File packedDbfile) throws IOException {
		if (packedDbfile == null) {
			return;
		}
		String filename = packedDbfile.getAbsolutePath();
		if (filename.endsWith(OLD_SUFFIX)) {
			packedDbfile.delete();
		}
		else {
			PackedDatabase.delete(packedDbfile);
		}
	}

	@Override
	public String getPath() {
		return (file != null) ? file.getAbsolutePath() : null; // TODO Is this correct?
	}

	@Override
	public ArchiveType getType() {
		return ArchiveType.FILE;
	}

	@Override
	public String toString() {
		return getClass().getSimpleName() + " - " + getName();
	}
}

