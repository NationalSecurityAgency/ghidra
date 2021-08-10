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

import db.DBConstants;
import generic.jar.ResourceFile;
import ghidra.framework.store.db.PackedDBHandle;
import ghidra.framework.store.db.PackedDatabase;
import ghidra.util.InvalidNameException;
import ghidra.util.UniversalID;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * DataTypeManager for a file. Can import categories from a file, or export
 * categories to a packed database.
 */
public class FileDataTypeManager extends StandAloneDataTypeManager
		implements FileArchiveBasedDataTypeManager {

	public final static String EXTENSION = "gdt"; // Ghidra Data Types
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
	 * @param packedDbfile file to load or create based upon openMode
	 * @param openMode one of the DBConstants: CREATE, UPDATE, READ_ONLY, UPGRADE 
	 * @throws IOException
	 */
	private FileDataTypeManager(ResourceFile packedDbfile, int openMode) throws IOException {
		super(validateFilename(packedDbfile), openMode);
		file = packedDbfile;
		name = getRootName(file.getName());
		packedDB = ((PackedDBHandle) dbHandle).getPackedDatabase();
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
	 * @throws IOException
	 */
	public static FileDataTypeManager createFileArchive(File packedDbfile) throws IOException {
		return new FileDataTypeManager(new ResourceFile(packedDbfile), DBConstants.CREATE);
	}

	/**
	 * Open an existing data-type file archive using the default data organization
	 * @param packedDbfile archive file (filename must end with DataTypeFileManager.SUFFIX)
	 * @param openForUpdate if true archive will be open for update
	 * @return data-type manager backed by specified packedDbFile
	 * @throws IOException
	 */
	public static FileDataTypeManager openFileArchive(File packedDbfile, boolean openForUpdate)
			throws IOException {
		return openFileArchive(new ResourceFile(packedDbfile), openForUpdate);
	}

	/**
	 * Open an existing data-type file archive using the default data organization
	 * @param packedDbfile archive file (filename must end with DataTypeFileManager.SUFFIX)
	 * @param openForUpdate if true archive will be open for update
	 * @return data-type manager backed by specified packedDbFile
	 * @throws IOException
	 */
	public static FileDataTypeManager openFileArchive(ResourceFile packedDbfile,
			boolean openForUpdate) throws IOException {
		int mode = openForUpdate ? DBConstants.UPDATE : DBConstants.READ_ONLY;
		return new FileDataTypeManager(packedDbfile, mode);
	}

	/**
	 * Saves the data type manager to the given file with a specific databaseId.
	 * NOTE: This method is intended for use in transforming one archive database to
	 * match another existing archive database.
	 * @param saveFile the file to save
	 * @param newUniversalId the new id to use
	 * @throws DuplicateFileException 
	 * @throws IOException 
	 */
	public void saveAs(File saveFile, UniversalID newUniversalId)
			throws DuplicateFileException, IOException {
		ResourceFile resourceSaveFile = new ResourceFile(saveFile);
// TODO: this should really be a package method and not public!
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
	}

	/**
	 * Saves the data type manager to the given file
	 * @param saveFile the file to save
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
	}

	/**
	 * Save the category to source file.
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
		catch (DuplicateNameException e) {
		}
		catch (InvalidNameException e) {
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
	public void close() {
		if (packedDB != null) {
			packedDB.dispose();
			packedDB = null;
		}
		super.close();
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
