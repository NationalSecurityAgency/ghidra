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

import static ghidra.program.model.dtarchive.FileDataTypeArchive.*;

import java.io.File;
import java.io.IOException;

import db.DBHandle;
import db.util.ErrorHandler;
import ghidra.framework.data.OpenMode;
import ghidra.framework.store.db.PackedDatabase;
import ghidra.program.database.dtarchive.FileDtArchiveDB;
import ghidra.program.model.data.*;
import ghidra.program.model.dtarchive.DataTypeArchive;
import ghidra.util.Lock;
import ghidra.util.UniversalID;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

public class FileDataTypeManagerDB extends ArchiveDataTypeManagerDB
		implements FileDataTypeManager {

	final static String OLD_EXTENSION = "dtf";
	final static String OLD_SUFFIX = "." + OLD_EXTENSION;

	/**
	 * Construct a new DataTypeFileManager using the default data organization.
	 * <p>
	 * <B>NOTE:</B> it may be appropriate to {@link DataTypeArchive#getWarning() check for warnings} 
	 * after opening an existing archive file prior to use.  While an archive will remain useable 
	 * with a warning condition, architecture-specific data may not be available or up-to-date.
	 * @param handle the open database handle
	 * @param openMode CREATE, READ_ONLY or UPDATE
	 * @param errHandler the object to report errors
	 * @param lock the database lock.
	 * @param monitor the progress monitor
	 * @throws IOException if an IO error occurs
	 * @throws CancelledException if task cancelled
	 * @throws VersionException if the datatype database is not the correct version
	 */
	public FileDataTypeManagerDB(DBHandle handle, OpenMode openMode,
			ErrorHandler errHandler, Lock lock, TaskMonitor monitor)
			throws IOException, CancelledException, VersionException {
		super(handle, openMode, errHandler, lock, monitor);
	}

	@Override
	public FileDtArchiveDB getDataStore() {
		return (FileDtArchiveDB) super.getDataStore();
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
	@Override
	public void saveAs(File saveFile, UniversalID newUniversalId)
			throws DuplicateFileException, IOException {
		getDataStore().saveAs(saveFile, newUniversalId);

	}

	/**
	 * Saves the data type manager to the given file
	 * @param saveFile the file to save
	 * @throws DuplicateFileException if save file already exists
	 * @throws IOException if IO error occurs
	 */
	@Override
	public void saveAs(File saveFile) throws DuplicateFileException, IOException {
		try {
			getDataStore().saveAs(saveFile, TaskMonitor.DUMMY);
		}
		catch (CancelledException e) {
			// can't happen since we used a DUMMY monitor
		}
	}

	/**
	 * Save the category to source file.
	 * @throws IOException if IO error occurs
	 */
	@Override
	public void save() throws IOException {
		try {
			getDataStore().save(null, TaskMonitor.DUMMY);
		}
		catch (CancelledException e) {
			// can't happen since we are using a DUMMY TaskMonitor
		}
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

	public void notifyNameChange() {
		defaultListener.categoryRenamed(this, CategoryPath.ROOT, CategoryPath.ROOT);
	}

	@Override
	public boolean isClosed() {
		return archive.isClosed();
	}

	@Override
	public void finalize() {
		close();
	}

	public void delete() throws IOException {
		getDataStore().delete();
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
		return archive.getPath();
	}

	@Override
	public ArchiveType getType() {
		return ArchiveType.FILE;
	}

	@Override
	@Deprecated(since = "12.2", forRemoval = true)
	public void close() {
		if (!archive.isClosed()) {
			getDataStore().releaseDefaultConsumers();
		}
	}

	@Override
	public String toString() {
		return getClass().getSimpleName() + " - " + getName();
	}

}
