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
package ghidra.program.model.dtarchive;

import java.io.File;
import java.io.IOException;

import generic.jar.ResourceFile;
import ghidra.util.UniversalID;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateFileException;
import ghidra.util.filechooser.ExtensionFileFilter;
import ghidra.util.filechooser.GhidraFileFilter;
import ghidra.util.task.TaskMonitor;

/**
 * {@link FileDataTypeArchive} corresponds to a stand-alone datatype archive that is stored
 * within a packed {@link File} on a native filesystem.  Read-only archives may also be accessed 
 * as a {@link ResourceFile} contained within a Java Archive (jar) resource.
 */
public interface FileDataTypeArchive extends PersistentDataTypeArchive {

	/**
	 * File extension for a datatype archive file. "gdt"
	 */
	public final static String EXTENSION = "gdt";

	/**
	 * Filename suffix for a datatype archive file. ".gdt"
	 */
	public final static String SUFFIX = "." + EXTENSION;

	/**
	 * File archive chooser filter
	 */
	public static final GhidraFileFilter GDT_FILEFILTER =
		ExtensionFileFilter.forExtensions("Ghidra Data Type Files", EXTENSION);

	/**
	 * Saves the data type manager to the given file
	 * @param outputFile the new output file
	 * @param monitor the TaskMonitor that can be used to cancel the operation
	 * @throws DuplicateFileException if output file already exists
	 * @throws IOException if IO error occurs
	 * @throws CancelledException if the user cancelled the operation
	 */
	public void saveAs(File outputFile, TaskMonitor monitor)
			throws DuplicateFileException, IOException, CancelledException;

	/**
	 * Saves the data type manager to the given file with a specific databaseId.
	 * NOTE: This method is intended for use in transforming one archive database to
	 * match another existing archive database.
	 * @param outputFile the new output file
	 * @param newUniversalId the new id to use
	 * @throws DuplicateFileException if output file already exists
	 * @throws IOException if IO error occurs
	 */
	public void saveAs(File outputFile, UniversalID newUniversalId)
			throws DuplicateFileException, IOException;

	/**
	 * {@return the {@link ResourceFile} that is where the data for this archive is stored}
	 */
	public ResourceFile getFile();

	/**
	 * Deletes this archive (deletes the underlying storage database file)
	 * @throws IOException if the file can't be deleted
	 */
	public void delete() throws IOException;

	/**
	 * {@return the UniversalId associated with this archive}
	 */
	public UniversalID getUniversalID();

}
