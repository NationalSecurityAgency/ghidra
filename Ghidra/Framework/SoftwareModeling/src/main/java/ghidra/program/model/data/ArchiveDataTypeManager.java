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

import java.io.IOException;
import java.util.List;

import javax.help.UnsupportedOperationException;

import ghidra.framework.store.LockException;
import ghidra.program.model.dtarchive.*;
import ghidra.program.model.dtarchive.DataTypeArchive.LanguageUpdateOption;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.IncompatibleLanguageException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * {@link ArchiveDataTypeManager} provides datatype management interface for 
 * {@link PersistentDataTypeArchive stand-alone datatype archives}.
 */
public interface ArchiveDataTypeManager extends DataTypeManager {

	@Override
	public DataTypeArchive getDataStore();

	/**
	 * Get the path name associated with the storage of this datatype manager's archive. 
	 * @return path name or null if not applicable
	 * @deprecated use {@link DataTypeStore#getPath()} instead. (After calling getDataStore())
	 */
	@Deprecated(since = "12.2", forRemoval = true)
	public default String getPath() {
		return null;
	}

	/**
	 * Establish the program architecture for this datatype manager.  The current setting can be 
	 * determined from {@link #getProgramArchitecture()}.  Archive must be open for update for 
	 * this method to be used.
	 * @param language language
	 * @param compilerSpecId compiler specification ID defined by the language.
	 * @param updateOption indicates how variable storage data should be transitioned.  If 
	 * {@link DataTypeArchive#isProgramArchitectureMissing()} is true and 
	 * {@link LanguageUpdateOption#TRANSLATE} specified, the translator will be based on whatever 
	 * language version can be found.  In this situation it may be best to force a 
	 * {@link LanguageUpdateOption#CLEAR}.
	 * @param monitor task monitor (cancel not permitted to avoid corrupt state)
	 * @throws CompilerSpecNotFoundException if invalid compilerSpecId specified for language
	 * @throws LanguageNotFoundException if current language is not found (if required for data transition)
	 * @throws IOException if IO error occurs
	 * @throws CancelledException if task cancelled.  If thrown, this data type manager is no longer 
	 * stable and should be closed without saving.
	 * @throws LockException failure if exclusive access is required
	 * @throws UnsupportedOperationException if architecture change is not permitted
	 * @throws IncompatibleLanguageException if translation requested but not possible due to incompatible language architectures
	 * @deprecated use {@link PersistentDataTypeArchive#setProgramArchitecture(Language, CompilerSpecID, LanguageUpdateOption, TaskMonitor)}
	 * on the associated archive.
	 */
	@Deprecated(since = "12.2", forRemoval = true)
	public default void setProgramArchitecture(Language language, CompilerSpecID compilerSpecId,
			LanguageUpdateOption updateOption, TaskMonitor monitor)
			throws CompilerSpecNotFoundException, LanguageNotFoundException, IOException,
			CancelledException, LockException, UnsupportedOperationException,
			IncompatibleLanguageException {
		getDataStore().setProgramArchitecture(language, compilerSpecId, updateOption, monitor);
	}

	/**
	 * Undo the last transaction if available
	 */
	public void undo();

	/**
	 * Redo the previous undo if available
	 */
	public void redo();

	/**
	 * Determine if there is a transaction previously undone (see {@link #undo()}) that can be 
	 * redone (see {@link #redo()}).
	 * 
	 * @return true if there is a transaction previously undone that can be redone, else false
	 */
	public boolean canRedo();

	/**
	 * Determine if there is a previous transaction that can be reverted/undone (see {@link #undo()}).
	 * 
	 * @return true if there is a previous transaction that can be reverted/undone, else false.
	 */
	public boolean canUndo();

	/**
	 * Get the transaction name that is available for {@link #redo()} (see {@link #canRedo()}).
	 * @return transaction name that is available for {@link #redo()} or empty String.
	 */
	public String getRedoName();

	/**
	 * Get the transaction name that is available for {@link #undo()} (see {@link #canUndo()}).
	 * @return transaction name that is available for {@link #undo()} or empty String.
	 */
	public String getUndoName();

	/**
	 * Get all transaction names that are available within the {@link #undo()} stack.
	 * 
	 * @return all transaction names that are available within the {@link #undo()} stack.
	 */
	public List<String> getAllUndoNames();

	/**
	 * Get all transaction names that are available within the {@link #redo()} stack.
	 * 
	 * @return all transaction names that are available within the {@link #redo()} stack.
	 */
	public List<String> getAllRedoNames();
}
