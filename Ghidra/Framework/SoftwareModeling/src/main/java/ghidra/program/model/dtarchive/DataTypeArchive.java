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

import java.io.IOException;

import ghidra.framework.store.LockException;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.IncompatibleLanguageException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Common interface of {@link DataTypeStore}s that are not a Program. 
 * <P>
 * The main difference between a DataTypeStore that is a program and those that are archives is the
 * idea of a {@link ProgramArchitecture}. Programs naturally have a program architecture since they
 * always have an underlying processor and compiler spec.  Archives, on the other hand, have
 * methods to handle when their associated program architecture is changed. Such a change
 * may require internal upgrading and bulk changes to the archive's data type store.
 */
public interface DataTypeArchive extends DataTypeStore {

	/**
	 * Returns true if this DataTypeManager can be modified.
	 * @return true if this DataTypeMangaer can be modified.
	 */
	public boolean isUpdatable();

	/**
	 * Indicates that a program architecture upgrade is required in order
	 * to constitute associated data.  If true, the associated archive
	 * must be open for update to allow the upgrade to complete, or a new
	 * program architecture may be set/cleared if such an operation is supported.
	 * @return true if a program architecture upgrade is required, else false
	 */
	public boolean isProgramArchitectureUpgradeRequired();

	/**
	 * Indicates that a failure occurred establishing the program architecture 
	 * for the associated archive.
	 * @return true if a failure occurred establishing the program architecture 
	 */
	public boolean isProgramArchitectureMissing();

	/**
	 * Establish the program architecture for this archive.  The current setting can be 
	 * determined from {@link #getProgramArchitecture()}.  Archive must be open for update for 
	 * this method to be used.
	 * <P>
	 * If there is no program architecture set, then a failure occurred. If the updateOption is 
	 * {@link LanguageUpdateOption#TRANSLATE}, the translator will be based on whatever language
	 * version can be found.  In this situation it may be best to force a 
	 * {@link LanguageUpdateOption#CLEAR}.
	 * 
	 * @param language processor language
	 * @param compilerSpecId compiler specification ID defined by the language.
	 * @param updateOption indicates how variable storage data should be transitioned. 
	 * @param monitor task monitor (cancel not permitted to avoid corrupt state)
	 * @throws CompilerSpecNotFoundException if invalid compilerSpecId specified for language
	 * @throws LanguageNotFoundException if current language is not found (if required for data
	 * transition)
	 * @throws IOException if IO error occurs
	 * @throws CancelledException if task cancelled.  If thrown, this data type manager is no longer 
	 * stable and should be closed without saving.
	 * @throws LockException failure if exclusive access is required
	 * @throws UnsupportedOperationException if architecture change is not permitted
	 * @throws IncompatibleLanguageException if translation requested but not possible due to
	 * incompatible language architectures
	 */
	public void setProgramArchitecture(Language language, CompilerSpecID compilerSpecId,
			LanguageUpdateOption updateOption, TaskMonitor monitor)
			throws CompilerSpecNotFoundException, LanguageNotFoundException, IOException,
			CancelledException, LockException, UnsupportedOperationException,
			IncompatibleLanguageException;

	/**
	 * Establish the program architecture for this archive.  The current setting can be 
	 * determined from {@link #getProgramArchitecture()}.  Archive must be open for update for 
	 * this method to be used.
	 * @param languageId valid processor language ID (see appropriate *.ldefs file for defined IDs)
	 * @param compilerSpecId valid compiler spec ID which corresponds to the language ID.
	 * @param updateOption indicates how variable storage data should be transitioned.  If 
	 * {@link #isProgramArchitectureMissing()} is true and {@link LanguageUpdateOption#TRANSLATE} 
	 * specified, the translator will be based on whatever language version can  be found.  In this 
	 * situation it may be best to force a  {@link LanguageUpdateOption#CLEAR}.
	 * @param monitor task monitor (cancel not permitted to avoid corrupt state)
	 * @throws CompilerSpecNotFoundException if invalid compilerSpecId specified for language
	 * @throws LanguageNotFoundException if current language is not found (if required for data transition)
	 * @throws IOException if IO error occurs
	 * @throws CancelledException if task cancelled.  If thrown, this data type manager is no longer 
	 * stable and should be closed without saving.
	 * @throws LockException failure if exclusive access is required
	 * @throws UnsupportedOperationException if architecture change is not permitted
	 * @throws IncompatibleLanguageException if translation requested but not possible due to incompatible language architectures
	 */
	public void setProgramArchitecture(LanguageID languageId, CompilerSpecID compilerSpecId,
			LanguageUpdateOption updateOption, TaskMonitor monitor)
			throws CompilerSpecNotFoundException, LanguageNotFoundException, IOException,
			CancelledException, LockException, UnsupportedOperationException,
			IncompatibleLanguageException;

	/**
	 * Clear the program architecture setting and all architecture-specific data from this archive.
	 * Archive will revert to using the default {@link DataOrganization}.
	 * Archive must be open for update for this method to be used.
	 * @param monitor task monitor
	 * @throws CancelledException if task cancelled.  If thrown, this data type manager is no longer 
	 * stable and should be closed without saving.
	 * @throws IOException if IO error occurs
	 * @throws LockException failure if exclusive access is required
	 * @throws UnsupportedOperationException if architecture change is not permitted by 
	 * implementation (e.g., {@link BuiltInDataTypeManager}).
	 */
	public void clearProgramArchitecture(TaskMonitor monitor)
			throws CancelledException, IOException, LockException;

	/**
	 * Get the {@link ArchiveWarning} which may have occured immediately following 
	 * instantiation of this {@link StandAloneDataTypeManager}.  {@link ArchiveWarning#NONE}
	 * will be returned if not warning condition.
	 * @return warning type.
	 */
	public ArchiveWarning getWarning();

	/**
	 * Get the detail exception associated with {@link ArchiveWarning#LANGUAGE_NOT_FOUND} or
	 * {@link ArchiveWarning#COMPILER_SPEC_NOT_FOUND} warning (see {@link #getWarning()})
	 * immediately following instantiation of this {@link StandAloneDataTypeManager}.
	 * @return warning detail exception or null
	 */
	public Exception getWarningDetail();

	/**
	 * Get a suitable warning message.  See {@link #getWarning()} for type and its severity level
	 * {@link ArchiveWarning#level()}.
	 * @param includeDetails if false simple message returned, otherwise more details are included.
	 * @return warning message or null if {@link #getWarning()} is {@link ArchiveWarning#NONE}.
	 */
	public String getWarningMessage(boolean includeDetails);

	/**
	 * Specifies how to handle a language update when setting the program architecture.
	 */
	public static enum LanguageUpdateOption {
		/**
		 * All existing storage data should be cleared
		 */
		CLEAR,
		/**
		 * An attempt should be made to translate from old-to-new language.
		 * This has limitations (i.e., similar architecture) and may result in 
		 * poor register mappings.
		 */
		TRANSLATE,
		/**
		 * Variable storage data will be retained as-is but may not de-serialize 
		 * properly when used.
		 */
		UNCHANGED // Note: Is this option safe?
	}

}
