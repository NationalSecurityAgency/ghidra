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

import java.io.IOException;

import javax.help.UnsupportedOperationException;

import ghidra.framework.model.RuntimeIOException;
import ghidra.framework.store.LockException;
import ghidra.program.database.dtarchive.TransientDtArchiveDB;
import ghidra.program.model.data.ArchiveType;
import ghidra.program.model.data.DataOrganization;
import ghidra.program.model.dtarchive.DataTypeArchive.LanguageUpdateOption;
import ghidra.program.model.dtarchive.TransientDataTypeArchive;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.IncompatibleLanguageException;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * {@link TransientDataTypeManager} provides a transient/temporary datatype manager that is meant to 
 * be used as a temporary scratch pad for resolving datatype relationships.
 */
public class TransientDataTypeManager extends ArchiveDataTypeManagerDB {

	/**
	 * Create a transient/temporary datatype manager using a specified data organization.
	 * 
	 * @param name archive and datatype manager name
	 * @param dataOrganization data organization
	 * @throws RuntimeIOException if database error occurs during creation
	 */
	public TransientDataTypeManager(String name, DataOrganization dataOrganization)
			throws RuntimeIOException {
		super();
		try {
			// Unusual code alert: Normally DataTypeManagers are created by the archives, but
			// for convenience of being able to just create a TransientDataTypeManager by 
			// constructing it, we internally construct the containing archive here and pass our
			// instance to the archive constructor.
			archive = new TransientDtArchiveDB(dbHandle, name, this);
		}
		catch (IOException e) {
			throw new RuntimeIOException(e);
		}
		setDataOrganization(dataOrganization); // may be null
		this.errHandler = archive;
		this.lock = archive.getLock();
	}

	/**
	 * Create a transient/temporary datatype manager using a default data organization.
	 * 
	 * @param name archive and datatype manager name
	 * @throws RuntimeIOException if database error occurs during creation
	 */
	public TransientDataTypeManager(String name)
			throws RuntimeIOException {
		this(name, null);
	}

	/**
	 * Create a transient/temporary datatype manager using a specified program architecture.
	 * 
	 * @param name archive and datatype manager name
	 * @param language processor language
	 * @param compilerSpecId valid compiler spec ID which corresponds to the language ID.
	 * @throws CompilerSpecNotFoundException if invalid compilerSpecId specified for language
	 * @throws LanguageNotFoundException if current language is not found (if required for data transition)
	 * @throws IOException if an IO error occurs
	 */
	public TransientDataTypeManager(String name, Language language, CompilerSpecID compilerSpecId)
			throws CompilerSpecNotFoundException, LanguageNotFoundException, IOException {
		this(name, null);
		try {
			archive.setProgramArchitecture(language, compilerSpecId, LanguageUpdateOption.CLEAR,
				TaskMonitor.DUMMY);
		}
		catch (CancelledException | LockException | UnsupportedOperationException
				| IncompatibleLanguageException e) {
			throw new AssertException(e);
		}
		catch (RuntimeIOException e) {
			e.throwIOException();
		}
	}

	/**
	 * Create a transient/temporary datatype manager using a specified program architecture.
	 * 
	 * @param name archive and datatype manager name
	 * @param languageId valid language ID (see appropriate *.ldefs file for defined IDs)
	 * @param compilerSpecId valid compiler spec ID which corresponds to the language ID.
	 * @throws CompilerSpecNotFoundException if invalid compilerSpecId specified for language
	 * @throws LanguageNotFoundException if current language is not found (if required for data transition)
	 * @throws IOException if an IO error occurs
	 */
	public TransientDataTypeManager(String name, LanguageID languageId,
			CompilerSpecID compilerSpecId)
			throws CompilerSpecNotFoundException, LanguageNotFoundException, IOException {

		// Verify that the specified language and compiler spec are valid 
		LanguageService languageService = DefaultLanguageService.getLanguageService();
		Language language = languageService.getLanguage(languageId);
		language.getCompilerSpecByID(compilerSpecId); // performs check only

		this(name, language, compilerSpecId);
	}

	@Override
	public TransientDataTypeArchive getDataStore() {
		return (TransientDataTypeArchive) super.getDataStore();
	}

	@Override
	public ArchiveType getType() {
		return ArchiveType.TEMPORARY;
	}

	@Override
	public void close() {
		((TransientDtArchiveDB) archive).close();
	}

}
