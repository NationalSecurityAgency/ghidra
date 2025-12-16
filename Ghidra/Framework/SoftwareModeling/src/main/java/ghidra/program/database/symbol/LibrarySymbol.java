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
package ghidra.program.database.symbol;

import db.DBRecord;
import ghidra.program.database.DBObjectCache;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CircularDependencyException;
import ghidra.program.model.listing.Library;
import ghidra.program.model.symbol.*;
import ghidra.program.util.ProgramEvent;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

/**
 * Class for library symbols.
 * 
 * Symbol data usage:
 *   String stringData - associated program project file path
 */
public class LibrarySymbol extends SymbolDB {

	private LibraryDB library;

	/**
	 * Constructs a new Library Symbol
	 * @param symbolMgr the symbol manager
	 * @param cache symbol object cache
	 * @param record the record for this symbol
	 */
	public LibrarySymbol(SymbolManager symbolMgr, DBObjectCache<SymbolDB> cache, DBRecord record) {
		super(symbolMgr, cache, Address.NO_ADDRESS, record);
	}

	@Override
	public void setName(String newName, SourceType source)
			throws DuplicateNameException, InvalidInputException {
		String oldName = getName();
		if (Library.UNKNOWN.equals(oldName)) {
			Msg.warn(this, "Unable to change name of " + Library.UNKNOWN + " Library");
			return;
		}

		super.setName(newName, source);

		if (!oldName.equals(getName())) {
			symbolMgr.getProgram()
					.setObjChanged(ProgramEvent.EXTERNAL_NAME_CHANGED, (Address) null, null,
						oldName, newName);
		}
	}

	@Override
	public void setNameAndNamespace(String newName, Namespace newNamespace, SourceType source)
			throws DuplicateNameException, InvalidInputException, CircularDependencyException {
		String oldName = getName();

		super.setNameAndNamespace(newName, newNamespace, source);

		if (!oldName.equals(getName())) {
			symbolMgr.getProgram()
					.setObjChanged(ProgramEvent.EXTERNAL_NAME_CHANGED, (Address) null, null,
						oldName, newName);
		}
	}

	@Override
	public SymbolType getSymbolType() {
		return SymbolType.LIBRARY;
	}

	@Override
	public boolean isExternal() {
		return true;
	}

	@Override
	public Library getObject() {
		lock.acquire();
		try {
			if (!checkIsValid()) {
				return null;
			}
			if (library == null) {
				library = new LibraryDB(this, symbolMgr.getProgram().getNamespaceManager());
			}
			return library;
		}
		finally {
			lock.release();
		}
	}

	@Override
	public boolean isPrimary() {
		return true;
	}

	@Override
	public boolean isValidParent(Namespace parent) {
		return super.isValidParent(parent) &&
			SymbolType.LIBRARY.isValidParent(symbolMgr.getProgram(), parent, address, isExternal());
	}

	/**
	 * {@return the library program path within the project (may be null)}
	 */
	public String getExternalLibraryPath() {
		validate(lock);
		return record.getString(SymbolDatabaseAdapter.SYMBOL_LIBPATH_COL);
	}

	/**
	 * Set the library program path within the project.
	 * @param libraryPath library program path or null to clear
	 */
	public void setExternalLibraryPath(String libraryPath) {

		String oldPath = getExternalLibraryPath();

		lock.acquire();
		try {
			checkDeleted();
			setRecordFields(record, libraryPath);
			updateRecord();
		}
		finally {
			lock.release();
		}

		symbolMgr.getProgram()
				.setObjChanged(ProgramEvent.EXTERNAL_PATH_CHANGED, getName(), oldPath, libraryPath);
	}

	static void setRecordFields(DBRecord record, String libraryPath) {
		record.setString(SymbolDatabaseAdapter.SYMBOL_LIBPATH_COL, libraryPath);
	}
}
