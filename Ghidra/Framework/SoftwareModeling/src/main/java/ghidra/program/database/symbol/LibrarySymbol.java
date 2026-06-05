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

import java.util.*;

import db.DBRecord;
import db.Field;
import ghidra.framework.store.FileSystem;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CircularDependencyException;
import ghidra.program.model.listing.Library;
import ghidra.program.model.symbol.*;
import ghidra.program.util.ProgramEvent;
import ghidra.util.Lock.Closeable;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

/**
 * Class for library symbols.
 * 
 * Symbol data usage:
 *   String stringData - associated program project file path
 */
public class LibrarySymbol extends SymbolDB implements Comparable<LibrarySymbol> {

	private LibraryDB library;

	/**
	 * Constructs a new Library Symbol
	 * @param symbolMgr the symbol manager
	 * @param record the record for this symbol
	 */
	LibrarySymbol(SymbolManager symbolMgr, DBRecord record) {
		super(symbolMgr, Address.NO_ADDRESS, record, record.getKey());
	}

	@Override
	public void setNameAndNamespace(String newName, Namespace newNamespace, SourceType source)
			throws DuplicateNameException, InvalidInputException, CircularDependencyException {

		String oldName = getName();
		if (Library.UNKNOWN.equals(oldName)) {
			Msg.warn(this, "Unable to change name of " + Library.UNKNOWN + " Library");
			return;
		}
		if (newNamespace.getID() != Namespace.GLOBAL_NAMESPACE_ID) {
			throw new InvalidInputException("Namespace \"" + newNamespace.getName(true) +
				"\" is not valid for library " + getName());
		}

		try (Closeable c = lock.write()) {

			super.setNameAndNamespace(newName, newNamespace, source);

			if (!oldName.equals(getName())) {
				symbolMgr.getProgram()
						.setObjChanged(ProgramEvent.EXTERNAL_NAME_CHANGED, (Address) null, this,
							oldName, newName);
			}

			if (Library.UNKNOWN.equals(newName)) {
				symbolMgr.adjustLibraryOrdinals(this, 0);
				setExternalLibraryPath(null); // clear file path for UNKNOWN lib
			}
		}
	}

	@Override
	public boolean delete() {
		try (Closeable c = lock.write()) {

			// Pre-fetch library symbol list to facilitate ordinal reassignments after removal
			int ordinal = getOrdinal();
			List<LibrarySymbol> libSymList = new ArrayList<>(symbolMgr.getLibrarySymbolList());

			if (super.delete()) {
				// Perform ordinal reassignments for remaining library symbols if needed.
				// It is expected that all ordinals are accounted for in cached library list
				// but to be safe we will perform brute-force search if mismatch and ignore
				// if not found in list;
				LibrarySymbol s = libSymList.get(ordinal);
				if (s != this) {
					String libName = record.getString(SymbolDatabaseAdapter.SYMBOL_NAME_COL);
					Msg.error(this,
						"Library symbol list did not contain removed symbol: " + libName);
					for (ordinal = 0; ordinal < libSymList.size(); ordinal++) {
						s = libSymList.get(ordinal);
						if (s == this) {
							break;
						}
					}
				}
				if (s == this) {
					libSymList.remove(ordinal);
					symbolMgr.assignLibraryOrdinals(libSymList, false);
				}
				return true;
			}
		}
		return false;
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
		try (Closeable c = lock.read()) {
			if (!refreshIfNeeded()) {
				return null;
			}
			if (library == null) {
				library = new LibraryDB(this, symbolMgr.getProgram().getNamespaceManager());
			}
			return library;
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
	 * {@return Library's ordinal placement within ordered library list.}
	 */
	public int getOrdinal() {
		// NOTE: This method must not be used by compareTo since it may invoke it
		validate(lock);
		int ordinal = doGetOrdinalFromRecord();
		if (ordinal < 0) {
			// NOTE: this method invocation relies on the use of the compareTo method
			ordinal = symbolMgr.computeLibraryOrdinal(this);
		}
		return ordinal;
	}

	/**
	 * Get this Library's ordinal as stored in the database.  A value of -1 is returned if one has
	 * not yet been established in which case the symbol ID should be used for sort while ensuring 
	 * {@link Library#UNKNOWN} always sorts as first.
	 * 
	 * @return Library symbol stored ordinal or -1 if not yet stored.
	 */
	int doGetOrdinalFromRecord() {
		Field fieldValue = record.getFieldValue(SymbolDatabaseAdapter.SYMBOL_LIB_ORDINAL_COL);
		return fieldValue != null ? fieldValue.getIntValue() : -1;
	}

	/**
	 * Set the Library ordinal.
	 * Other Library ordinals will be adjusted if displaced by ordinal change.
	 * No change is made if this Library symbol corresponds to {@link Library#UNKNOWN} Library. 
	 * 
	 * @param ordinal positive greater or equal to 0.  
	 * @throws IllegalArgumentException if a negative ordinal is specified
	 */
	public void setOrdinal(int ordinal) {
		if (ordinal < 0) {
			throw new IllegalArgumentException("Non-negative ordinal is required");
		}
		if (Library.UNKNOWN.equals(getName())) {
			return; // ordinal change ignored for UNKNOWN Library
		}

		try (Closeable c = lock.write()) {
			checkDeleted();
			if (ordinal == 0) {
				// Cannot displace UNKNOWN Library which may reside at ordinal 0
				LibrarySymbol displacedLibSym = symbolMgr.getLibrarySymbolByOrdinal(0);
				if (displacedLibSym != null && Library.UNKNOWN.equals(displacedLibSym.getName())) {
					return;
				}
			}
			symbolMgr.adjustLibraryOrdinals(this, ordinal);
		}
	}

	void doSetOrdinal(int newOrdinal, boolean notify) {
		if (newOrdinal < 0) {
			throw new IllegalArgumentException("Unsupported ordinal assignment: " + newOrdinal);
		}
		int oldOrdinal = doGetOrdinalFromRecord();
		if (oldOrdinal == newOrdinal) {
			return;
		}
		record.setIntValue(SymbolDatabaseAdapter.SYMBOL_LIB_ORDINAL_COL, newOrdinal);
		updateRecord();
		if (notify) {
			symbolMgr.symbolDataChanged(this);
		}
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
	 * The {@link Library#UNKNOWN} Library path may only be cleared.
	 * 
	 * @param libraryPath library program path or null to clear
	 * @throws InvalidInputException if an invalid project file path is specified
	 */
	public void setExternalLibraryPath(String libraryPath) throws InvalidInputException {
		try (Closeable c = lock.write()) {
			checkDeleted();
			if (Library.UNKNOWN.equals(getName())) {
				libraryPath = null;
			}
			validateExternalPath(libraryPath);
			String oldPath = record.getString(SymbolDatabaseAdapter.SYMBOL_LIBPATH_COL);
			if (Objects.equals(oldPath, libraryPath)) {
				return;
			}
			record.setString(SymbolDatabaseAdapter.SYMBOL_LIBPATH_COL, libraryPath);
			updateRecord();
		}
		symbolMgr.symbolDataChanged(this);
	}

	/**
	 * Perform path validation for an external library path within the project
	 * @param path external library path within the project (null is allowed for clearing path)
	 * @throws InvalidInputException if path is invalid
	 */
	public static void validateExternalPath(String path) throws InvalidInputException {
		if (path == null) {
			return; // null is an allowed value (used to clear)
		}

		int len = path.length();
		if (len == 0 || path.charAt(0) != FileSystem.SEPARATOR_CHAR) {
			throw new InvalidInputException(
				"Absolute path must begin with '" + FileSystem.SEPARATOR_CHAR + "'");
		}
	}

	/**
	 * Set library symbol record fields during symbol creation
	 * @param record new symbol record
	 * @param ordinal library symbol ordinal
	 * @param libraryPath library path or null
	 */
	static void setRecordFields(DBRecord record, int ordinal, String libraryPath) {
		// NOTE: method use must be limited since ordinal re-assignments of affected Libraries
		// is not handled here.
		record.setIntValue(SymbolDatabaseAdapter.SYMBOL_LIB_ORDINAL_COL, ordinal);
		record.setString(SymbolDatabaseAdapter.SYMBOL_LIBPATH_COL, libraryPath);
	}

	@Override
	public int compareTo(LibrarySymbol o) {
		validate(lock);
		o.validate(lock);
		// NOTE: this method is not intended to be used between symbols from different programs
		// where one may have stored ordinals and the other may not in which case this comparison
		// would be invalid.  For a single program it is required that all library symbols either
		// have an assigned ordinal or do not in which cases symbol ID comparison is used
		int c = Long.compare(doGetOrdinalFromRecord(), o.doGetOrdinalFromRecord());
		if (c == 0) {
			// Handles case where all library symbols report a -1 ordinal (not yet assigned) 
			// UNKNOWN Library placement is arbitrary in this case.
			c = Long.compare(getID(), o.getID());
		}
		return c;
	}

}
