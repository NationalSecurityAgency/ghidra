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
import ghidra.program.util.ChangeManager;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

/**
 * Class for library symbols.
 * 
 * Symbol data usage:
 *   int data2 - set to 0 (not used) 
 *   String data3 - associated program project file path
 */

public class LibrarySymbol extends SymbolDB {

	private LibraryDB library;

	/**
	 * Constructs a new Library Symbol
	 * @param symbolMgr the symbol manager
	 * @param cache symbol object cache
	 * @param address the address for this symbol
	 * @param record the record for this symbol
	 */
	public LibrarySymbol(SymbolManager symbolMgr, DBObjectCache<SymbolDB> cache, Address address,
			DBRecord record) {
		super(symbolMgr, cache, address, record);

	}

	@Override
	public void setName(String newName, SourceType source) throws DuplicateNameException,
			InvalidInputException {
		String oldName = getName();
		if (Library.UNKNOWN.equals(oldName)) {
			Msg.warn(this, "Unable to change name of " + Library.UNKNOWN + " Library");
			return;
		}

		super.setName(newName, source);

		if (!oldName.equals(getName())) {
			symbolMgr.getProgram().setObjChanged(ChangeManager.DOCR_EXTERNAL_NAME_CHANGED,
				(Address) null, null, oldName, newName);
		}
	}

	@Override
	public void setNameAndNamespace(String newName, Namespace newNamespace, SourceType source)
			throws DuplicateNameException, InvalidInputException, CircularDependencyException {
		String oldName = getName();

		super.setNameAndNamespace(newName, newNamespace, source);

		if (!oldName.equals(getName())) {
			symbolMgr.getProgram().setObjChanged(ChangeManager.DOCR_EXTERNAL_NAME_CHANGED,
				(Address) null, null, oldName, newName);
		}
	}

	@Override
	public void setSymbolData3(String newPath) {
		String oldPath = getSymbolData3();

		super.setSymbolData3(newPath);

		symbolMgr.getProgram().setObjChanged(ChangeManager.DOCR_EXTERNAL_PATH_CHANGED, getName(),
			oldPath, newPath);
	}

	public SymbolType getSymbolType() {
		return SymbolType.LIBRARY;
	}

	@Override
	public boolean isExternal() {
		return true;
	}

	@Override
	public Object getObject() {
		if (library == null) {
			library = new LibraryDB(this, symbolMgr.getProgram().getNamespaceManager());
		}
		return library;
	}

	@Override
	public boolean isPrimary() {
		return true;
	}

	/**
	 * @see ghidra.program.model.symbol.Symbol#getProgramLocation()
	 */
	public ProgramLocation getProgramLocation() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean isValidParent(Namespace parent) {
		return SymbolType.LIBRARY.isValidParent(symbolMgr.getProgram(), parent, address,
			isExternal());
	}
}
