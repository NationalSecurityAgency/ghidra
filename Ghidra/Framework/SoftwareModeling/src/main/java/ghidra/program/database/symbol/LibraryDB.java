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

import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.CircularDependencyException;
import ghidra.program.model.listing.Library;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

/**
 * Object to represent an external library.
 */
class LibraryDB implements Library {
	private SymbolDB symbol;
	private NamespaceManager namespaceMgr;

	/**
	 * Constructs a new Library object
	 * @param symbol the library symbol.
	 * @param namespaceMgr the namespace manager
	 */
	LibraryDB(SymbolDB symbol, NamespaceManager namespaceMgr) {
		this.symbol = symbol;
		this.namespaceMgr = namespaceMgr;
	}

	/**
	 * @see ghidra.program.model.symbol.Namespace#getSymbol()
	 */
	public Symbol getSymbol() {
		return symbol;
	}

	/**
	 * @see ghidra.program.model.symbol.Namespace#getName()
	 */
	public String getName() {
		return symbol.getName();
	}

	/**
	 * @see ghidra.program.model.symbol.Namespace#getID()
	 */
	public long getID() {
		return symbol.getID();
	}

	/**
	 * @see ghidra.program.model.symbol.Namespace#getParentNamespace()
	 */
	public Namespace getParentNamespace() {
		return symbol.getParentNamespace();
	}

	/**
	 * @see ghidra.program.model.symbol.Namespace#getBody()
	 */
	public AddressSetView getBody() {
		return namespaceMgr.getAddressSet(this);
	}

	/**
	 * @see ghidra.program.model.symbol.Namespace#getName(boolean)
	 */
	public String getName(boolean includeNamespacePath) {
		return symbol.getName(includeNamespacePath);
	}

	/**
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object obj) {
		if (obj == null) {
			return false;
		}
		if (obj.getClass() != getClass()) {
			return false;
		}
		LibraryDB lib = (LibraryDB) obj;

		return symbol == lib.symbol;
	}

	/**
	 * @see ghidra.program.model.symbol.Namespace#setParentNamespace(ghidra.program.model.symbol.Namespace)
	 */
	public void setParentNamespace(Namespace parentNamespace) throws DuplicateNameException,
			InvalidInputException, CircularDependencyException {
		symbol.setNamespace(parentNamespace);
	}

	@Override
	public String getAssociatedProgramPath() {
		return symbol.getSymbolStringData();
	}

	@Override
	public boolean isExternal() {
		return true;
	}

}
