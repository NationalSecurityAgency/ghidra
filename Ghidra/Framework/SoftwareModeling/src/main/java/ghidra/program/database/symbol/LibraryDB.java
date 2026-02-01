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
	private LibrarySymbol symbol;
	private NamespaceManager namespaceMgr;

	/**
	 * Constructs a new Library object
	 * @param symbol the library symbol.
	 * @param namespaceMgr the namespace manager
	 */
	LibraryDB(LibrarySymbol symbol, NamespaceManager namespaceMgr) {
		this.symbol = symbol;
		this.namespaceMgr = namespaceMgr;
	}

	@Override
	public Symbol getSymbol() {
		return symbol;
	}

	@Override
	public String getName() {
		return symbol.getName();
	}

	@Override
	public long getID() {
		return symbol.getID();
	}

	@Override
	public Namespace getParentNamespace() {
		return symbol.getParentNamespace();
	}

	@Override
	public AddressSetView getBody() {
		return namespaceMgr.getAddressSet(this);
	}

	@Override
	public String getName(boolean includeNamespacePath) {
		return symbol.getName(includeNamespacePath);
	}

	@Override
	public int hashCode() {
		return symbol.hashCode();
	}

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

	@Override
	public void setParentNamespace(Namespace parentNamespace)
			throws DuplicateNameException, InvalidInputException, CircularDependencyException {
		symbol.setNamespace(parentNamespace);
	}

	@Override
	public String getAssociatedProgramPath() {
		return symbol.getExternalLibraryPath();
	}

	@Override
	public boolean isExternal() {
		return true;
	}

	@Override
	public String toString() {
		return getName();
	}

}
