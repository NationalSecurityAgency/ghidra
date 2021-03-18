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
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

/**
 * Object to represent a "Class"
 */

class GhidraClassDB implements GhidraClass {
	private SymbolDB symbol;
	private NamespaceManager namespaceMgr;

	/**
	 * Construct a new GhidraClass
	 * @param symbol the symbol for this GhidraClass
	 * @param namespaceMgr the namespace manager
	 */
	GhidraClassDB(SymbolDB symbol, NamespaceManager namespaceMgr) {
		this.symbol = symbol;
		this.namespaceMgr = namespaceMgr;
	}

	/**
	 * @see ghidra.program.model.symbol.Namespace#getSymbol()
	 */
	@Override
	public Symbol getSymbol() {
		return symbol;
	}

	@Override
	public boolean isExternal() {
		return symbol.isExternal();
	}

	/**
	 * @see ghidra.program.model.symbol.Namespace#getName()
	 */
	@Override
	public String getName() {
		return symbol.getName();
	}

	public void setName(String name, SourceType source, boolean checkForDuplicates)
			throws DuplicateNameException, InvalidInputException {

		try {
			symbol.doSetNameAndNamespace(name, symbol.getParentNamespace(), source,
				checkForDuplicates);
		}
		catch (CircularDependencyException e) {
			// can't happen since we are not changing the namespace
		}

	}

	/**
	 * @see ghidra.program.model.symbol.Namespace#getID()
	 */
	@Override
	public long getID() {
		return symbol.getID();
	}

	/**
	 * @see ghidra.program.model.symbol.Namespace#getParentNamespace()
	 */
	@Override
	public Namespace getParentNamespace() {
		return symbol.getParentNamespace();
	}

	/**
	 * @see ghidra.program.model.symbol.Namespace#getBody()
	 */
	@Override
	public AddressSetView getBody() {
		return namespaceMgr.getAddressSet(this);
	}

	/**
	 * @see ghidra.program.model.symbol.Namespace#getName(boolean)
	 */
	@Override
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
		GhidraClassDB gc = (GhidraClassDB) obj;

		return symbol == gc.symbol;
	}

	/**
	 * @see ghidra.program.model.symbol.Namespace#setParentNamespace(ghidra.program.model.symbol.Namespace)
	 */
	@Override
	public void setParentNamespace(Namespace parentNamespace) throws DuplicateNameException,
			InvalidInputException, CircularDependencyException {
		symbol.setNamespace(parentNamespace);
	}

	@Override
	public String toString() {
		return symbol.getName(true) + " (GhidraClass)";
	}

}
