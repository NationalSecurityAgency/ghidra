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
package ghidra.program.model.address;

import ghidra.program.model.listing.CircularDependencyException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.program.util.ProgramLocation;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * The global symbol implementation class
 */
public class GlobalSymbol implements Symbol {
	private GlobalNamespace globalNamespace;

	GlobalSymbol(GlobalNamespace globalNamespace) {
		this.globalNamespace = globalNamespace;
	}

	@Override
	public boolean isDeleted() {
		return false;
	}

	@Override
	public boolean isExternal() {
		return false;
	}

	@Override
	public int hashCode() {
		int result = 17;
		result = 31 * result + getClass().hashCode();
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == null) {
			return false;
		}
		if (obj == this) {
			return true;
		}
		return getClass() == obj.getClass();
	}

	@Override
	public Address getAddress() {
		return Address.NO_ADDRESS;
	}

	@Override
	public Program getProgram() {
		return null;
	}

	@Override
	public String getName() {
		return "global";
	}

	@Override
	public String getName(boolean includeNamespace) {
		return getName();
	}

	@Override
	public String[] getPath() {
		return new String[0];
	}

	@Override
	public Namespace getParentNamespace() {
		return null;
	}

	@Override
	public Symbol getParentSymbol() {
		return null;
	}

	@Override
	public boolean isDescendant(Namespace namespace) {
		return true;
	}

	@Override
	public boolean isValidParent(Namespace parent) {
		return false;
	}

	@Override
	public SymbolType getSymbolType() {
		return SymbolType.GLOBAL;
	}

	@Override
	public int getReferenceCount() {
		return 0;
	}

	@Override
	public boolean hasMultipleReferences() {
		return false;
	}

	@Override
	public boolean hasReferences() {
		return false;
	}

	@Override
	public Reference[] getReferences() {
		return new Reference[0];
	}

	@Override
	public Reference[] getReferences(TaskMonitor monitor) {
		return new Reference[0];
	}

	public Reference[] getAssociatedReferences() {
		return new Reference[0];
	}

	@Override
	public ProgramLocation getProgramLocation() {
		return null;
	}

	@Override
	public void setName(String newName, SourceType source)
			throws DuplicateNameException, InvalidInputException {
		throw new UnsupportedOperationException(
			"Setting the name of the Global symbol is not allowed.");
	}

	@Override
	public boolean delete() {
		return false;
	}

	/**
	 * This returns false, since the global symbol isn't associated with a specific
	 * program memory address.
	 */
	@Override
	public boolean isPinned() {
		return false;
	}

	/**
	 * This method doesn't apply to the global symbol, since it isn't associated with a specific
	 * program memory address. Therefore calling it will have no effect.
	 */
	@Override
	public void setPinned(boolean pinned) {
		throw new UnsupportedOperationException("Can't pin the global symbol");
	}

	/**
	 * This method doesn't apply to the global symbol, since a program always has a global symbol 
	 * and it can't be renamed. Therefore calling it will throw an UnsupportedOperationException.
	 * @param source the source of this symbol: Symbol.DEFAULT, Symbol.IMPORTED, Symbol.ANALYSIS, or Symbol.USER_DEFINED.
	 * @throws UnsupportedOperationException whenever called.
	 */
	@Override
	public void setSource(SourceType source) {
		throw new UnsupportedOperationException(
			"Setting the source of the Global symbol is not allowed.");
	}

	/**
	 * This method doesn't apply to the global symbol, since a program always has a global symbol 
	 * and it can't be renamed. Therefore calling it will throw an UnsupportedOperationException.
	 * return source the source of this symbol: default, imported, analysis, or user defined.
	 * @throws UnsupportedOperationException whenever called.
	 */
	@Override
	public SourceType getSource() {
		throw new UnsupportedOperationException(
			"Getting the source of the Global symbol is not allowed.");
	}

	@Override
	public boolean isDynamic() {
		return false;
	}

	@Override
	public boolean isPrimary() {
		return true;
	}

	@Override
	public boolean setPrimary() {
		return false;
	}

	@Override
	public boolean isExternalEntryPoint() {
		return false;
	}

	@Override
	public long getID() {
		return Namespace.GLOBAL_NAMESPACE_ID;
	}

	@Override
	public Object getObject() {
		return globalNamespace;
	}

	@Override
	public void setNamespace(Namespace newNamespace)
			throws DuplicateNameException, InvalidInputException, CircularDependencyException {
		throw new UnsupportedOperationException("Cannot change the Global namespace");
	}

	@Override
	public void setNameAndNamespace(String newName, Namespace newNamespace, SourceType source)
			throws DuplicateNameException, InvalidInputException, CircularDependencyException {
		throw new UnsupportedOperationException("Cannot change the Global name and/or namespace");
	}

	@Override
	public boolean isGlobal() {
		return true;
	}

}
