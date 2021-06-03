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
package ghidra.app.plugin.core.symtable;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.program.util.ProgramLocation;
import ghidra.util.task.TaskMonitor;

/**
 * A class that allows the symbol table plugin to locate deleted items by id
 */
class ProxySymbol implements Symbol {

	private long id;
	private Address address;

	ProxySymbol(long id, Address address) {
		this.id = id;
		this.address = address;
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof Symbol)) {
			return false;
		}
		if (obj == this) {
			return true;
		}

		// this class is only ever equal if the id matches
		Symbol s = (Symbol) obj;
		if (getID() == s.getID()) {
			return true;
		}
		return false;
	}

	@Override
	public int hashCode() {
		return (int) id;
	}

	@Override
	public long getID() {
		return id;
	}

	@Override
	public Address getAddress() {
		return address;
	}

	@Override
	public SymbolType getSymbolType() {
		throw new UnsupportedOperationException();
	}

	@Override
	public ProgramLocation getProgramLocation() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isExternal() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Object getObject() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isPrimary() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isValidParent(Namespace parent) {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getName() {
		throw new UnsupportedOperationException();
	}

	@Override
	public String[] getPath() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Program getProgram() {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getName(boolean includeNamespace) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Namespace getParentNamespace() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Symbol getParentSymbol() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isDescendant(Namespace namespace) {
		throw new UnsupportedOperationException();
	}

	@Override
	public int getReferenceCount() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean hasMultipleReferences() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean hasReferences() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Reference[] getReferences(TaskMonitor monitor) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Reference[] getReferences() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setName(String newName, SourceType source) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setNamespace(Namespace newNamespace) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setNameAndNamespace(String newName, Namespace newNamespace, SourceType source) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean delete() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isPinned() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setPinned(boolean pinned) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isDynamic() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean setPrimary() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isExternalEntryPoint() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isGlobal() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setSource(SourceType source) {
		throw new UnsupportedOperationException();
	}

	@Override
	public SourceType getSource() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean isDeleted() {
		throw new UnsupportedOperationException();
	}

	@Override
	public String toString() {
		return getClass().getSimpleName() + "[id=" + id + ", address=" + address + "]";
	}
}
