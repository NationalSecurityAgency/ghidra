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
package ghidra.program.model.symbol;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CircularDependencyException;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

// Simple symbol test implementation
public class StubSymbol implements Symbol {
	private static long nextId = 0;

	private long id;
	private String name;
	private Address address;

	public StubSymbol(String name, Address address) {
		this.name = name;
		this.address = address;
		id = nextId++;
	}

	@Override
	public Address getAddress() {
		return address;
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public String[] getPath() {
		return new String[] { name };
	}

	@Override
	public Program getProgram() {
		return null;
	}

	@Override
	public String getName(boolean includeNamespace) {
		return name;
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
		return false;
	}

	@Override
	public boolean isValidParent(Namespace parent) {
		return false;
	}

	@Override
	public SymbolType getSymbolType() {
		return SymbolType.LABEL;
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
	public Reference[] getReferences(TaskMonitor monitor) {
		return null;
	}

	@Override
	public Reference[] getReferences() {
		return null;
	}

	@Override
	public ProgramLocation getProgramLocation() {
		return null;
	}

	@Override
	public void setName(String newName, SourceType source)
			throws DuplicateNameException, InvalidInputException {
		this.name = newName;
	}

	@Override
	public void setNamespace(Namespace newNamespace)
			throws DuplicateNameException, InvalidInputException, CircularDependencyException {
		// do nothing
	}

	@Override
	public void setNameAndNamespace(String newName, Namespace newNamespace, SourceType source)
			throws DuplicateNameException, InvalidInputException, CircularDependencyException {
		this.name = newName;
	}

	@Override
	public boolean delete() {
		return false;
	}

	@Override
	public boolean isPinned() {
		return false;
	}

	@Override
	public void setPinned(boolean pinned) {
		// nothing
	}

	@Override
	public boolean isDynamic() {
		return false;
	}

	@Override
	public boolean isExternal() {
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
		return name.hashCode();
	}

	@Override
	public Object getObject() {
		return null;
	}

	@Override
	public boolean isGlobal() {
		return true;
	}

	@Override
	public void setSource(SourceType source) {
		// nothing
	}

	@Override
	public SourceType getSource() {
		return SourceType.USER_DEFINED;
	}

	@Override
	public boolean isDeleted() {
		return false;
	}

	@Override
	public int hashCode() {
		return (int) id;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		StubSymbol other = (StubSymbol) obj;
		return id == other.id;
	}

}
