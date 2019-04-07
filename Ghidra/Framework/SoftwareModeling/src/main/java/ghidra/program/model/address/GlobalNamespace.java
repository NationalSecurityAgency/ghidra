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

import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

/** 
 * The global namespace implementation class
 */
public class GlobalNamespace implements Namespace {

	/**
	 * Global namespace name which may (incorrectly) appear as the first 
	 * element within a namespace path (e.g., <code>Global::Foo::Bar</code>).  It is 
	 * preferred that the Global namespace be omitted in favor of <code>Foo::Bar</code>.
	 */
	public static final String GLOBAL_NAMESPACE_NAME = "Global";

	private Memory memory;
	private Symbol globalSymbol;

	/**
	 * Constructs a new GlobalNamespace
	 * @param memory the memory associated with this global namespace
	 */
	public GlobalNamespace(Memory memory) {
		this.memory = memory;
		globalSymbol = new GlobalSymbol(this);
	}

	/**
	 * @see ghidra.program.model.symbol.Namespace#getSymbol()
	 */
	@Override
	public Symbol getSymbol() {
		return globalSymbol;
	}

	/**
	 * @see ghidra.program.model.symbol.Namespace#getName()
	 */
	@Override
	public String getName() {
		return GLOBAL_NAMESPACE_NAME;
	}

	/**
	 * @see ghidra.program.model.symbol.Namespace#getID()
	 */
	@Override
	public long getID() {
		return Namespace.GLOBAL_NAMESPACE_ID;
	}

	/**
	 * @see ghidra.program.model.symbol.Namespace#getParentNamespace()
	 */
	@Override
	public Namespace getParentNamespace() {
		return null;
	}

	/**
	 * @see ghidra.program.model.symbol.Namespace#getBody()
	 */
	@Override
	public AddressSetView getBody() {
		return new AddressSet(memory);
	}

	/**
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		return getName();
	}

	/**
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
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

	/**
	 * @see ghidra.program.model.symbol.Namespace#getName(boolean)
	 */
	@Override
	public String getName(boolean includeNamespacePath) {
		return getName();
	}

	/**
	 * @see ghidra.program.model.symbol.Namespace#setParentNamespace(ghidra.program.model.symbol.Namespace)
	 */
	@Override
	public void setParentNamespace(Namespace parentNamespace)
			throws DuplicateNameException, InvalidInputException {
		throw new InvalidInputException("Can't parent this namespace");
	}

	@Override
	public boolean isExternal() {
		return false;
	}

}
