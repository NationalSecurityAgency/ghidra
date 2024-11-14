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
package ghidra.app.util.pdb.classtype;

import java.util.List;

import ghidra.app.util.SymbolPath;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbException;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;

/**
 * Manages virtual function table lookups.
 */
public class ProgramVirtualFunctionTable extends VirtualFunctionTable {

	private Memory memory;
	private Address address;
	private int defaultEntrySize; // Might go away, as would constructor param
	private String mangledName;

	/**
	 * Constructor
	 * @param owner the owner class
	 * @param parentage the parentage for the table
	 * @param memory the program memory
	 * @param address the address of the table in memory
	 * @param defaultEntrySize the default entry size
	 * @param mangledName the mangled name for the table
	 */
	public ProgramVirtualFunctionTable(ClassID owner, List<ClassID> parentage, Memory memory,
			Address address, int defaultEntrySize, String mangledName) {
		super(owner, parentage);
		if (defaultEntrySize != 4 && defaultEntrySize != 8) {
			throw new IllegalArgumentException(
				"Invalid size (" + defaultEntrySize + "): must be 4 or 8.");
		}
		this.memory = memory;
		this.address = address;
		this.defaultEntrySize = defaultEntrySize;
		this.mangledName = mangledName;
	}

	/**
	 * Returns the address of the table in program memory
	 * @return the address
	 */
	public Address getAddress() {
		return address;
	}

	/**
	 * Returns the mangled name
	 * @return the mangled name
	 */
	String getMangledName() {
		return mangledName;
	}

	@Override
	public Address getAddress(int ordinal) throws PdbException {
		throw new UnsupportedOperationException();
	}

	@Override
	public SymbolPath getPath(int index) throws PdbException {
		throw new UnsupportedOperationException();
	}
}
