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
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;

/**
 * Manages virtual function table lookups.
 */
public class ProgramVirtualFunctionTable extends VirtualFunctionTable {

	private Program program;
	private Address address;
	private int defaultEntrySize; // Might go away, as would constructor param
	private String mangledName;

	/**
	 * Constructor
	 * @param owner the owner class
	 * @param parentage the parentage for the table
	 * @param program the program
	 * @param address the address of the table in memory
	 * @param defaultEntrySize the default entry size
	 * @param mangledName the mangled name for the table
	 */
	public ProgramVirtualFunctionTable(ClassID owner, List<ClassID> parentage, Program program,
			Address address, int defaultEntrySize, String mangledName) {
		super(owner, parentage);
		if (defaultEntrySize != 4 && defaultEntrySize != 8) {
			throw new IllegalArgumentException(
				"Invalid size (" + defaultEntrySize + "): must be 4 or 8.");
		}
		this.program = program;
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
		Memory memory = program.getMemory();
		Address entryAddress = address.add(ordinal * defaultEntrySize);
		try {
			long offset =
				(defaultEntrySize == 4) ? Integer.toUnsignedLong(memory.getInt(entryAddress))
						: memory.getLong(entryAddress);
			if (offset == 0L) {
				return null;
			}
			Address result = address.getNewAddress(offset, false);
			return result;
		}
		catch (MemoryAccessException e) {
			throw new PdbException(
				"MemoryAccessException while trying to parse virtual function table entry at address: " +
					entryAddress);
		}
		//throw new UnsupportedOperationException();
	}

	@Override
	public SymbolPath getPath(int index) throws PdbException {
		throw new UnsupportedOperationException();
	}
}
