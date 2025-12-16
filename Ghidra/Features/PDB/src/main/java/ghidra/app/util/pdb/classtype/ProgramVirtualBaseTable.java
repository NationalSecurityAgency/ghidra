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

import ghidra.app.util.bin.format.pdb2.pdbreader.PdbException;
import ghidra.program.model.address.Address;
import ghidra.program.model.gclass.ClassID;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;

/**
 * Virtual Base Table from perspective of program with memory.  Values are read from memory
 */
public class ProgramVirtualBaseTable extends VirtualBaseTable {

	private Program program;
	private Address address;
	private int entrySize;
	private String mangledName; // remove?

	/**
	 * Constructor
	 * @param owner the class that owns the table
	 * @param parentage the parentage of the base class(es) of the table
	 * @param program the program
	 * @param address the address of the table
	 * @param entrySize the size of the index field for each table entry in memory
	 * @param mangledName the mangled name of the table
	 */
	public ProgramVirtualBaseTable(ClassID owner, List<ClassID> parentage, Program program,
			Address address, int entrySize, String mangledName) {
		super(owner, parentage);
		this.program = program;
		this.address = address;
		this.entrySize = entrySize;
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
	public String getMangledName() {
		return mangledName;
	}

	@Override
	public Long getBaseOffset(int tableIndex) throws PdbException {
		Long offset = baseOffsetByTableIndex.get(tableIndex);
		if (offset != null) {
			return offset;
		}
		offset = getOffsetFromMemory(tableIndex);
		if (offset != null) {
			baseOffsetByTableIndex.put(tableIndex, offset);
		}
		return offset;
	}

	private Long getOffsetFromMemory(int tableIndex) throws PdbException {
		if (program == null || address == null) {
			return null;
		}
		Memory memory = program.getMemory();
		Address entryAddress = address.add(tableIndex * entrySize);
		try {
			Long offset = (entrySize == 4) ? (long) memory.getInt(entryAddress)
					: memory.getLong(entryAddress);
			return offset;
		}
		catch (MemoryAccessException e) {
			throw new PdbException(
				"MemoryAccessException while trying to parse virtual base table entry at address: " +
					entryAddress);
		}
		finally {
			maxTableIndexSeen = Integer.max(maxTableIndexSeen, tableIndex);
		}
	}

	@Override
	protected VirtualBaseTableEntry getNewEntry(ClassID baseId) {
		return new VirtualBaseTableEntry(baseId);
	}

	/**
	 * Returns the entry for the table index; the table index is based at 1
	 * @param tableIndex the index location in the table
	 * @return the entry
	 */
	private VirtualBaseTableEntry entry(int tableIndex) {
		return entryByTableIndex.get(tableIndex);
	}

	private VirtualBaseTableEntry existing(int tableIndex) throws PdbException {
		VirtualBaseTableEntry entry = entry(tableIndex);
		if (entry == null) {
			throw new PdbException(
				"No entry in Virtual Base Table for table offset: " + tableIndex);
		}
		return entry;
	}

}
