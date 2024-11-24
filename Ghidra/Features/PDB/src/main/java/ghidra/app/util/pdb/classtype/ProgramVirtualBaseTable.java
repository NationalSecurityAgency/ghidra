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

import java.util.*;

import ghidra.app.util.bin.format.pdb2.pdbreader.PdbException;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;

/**
 * Virtual Base Table from perspective of program with memory.  Values are read from memory
 */
public class ProgramVirtualBaseTable extends VirtualBaseTable {

	private Memory memory;
	private Address address;
	private int entrySize;
	private String mangledName; // remove?

	private Boolean createdFromMemory = null;
	private Boolean createdFromCompiled = null;

	private int numEntries = 0;

	private int maxIndexSeen = -1;
	private Map<Integer, VBTableEntry> entriesByIndex = new HashMap<>();

	/**
	 * Constructor
	 * @param owner the class that owns the table
	 * @param parentage the parentage of the base class(es) of the table
	 * @param memory the program memory
	 * @param address the address of the table
	 * @param entrySize the size for each table entry
	 * @param ctm the class type manager
	 * @param mangledName the mangled name of the table
	 */
	public ProgramVirtualBaseTable(ClassID owner, List<ClassID> parentage, Memory memory,
			Address address, int entrySize, ClassTypeManager ctm, String mangledName) {
		super(owner, parentage);
		if (entrySize != 4 && entrySize != 8) {
			throw new IllegalArgumentException("Invalid size (" + entrySize + "): must be 4 or 8.");
		}
		this.memory = memory;
		this.address = address;
		this.entrySize = entrySize;
		this.mangledName = mangledName;
		createdFromMemory = true;
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

	/*
	 * For the next method below... once we determine the number of virtual bases (virtual and
	 * indirect virtual) for each class (from PDB or other), we can determine the number of
	 * entries in each VBT.  For a VBT for the main class, the number is equal... if for some
	 * parentage, then the number can reflect the number of the parent.  TODO: can VBT overlay/extend one from parent????????????????????????????????????????????
	 */
	/**
	 * TBD: need to determine table size to do this.  Might want to place a symbol (diff method?).
	 */
	void placeTableDataType(int numEntries) {

	}

	int getMaxIndex() {
		return maxIndexSeen;
	}

	@Override
	public Long getBaseOffset(int index) throws PdbException {
		Address entryAddress = address.add(index * entrySize);
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
			maxIndexSeen = Integer.max(maxIndexSeen, index);
		}
	}

	@Override
	public ClassID getBaseClassId(int index) throws PdbException {
		VBTableEntry entry = entriesByIndex.get(index);
		if (entry == null) {
			throw new PdbException("No entry in Virtual Base Table for index: " + index);
		}
		maxIndexSeen = Integer.max(maxIndexSeen, index);
		return entry.getClassId();
	}

	@Override
	public VBTableEntry getBase(int index) throws PdbException {
		VBTableEntry entry = entriesByIndex.get(index);
		if (entry == null) {
			throw new PdbException("No entry in Virtual Base Table for index: " + index);
		}
		maxIndexSeen = Integer.max(maxIndexSeen, index);
		return entry;
	}

	// Need to decide if we want to allow this to overwrite existing entry.
	public void setBaseClassId(int index, ClassID baseId) throws PdbException {
		VBTableEntry entry = entriesByIndex.get(index);
		if (entry != null) {
			throw new PdbException(
				"Entry already exists in Virtual Base Table for index: " + index);
		}
		entry = new VirtualBaseTableEntry(baseId);
		entriesByIndex.put(index, entry);
		maxIndexSeen = Integer.max(maxIndexSeen, index); // do we want this here with a "set" method?
	}

}
