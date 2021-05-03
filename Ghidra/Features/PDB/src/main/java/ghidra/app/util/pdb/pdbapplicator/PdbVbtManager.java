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
package ghidra.app.util.pdb.pdbapplicator;

import java.util.*;

import ghidra.app.util.bin.format.pdb2.pdbreader.*;
import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.AbstractMsSymbol;
import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.AbstractPublicMsSymbol;
import ghidra.app.util.pdb.pdbapplicator.SymbolGroup.AbstractMsSymbolIterator;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Manages virtual base table lookup for PDB classes.
 */
public class PdbVbtManager extends VbtManager {

	private Map<String, Address> addressByMangledName;
	private Memory memory;

	private static Memory getMemory(PdbApplicator applicator) throws PdbException {
		Program program = applicator.getProgram();
		if (program == null) {
			throw new PdbException("Program null for VbtManager");
		}
		return program.getMemory();
	}

	// TODO: Research whether we ever find VBT symbols put into the program by the "loader."
	//  If we find some this way, then need to modify PdbVbtManager to also look
	//  through the loader symbol for them.
	private static Map<String, Address> findVirtualBaseTableSymbols(PdbApplicator applicator)
			throws CancelledException {

		TaskMonitor monitor = applicator.getMonitor();
		SymbolGroup symbolGroup = applicator.getSymbolGroup();
		Map<String, Address> myAddressByMangledName = new HashMap<>();

		PublicSymbolInformation publicSymbolInformation =
			applicator.getPdb().getDebugInfo().getPublicSymbolInformation();
		List<Long> offsets = publicSymbolInformation.getModifiedHashRecordSymbolOffsets();
		applicator.setMonitorMessage("PDB: Searching for virtual base table symbols...");
		monitor.initialize(offsets.size());

		AbstractMsSymbolIterator iter = symbolGroup.iterator();
		for (long offset : offsets) {
			monitor.checkCanceled();
			iter.initGetByOffset(offset);
			if (!iter.hasNext()) {
				break;
			}
			AbstractMsSymbol symbol = iter.peek();
			if (symbol instanceof AbstractPublicMsSymbol) {
				AbstractPublicMsSymbol pubSymbol = (AbstractPublicMsSymbol) symbol;
				String name = pubSymbol.getName();
				if (name.startsWith("??_8")) {
					Address address = applicator.getAddress(pubSymbol);
					if (!applicator.isInvalidAddress(address, name)) {
						myAddressByMangledName.put(name, address);
					}
				}
			}
			monitor.incrementProgress(1);
		}
		return myAddressByMangledName;
	}

	/**
	 * Virtual Base Table Lookup Manager
	 * @param applicator {@link PdbApplicator} for which this class is working.
	 * @throws PdbException If Program is null;
	 * @throws CancelledException upon user cancellation
	 */
	PdbVbtManager(PdbApplicator applicator) throws PdbException, CancelledException {
		this(applicator.getDataTypeManager(), getMemory(applicator),
			findVirtualBaseTableSymbols(applicator));
	}

	PdbVbtManager(DataTypeManager dataTypeManager, Memory memory,
			Map<String, Address> addressByMangledName) {
		super(dataTypeManager);
		this.memory = memory;
		this.addressByMangledName = addressByMangledName;
	}

//	/**
//	 * Builds the tables
//	 * @throws PdbException If Program is null;
//	 * @throws CancelledException upon user cancellation.
//	 */
//	void CreateVirtualBaseTables() throws PdbException, CancelledException {
//		createVirtualBaseTables();
//	}
//
	PdbVirtualBaseTable createVirtualBaseTableByName(String mangledName, int entrySize) {
		Address address = addressByMangledName.get(mangledName);
		if (address == null) {
			return null;
			//throw new PdbException("Cannot find address for table name: " + mangledName);
		}
		return createVirtualBaseTable(address, entrySize);
	}

	PdbVirtualBaseTable createVirtualBaseTable(Address address, int entrySize) {

		VirtualBaseTable vbt = vbtByAddress.get(address);
		if (vbt != null) {
			String message =
				"PDB: warning virtual base table already exists for address: " + address;
			PdbLog.message(message);
			Msg.info(this, message);
		}
		else {
			vbt = new PdbVirtualBaseTable(memory, address, entrySize);
			vbtByAddress.put(address, vbt);
		}
		if (!(vbt instanceof PdbVirtualBaseTable)) {
			// investigate this
		}
		return (PdbVirtualBaseTable) vbt;
	}

	/**
	 * Returns offset for vbtable (mangled name) and ordinal
	 * @param vbtMangledName mangled name of vbtable
	 * @param ordinal index into table
	 * @param size size of a vbt entry offset value
	 * @return the offset
	 * @throws PdbException if no address exists for mangled name
	 */
	long getOffset(String vbtMangledName, int ordinal, int size) throws PdbException {
		Address address = addressByMangledName.get(vbtMangledName);
		if (address == null) {
			throw new PdbException(
				"Virtual Base Table does not exist for symbol: " + vbtMangledName);
		}
		return getOffset(address, ordinal, size);
	}

	/**
	 * Returns the offset from the virtual base table entry
	 * @param address Address of virtual base table
	 * @param ordinal index into table
	 * @param size size of a vbt entry offset value
	 * @return the offset
	 * @throws PdbException if no table exists for address or no entry exists for ordinal
	 */
	long getOffset(Address address, int ordinal, int size) throws PdbException {
		VirtualBaseTable table = vbtByAddress.get(address);
		if (table == null) {
			throw new PdbException("Virtual Base Table does not exist for address: " + address);
		}
		if (!(table instanceof PdbVirtualBaseTable)) {
			throw new PdbException("Not a PDB Virtual Base Table for address: " + address);
		}
		VirtualBaseTableEntry entry =
			((PdbVirtualBaseTable) table).getOrParseEntryByOrdinal(ordinal);
		return entry.getOffset();
	}

	private void createVirtualBaseTables() {
		for (Map.Entry<String, Address> entry : addressByMangledName.entrySet()) {
			Address address = entry.getValue();
			createVirtualBaseTable(address);
		}
	}

	static VirtualBaseTableEntry parseVbtEntryFromMemory(Memory memory, Address address,
			int ordinal, int size) throws PdbException {
		if (size != 4 && size != 8) {
			throw new IllegalArgumentException("Invalid size (" + size + "): must be 4 or 8.");
		}
		Address readAddress = address.add(ordinal * size);
		long offset;
		try {
			offset = (size == 4) ? (long) memory.getInt(readAddress) : memory.getLong(readAddress);
		}
		catch (MemoryAccessException e) {
			throw new PdbException(
				"MemoryAccessException while trying to parse virtual base table entry at address: " +
					readAddress);
		}
		return new VirtualBaseTableEntry(offset);
	}

	static class PdbVirtualBaseTable extends VirtualBaseTable {
		private Memory memory;
		private Address address;
		private int entrySize;

		PdbVirtualBaseTable(Memory memory, Address address, int entrySize) {
			super();
			this.memory = memory;
			this.address = address;
			this.entrySize = entrySize;
		}

		@Override
		VirtualBaseTableEntry getEntry(int ordinal) throws PdbException {
			return getOrParseEntryByOrdinal(ordinal);
			//return entryByOrdinal.get(ordinal);
		}

		VirtualBaseTableEntry getOrParseEntryByOrdinal(int ordinal) throws PdbException {
			VirtualBaseTableEntry entry = entryByOrdinal.get(ordinal);
			if (entry == null) {
				entry = parseVbtEntryFromMemory(memory, address, ordinal, entrySize);
				addEntry(ordinal, entry);
			}
			return entry;
		}
	}
}
