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

import java.util.HashMap;
import java.util.Map;

import ghidra.app.util.bin.format.pdb2.pdbreader.PdbException;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.util.Msg;

/**
 * Manages virtual base table lookup for PDB classes.
 */
public class VbtManager {

	private DataTypeManager dtm;
	private PointerDataType fallbackVbptr;
	protected Map<Address, VirtualBaseTable> vbtByAddress;

	/**
	 * Virtual Base Table Lookup Manager
	 * @param dtm TODO
	 */
	VbtManager(DataTypeManager dtm) {
		this.dtm = dtm;
		vbtByAddress = new HashMap<>();
		fallbackVbptr = new PointerDataType(new IntegerDataType(dtm));
	}

	PointerDataType getFallbackVbptr() {
		return fallbackVbptr;
	}

	/**
	 * Returns the offset from the virtual base table entry
	 * @param address Address of virtual base table
	 * @param ordinal index into table
	 * @return the offset
	 * @throws PdbException if no table exists for address or no entry exists for ordinal
	 */
	long getOffset(Address address, int ordinal) throws PdbException {
		VirtualBaseTable table = vbtByAddress.get(address);
		if (table == null) {
			table = createVirtualBaseTable(address);
		}
		VirtualBaseTableEntry entry = table.getEntry(ordinal);
		if (entry == null) {
			throw new PdbException(
				"Virtual Base Table Entry does not exist for ordinal: " + ordinal);
		}
		return entry.getOffset();
	}

	VirtualBaseTable createVirtualBaseTable(Address address) {
		VirtualBaseTable vbt = vbtByAddress.get(address);
		if (vbt != null) {
			String message =
				"PDB: warning virtual base table already exists for address: " + address;
			PdbLog.message(message);
			Msg.info(this, message);
		}
		else {
			vbt = new VirtualBaseTable();
			vbtByAddress.put(address, vbt);
		}
		return vbt;
	}

	static class VirtualBaseTableEntry {
		long offset;

		VirtualBaseTableEntry(long offset) {
			this.offset = offset;
		}

		long getOffset() {
			return offset;
		}
	}

	static class VirtualBaseTable {
		int maxSeen = -1;
		Map<Integer, VirtualBaseTableEntry> entryByOrdinal = new HashMap<>();

		/**
		 * Returns the entry from the table for the ordinal
		 * @param ordinal the ordinal into the table for the entry to retrieve
		 * @return the table entry
		 * @throws PdbException upon issue retrieving the entry
		 */
		VirtualBaseTableEntry getEntry(int ordinal) throws PdbException {
			return entryByOrdinal.get(ordinal);
		}

		long getOffset(int ordinal) throws PdbException {
			VirtualBaseTableEntry entry = getEntry(ordinal);
			if (entry == null) {
				throw new PdbException("No entry in Virtual Base Table for ordinal: " + ordinal);
			}
			return entry.getOffset();
		}

		void addEntry(int ordinal, VirtualBaseTableEntry entry) {
			entryByOrdinal.put(ordinal, entry);
			maxSeen = Integer.max(maxSeen, ordinal);
		}

		int getMaxOrdinal() {
			return maxSeen;
		}
	}

}
