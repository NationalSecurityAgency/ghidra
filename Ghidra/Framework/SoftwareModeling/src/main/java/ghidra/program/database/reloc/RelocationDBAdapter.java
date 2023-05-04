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
package ghidra.program.database.reloc;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;

import db.*;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.map.AddressMap;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

abstract class RelocationDBAdapter {

	// History:
	//  V1 - added Type
	//  V2 - added Value
	//  V3 - added Bytes
	//  V4 - added Name, switched Value to binary coded long[] from long
	//  V5 - moved Addr key to column and indexed, use one-up key
	//  V6 - added FLAGS columns (status and optional length)

	final static int ADDR_COL = 0; // indexed
	final static int FLAGS_COL = 1; // includes status enum and optional length when bytes==null
	final static int TYPE_COL = 2;
	final static int VALUE_COL = 3; // binary coded long[]
	final static int BYTES_COL = 4; // null defers to FileBytes (see length)
	final static int SYMBOL_NAME_COL = 5;

	/**
	 * FLAGS bit encoding:
	 *   | 7 | 6 | 5 | 4 | 3 | 2 | 1 | 0 |
	 *   |   |     length    |   status  |
	 *  status: Relocation.Status enum index    
	 *  length: Optional byte-length used when bytes is null (0..31)
	 */
	final static int STATUS_FLAGS_MASK = 0x7;
	final static int LENGTH_FLAGS_MASK = 0xF;
	final static int LENGTH_FLAGS_SHIFT = 3;
	final static int LENGTH_MAX = 31;

	final static String TABLE_NAME = "Relocations";

	final static Schema SCHEMA = new Schema(
		RelocationDBAdapterV6.VERSION, "Index",
		new Field[] { LongField.INSTANCE, ByteField.INSTANCE, IntField.INSTANCE,
			BinaryField.INSTANCE, BinaryField.INSTANCE, StringField.INSTANCE },
		new String[] { "Address", "Status", "Type", "Values", "Bytes", "Symbol Name" });

	static RelocationDBAdapter getAdapter(DBHandle dbHandle, int openMode, AddressMap addrMap,
			TaskMonitor monitor) throws VersionException, IOException {
		try {
			return new RelocationDBAdapterV6(dbHandle, addrMap, openMode == DBConstants.CREATE);
		}
		catch (VersionException e) {
			if (!e.isUpgradable() || openMode == DBConstants.UPDATE) {
				throw e;
			}
			RelocationDBAdapter adapter =
				findReadOnlyAdapter(dbHandle, addrMap);
			if (openMode == DBConstants.UPGRADE) {
				adapter = upgrade(dbHandle, addrMap, adapter, monitor);
			}
			return adapter;
		}
	}

	private static RelocationDBAdapter findReadOnlyAdapter(DBHandle handle, AddressMap addrMap)
			throws IOException, VersionException {
		try {
			return new RelocationDBAdapterV5(handle, addrMap);
		}
		catch (VersionException e) {
			// try the next version
		}
		try {
			return new RelocationDBAdapterV4(handle, addrMap);
		}
		catch (VersionException e) {
			// try the next version
		}
		try {
			return new RelocationDBAdapterV3(handle, addrMap);
		}
		catch (VersionException e) {
			// try the next version
		}
		try {
			return new RelocationDBAdapterV2(handle, addrMap);
		}
		catch (VersionException e) {
			// try the next version			
		}
		try {
			return new RelocationDBAdapterV1(handle, addrMap);
		}
		catch (VersionException e) {
			// try the next version			
		}
		return new RelocationDBAdapterNoTable(handle);
	}

	private static RelocationDBAdapter upgrade(DBHandle dbHandle, AddressMap addrMap,
			RelocationDBAdapter oldAdapter, TaskMonitor monitor)
			throws VersionException, IOException {

		AddressMap oldAddrMap = addrMap.getOldAddressMap();

		DBHandle tmpHandle = new DBHandle();
		try {
			tmpHandle.startTransaction();

			RelocationDBAdapter tmpAdapter =
				new RelocationDBAdapterV6(tmpHandle, addrMap, true);
			RecordIterator iter = oldAdapter.iterator();
			while (iter.hasNext()) {
				DBRecord rec = iter.next();
				// decode with old address map
				Address addr = oldAddrMap.decodeAddress(rec.getLongValue(ADDR_COL));
				BinaryCodedField values =
					new BinaryCodedField((BinaryField) rec.getFieldValue(VALUE_COL));
				tmpAdapter.add(addr, rec.getByteValue(FLAGS_COL), rec.getIntValue(TYPE_COL),
					values.getLongArray(), rec.getBinaryData(BYTES_COL),
					rec.getString(SYMBOL_NAME_COL));
			}

			dbHandle.deleteTable(TABLE_NAME);

			RelocationDBAdapterV6 newAdapter =
				new RelocationDBAdapterV6(dbHandle, addrMap, true);

			iter = tmpAdapter.iterator();
			while (iter.hasNext()) {
				DBRecord rec = iter.next();
				newAdapter.put(rec);
			}
			return newAdapter;
		}
		finally {
			tmpHandle.close();
		}
	}

	/**
	 * Generate flags value for specified status and original bytes length for relocation.
	 * @param status relocation status
	 * @param byteLength byte length (specify 0 if bytes length is known, otherwise 1..31)
	 * @return flags value
	 */
	static byte getFlags(Relocation.Status status, int byteLength) {
		if (byteLength < 0 || byteLength > LENGTH_MAX) {
			throw new IllegalArgumentException("unsupport byte-length: " + byteLength);
		}
		int flags = (status.getValue() & STATUS_FLAGS_MASK);
		flags |= byteLength << LENGTH_FLAGS_SHIFT;
		return (byte) flags;
	}

	/**
	 * Get the status specified by the relocation flags.
	 * @param flags relocation flags
	 * @return relocation status
	 */
	static Status getStatus(byte flags) {
		try {
			return Status.getStatus(flags & STATUS_FLAGS_MASK);
		}
		catch (Exception e) {
			return Status.UNKNOWN;
		}
	}

	/**
	 * Get the byte length specified by the relocation flags.  This length should only be used
	 * if stored bytes is null and relocation has an appropriate status.
	 * @param flags relocation flags
	 * @return byte length specified by the relocation flags (0..31)
	 */
	static int getByteLength(byte flags) {
		return (flags >> LENGTH_FLAGS_SHIFT) & LENGTH_FLAGS_MASK;
	}

	//==================================================================================================
	// Adapter Required Methods
	//==================================================================================================	

	/**
	 * Add new relocation record
	 * @param addr relocation address
	 * @param flags encoded flags (status, length), see {@link #getFlags(Status, int)}.
	 * @param type relocation type
	 * @param values relocation value (e.g., symbol index)
	 * @param bytes original memory bytes
	 * @param symbolName symbol name
	 * @throws IOException if a database error occurs
	 */
	abstract void add(Address addr, byte flags, int type, long[] values, byte[] bytes,
			String symbolName) throws IOException;

	/**
	 * Iterator over all records in address order.
	 * @return record iterator
	 * @throws IOException if a database error occurs
	 */
	abstract RecordIterator iterator() throws IOException;

	/**
	 * Iterator over all relocation records in address order constrained by the specified address set.
	 * @param set address set constraint
	 * @return record iterator
	 * @throws IOException if a database error occurs
	 */
	abstract RecordIterator iterator(AddressSetView set) throws IOException;

	/**
	 * Iterate over relocation records starting at specified start address.
	 * @param start start address
	 * @return relocation record iterator
	 * @throws IOException if a database error occurs
	 */
	abstract RecordIterator iterator(Address start) throws IOException;

	/**
	 * Get the total number of relocation records
	 * @return total number of relocation records
	 */
	abstract int getRecordCount();

	/**
	 * Translate relocation record to latest schema format
	 * @param rec old record requiring translation
	 * @return translated relocation record
	 */
	abstract DBRecord adaptRecord(DBRecord rec);

	//==================================================================================================
	// Complex Upgrade Methods
	//==================================================================================================	

	/**
	 * Perform relocation data migration following an adapter upgrade from a version prior to
	 * V6 (see {@link ProgramDB#RELOCATION_STATUS_ADDED_VERSION})  It is assumed that records have 
	 * already been migrated during the table upgrade with a {@link Status#UNKNOWN} status.
	 * @param adapter latest relocation adapter which permits record updates
	 * @param program program which is "ready"
	 * @param monitor task monitor
	 * @throws IOException if IO error occurs
	 * @throws CancelledException if task cancelled
	 */
	static void preV6DataMigrationUpgrade(RelocationDBAdapter adapter, Program program,
			TaskMonitor monitor) throws IOException, CancelledException {
		
		if (!(adapter instanceof RelocationDBAdapterV6 latestAdapter)) {
			throw new AssertException("latest relocation adapter version expected");
		}
		
		AddressMap addressMap = program.getAddressMap();
		Memory memory = program.getMemory();
		AddressSetView loadedAndInitializedAddressSet = memory.getLoadedAndInitializedAddressSet();
		
		ArrayList<DBRecord> list = new ArrayList<>();
		RecordIterator recIter = latestAdapter.iterator();
		while (recIter.hasNext()) {
			list.add(recIter.next());
		}
		
		// Sort on address and key order
		Collections.sort(list, (r1,r2) -> {
			Address a1 = addressMap.decodeAddress(r1.getLongValue(ADDR_COL));
			Address a2 = addressMap.decodeAddress(r2.getLongValue(ADDR_COL));
			int c = a1.compareTo(a2);
			if (c == 0) { // assumes positive keys only
				c = Long.compare(r1.getKey(), r2.getKey());
			}
			return c;
		});
		
		// Update status/length of each relocation record
		for (int i = 0; i < list.size(); i++) {
			monitor.checkCancelled();
			DBRecord rec = list.get(i);
			int byteLength = 0;
			Status status;
			Address relocAddr = addressMap.decodeAddress(rec.getLongValue(ADDR_COL));
			byte[] bytes = rec.getBinaryData(BYTES_COL);
			if (!loadedAndInitializedAddressSet.contains(relocAddr)) {
				status = Status.FAILURE;
			}
			else if (bytes != null) {
				status = rec.getIntValue(TYPE_COL) == 0 ? Status.APPLIED_OTHER : Status.APPLIED;
			}
			else {
				byteLength = computeOriginalFileBytesLength(list, relocAddr, i, program);
				if (byteLength < 0) {
					status = Status.PARTIAL;
					byteLength = 0;
				}
				else if (byteLength == 0) {
					status = Status.UNKNOWN;
				}
				else {
					status = rec.getIntValue(TYPE_COL) == 0 ? Status.APPLIED_OTHER
							: Status.APPLIED;
				}
			}
			rec.setByteValue(FLAGS_COL, getFlags(status, byteLength));
			latestAdapter.put(rec);
		}
	}

	/**
	 * Computes a relocation byte length which will be no greater than the default length
	 * (see {@link RelocationManager#getDefaultOriginalByteLength(Program)} which should not
	 * overlap a subsequent relocation record.
	 * <p>
	 * NOTE: it is possible for a patched instruction to interfere with this logic, however
	 * the result should be no worse than the previously over-extended relocation byte range.
	 * 
	 * @param list sorted relocation list
	 * @param relocAddr relocation address
	 * @param index relocation index within list
	 * @param program program containing relocations
	 * @return number of original bytes modified or -1 if there is a subsequent relocation at the
	 * same address
	 * @throws IOException if an IO error occurs
	 */
	private static int computeOriginalFileBytesLength(ArrayList<DBRecord> list, Address relocAddr,
			int index, Program program) throws IOException {

		AddressSpace space = relocAddr.getAddressSpace();
		AddressMap addrMap = program.getAddressMap();
		Memory memory = program.getMemory();

		int defaultLength = RelocationManager.getDefaultOriginalByteLength(program);

		int nextIndex = index + 1;
		if (nextIndex < list.size()) {
			DBRecord nextRec = list.get(nextIndex);
			Address nextAddr = addrMap.decodeAddress(nextRec.getLongValue(ADDR_COL));
			if (nextAddr.getAddressSpace().equals(relocAddr.getAddressSpace())) {
				defaultLength = (int) Math.min(defaultLength, nextAddr.subtract(relocAddr));
			}
		}

		if (defaultLength == 0) {
			return 0;
		}

		// Limit relocation length based upon end of address space
		try {
			relocAddr.addNoWrap(defaultLength - 1); // test for valid length
		}
		catch (AddressOverflowException e) {
			defaultLength = (int) space.getMaxAddress().subtract(relocAddr) + 1;
		}

		// Obtain original and current memory bytes at relocation address for comparison
		byte[] originalBytes = RelocationManager.getOriginalBytes(memory, relocAddr, defaultLength);
		byte[] currentBytes = new byte[defaultLength];
		try {
			defaultLength = memory.getBytes(relocAddr, currentBytes);
		}
		catch (MemoryAccessException e) {
			throw new AssertException(e); // unexpected - already checked relocAddr
		}

		// Indentify modification length
		while (defaultLength != 0) {
			int byteIndex = defaultLength - 1;
			if (originalBytes[byteIndex] != currentBytes[byteIndex]) {
				break;
			}
			--defaultLength;
		}
		return defaultLength;
	}

	//==================================================================================================
	// Inner Classes
	//==================================================================================================	

	class RecordIteratorAdapter implements RecordIterator {
		RecordIterator it;

		RecordIteratorAdapter(RecordIterator it) {
			this.it = it;
		}

		@Override
		public boolean delete() throws IOException {
			return it.delete();
		}

		@Override
		public boolean hasNext() throws IOException {
			return it.hasNext();
		}

		@Override
		public boolean hasPrevious() throws IOException {
			return it.hasPrevious();
		}

		@Override
		public DBRecord next() throws IOException {
			DBRecord rec = it.next();
			return adaptRecord(rec);
		}

		@Override
		public DBRecord previous() throws IOException {
			DBRecord rec = it.previous();
			return adaptRecord(rec);
		}

	}
}
