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
import java.util.*;

import db.*;
import ghidra.framework.options.Options;
import ghidra.program.database.ManagerDB;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.map.AddressMap;
import ghidra.program.database.mem.AddressSourceInfo;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.program.model.reloc.RelocationTable;
import ghidra.program.util.ChangeManager;
import ghidra.util.Lock;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 * An implementation of the relocation table interface.
 * 
 * 
 */
public class RelocationManager implements RelocationTable, ManagerDB {

	private ProgramDB program;
	private AddressMap addrMap;
	private RelocationDBAdapter adapter;
	private Boolean isRelocatable = null;
	private Lock lock;

	/**
	 * Constructs a new relocation manager.
	 * @param handle the database handle
	 * @param addrMap the address map
	 * @param openMode the open mode; CREATE, UPDATE, READONLY, UPGRADE
	 * @param lock the program synchronization lock
	 * @param monitor the task monitor
	 * @throws VersionException
	 * @throws IOException
	 */
	public RelocationManager(DBHandle handle, AddressMap addrMap, int openMode, Lock lock,
			TaskMonitor monitor) throws VersionException, IOException {
		this.addrMap = addrMap;
		this.lock = lock;
		initializeAdapters(handle, openMode, monitor);
	}

	private void initializeAdapters(DBHandle handle, int openMode, TaskMonitor monitor)
			throws VersionException, IOException {
		adapter = RelocationDBAdapter.getAdapter(handle, openMode, addrMap, monitor);
	}

	@Override
	public void invalidateCache(boolean all) {
		// no cache or DB objects
	}

	@Override
	public void setProgram(ProgramDB p) {
		this.program = p;
	}

	@Override
	public void programReady(int openMode, int currentRevision, TaskMonitor monitor)
			throws IOException, CancelledException {

		if (openMode == DBConstants.UPGRADE &&
			currentRevision < ProgramDB.RELOCATION_STATUS_ADDED_VERSION) {
			RelocationDBAdapter.preV6DataMigrationUpgrade(adapter, program, monitor);
		}
	}

	/**
	 * Get default byte length when unknown
	 * @param program program containing relocation
	 * @return default byte length
	 */
	static int getDefaultOriginalByteLength(Program program) {
		return program.getDefaultPointerSize() > 4 ? 8 : 4;
	}

	/**
	 * Get the specified number of original file bytes for the specified address.  Any offsets
	 * not backed by file bytes will have a 0-byte value.
	 * @param memory program memory
	 * @param addr memory address
	 * @param byteCount number of original file bytes to read
	 * @return byte array of length byteCount
	 * @throws IOException if an IO error occurs
	 */
	static byte[] getOriginalBytes(Memory memory, Address addr, int byteCount) throws IOException {
		byte[] originalBytes = new byte[byteCount];
		// must get one byte at a time due to the possibility of byte-mapped memory use
		for (int i = 0; i < byteCount; i++) {
			if (i != 0) {
				addr = addr.next();
			}
			if (addr == null) {
				break;
			}
			AddressSourceInfo addressSourceInfo = memory.getAddressSourceInfo(addr);
			if (addressSourceInfo == null) {
				return originalBytes;
			}
			originalBytes[i] = addressSourceInfo.getOriginalValue();
		}
		return originalBytes;
	}

	private byte[] getOriginalBytes(Address addr, Status status, byte[] bytes, int defaultLength)
			throws IOException {
		if (bytes != null || !status.hasBytes()) {
			return bytes;
		}
		int byteCount = defaultLength;
		if (defaultLength <= 0) {
			byteCount = getDefaultOriginalByteLength(program);
		}
		return getOriginalBytes(program.getMemory(), addr, byteCount);
	}

	@Override
	public Relocation add(Address addr, Status status, int type, long[] values, byte[] bytes,
			String symbolName) {
		lock.acquire();
		try {
			byte flags = RelocationDBAdapter.getFlags(status, 0);
			adapter.add(addr, flags, type, values, bytes, symbolName);
			Relocation reloc = new Relocation(addr, status, type, values,
				getOriginalBytes(addr, status, bytes, 0),
				symbolName);

			// fire event
			// TODO: full change support is missing
			program.setChanged(ChangeManager.DOCR_RELOCATION_ADDED, null, reloc);

			return reloc;
		}
		catch (IOException e) {
			program.dbError(e);
		}
		finally {
			lock.release();
		}
		return null;
	}

	@Override
	public Relocation add(Address addr, Status status, int type, long[] values, int byteLength,
			String symbolName) {
		lock.acquire();
		try {
			byte flags = RelocationDBAdapter.getFlags(status, byteLength);
			adapter.add(addr, flags, type, values, null, symbolName);
			Relocation reloc = new Relocation(addr, status, type, values,
				getOriginalBytes(addr, status, null, byteLength),
				symbolName);

			// fire event
			// TODO: full change support is missing
			program.setChanged(ChangeManager.DOCR_RELOCATION_ADDED, null, reloc);

			return reloc;
		}
		catch (IOException e) {
			program.dbError(e);
		}
		finally {
			lock.release();
		}
		return null;
	}

	@Override
	public boolean hasRelocation(Address addr) {
		lock.acquire();
		try {
			RecordIterator it = adapter.iterator(addr);
			if (!it.hasNext()) {
				return false;
			}
			DBRecord r = it.next();
			Address a = addrMap.decodeAddress(r.getLongValue(RelocationDBAdapter.ADDR_COL));
			return addr.equals(a);
		}
		catch (IOException e) {
			program.dbError(e);
		}
		finally {
			lock.release();
		}
		return false;
	}

	@Override
	public List<Relocation> getRelocations(Address addr) {
		lock.acquire();
		try {
			List<Relocation> list = null;
			RecordIterator it = adapter.iterator(addr);
			while (it.hasNext()) {
				DBRecord rec = it.next();
				Address a = addrMap.decodeAddress(rec.getLongValue(RelocationDBAdapter.ADDR_COL));
				if (!addr.equals(a)) {
					break;
				}
				if (list == null) {
					list = new ArrayList<>();
				}
				list.add(getRelocation(rec));
			}
			return list == null ? List.of() : list;
		}
		catch (IOException e) {
			program.dbError(e);
		}
		finally {
			lock.release();
		}
		return null;
	}

	private Relocation getRelocation(DBRecord rec) throws IOException {
		Address addr = addrMap.decodeAddress(rec.getLongValue(RelocationDBAdapter.ADDR_COL));
		byte flags = rec.getByteValue(RelocationDBAdapter.FLAGS_COL);
		Status status = RelocationDBAdapter.getStatus(flags);
		int length = RelocationDBAdapter.getByteLength(flags);
		BinaryCodedField valuesField =
			new BinaryCodedField((BinaryField) rec.getFieldValue(RelocationDBAdapter.VALUE_COL));
		byte[] originalBytes =
			getOriginalBytes(addr, status, rec.getBinaryData(RelocationDBAdapter.BYTES_COL),
				length);
		return new Relocation(addr, status, rec.getIntValue(RelocationDBAdapter.TYPE_COL),
			valuesField.getLongArray(),
			originalBytes, rec.getString(RelocationDBAdapter.SYMBOL_NAME_COL));
	}

	@Override
	public Iterator<Relocation> getRelocations() {
		RecordIterator ri = null;
		lock.acquire();
		try {
			ri = adapter.iterator();
		}
		catch (IOException e) {
			program.dbError(e);
		}
		finally {
			lock.release();
		}
		return new RelocationIterator(ri);
	}

	@Override
	public Address getRelocationAddressAfter(Address addr) {
		lock.acquire();
		try {
			RecordIterator it = adapter.iterator(addr);
			while (it.hasNext()) {
				DBRecord rec = it.next();
				Address a = addrMap.decodeAddress(rec.getLongValue(RelocationDBAdapter.ADDR_COL));
				if (!addr.equals(a)) {
					return a;
				}
			}
		}
		catch (IOException e) {
			program.dbError(e);
		}
		finally {
			lock.release();
		}
		return null;
	}

	@Override
	public Iterator<Relocation> getRelocations(AddressSetView set) {
		RecordIterator it = null;
		lock.acquire();
		try {
			it = adapter.iterator(set);
		}
		catch (IOException e) {
			program.dbError(e);
		}
		finally {
			lock.release();
		}
		return new RelocationIterator(it);
	}

	private class RelocationIterator implements Iterator<Relocation> {
		private RecordIterator it;

		RelocationIterator(RecordIterator ri) {
			this.it = ri;
		}

		@Override
		public boolean hasNext() {
			if (it == null)
				return false;
			lock.acquire();
			try {
				return it.hasNext();
			}
			catch (IOException e) {
				program.dbError(e);
			}
			finally {
				lock.release();
			}
			return false;
		}

		@Override
		public Relocation next() {
			if (it == null)
				return null;
			lock.acquire();
			try {
				DBRecord r = it.next();
				return getRelocation(r);
			}
			catch (IOException e) {
				program.dbError(e);
			}
			finally {
				lock.release();
			}
			return null;
		}

		@Override
		public void remove() {
			throw new UnsupportedOperationException(
				"Cannot remove from relocation table inside iterator!");
		}
	}

	@Override
	public int getSize() {
		return adapter.getRecordCount();
	}

	@Override
	public boolean isRelocatable() {
		if (isRelocatable == null) {
			Options propList = program.getOptions(Program.PROGRAM_INFO);
			if (propList.contains(RELOCATABLE_PROP_NAME)) {
				isRelocatable = propList.getBoolean(RELOCATABLE_PROP_NAME, false);
			}
			else {
				isRelocatable = (getSize() > 0);
			}
		}
		return isRelocatable.booleanValue();
	}

	@Override
	public void deleteAddressRange(Address startAddr, Address endAddr, TaskMonitor monitor) {
		// do nothing here
	}

	@Override
	public void moveAddressRange(Address fromAddr, Address toAddr, long length, TaskMonitor monitor) {
		// do nothing here
	}

}
