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

import ghidra.framework.options.Options;
import ghidra.program.database.ManagerDB;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.map.AddressMap;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.reloc.RelocationTable;
import ghidra.util.Lock;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;
import java.util.Iterator;

import db.*;

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
		initializeAdapters(handle, openMode, monitor);
	}

	private void initializeAdapters(DBHandle handle, int openMode, TaskMonitor monitor)
			throws VersionException, IOException {
		adapter = RelocationDBAdapter.getAdapter(handle, openMode, addrMap, monitor);
	}

	@Override
	public void invalidateCache(boolean all) {
		// guess we don't care
	}

	@Override
	public void setProgram(ProgramDB p) {
		this.program = p;
	}

	@Override
	public void programReady(int openMode, int currentRevision, TaskMonitor monitor)
			throws IOException, CancelledException {
		// Nothing to do
	}

	@Override
	public Relocation add(Address addr, int type, long[] values, byte[] bytes, String symbolName) {
		try {
			adapter.add(addrMap.getKey(addr, true), type, values, bytes, symbolName);
			return new Relocation(addr, type, values, bytes, symbolName);
		}
		catch (IOException e) {
			program.dbError(e);
		}
		return null;
	}

	@Override
	public void remove(Relocation reloc) {
		try {
			adapter.remove(addrMap.getKey(reloc.getAddress(), false));
		}
		catch (IOException e) {
			program.dbError(e);
		}
	}

	@Override
	public Relocation getRelocation(Address addr) {
		try {
			DBRecord rec = adapter.get(addrMap.getKey(addr, false));
			if (rec != null) {
				return getRelocation(rec);
			}
		}
		catch (IOException e) {
			program.dbError(e);
		}
		return null;
	}

	private Relocation getRelocation(DBRecord rec) {
		BinaryCodedField valuesField =
			new BinaryCodedField((BinaryField) rec.getFieldValue(RelocationDBAdapter.VALU_COL));
		return new Relocation(addrMap.decodeAddress(rec.getKey()),
			rec.getIntValue(RelocationDBAdapter.TYPE_COL), valuesField.getLongArray(),
			rec.getBinaryData(RelocationDBAdapter.BYTES_COL),
			rec.getString(RelocationDBAdapter.SYMBOL_NAME_COL));
	}

	@Override
	public Iterator<Relocation> getRelocations() {
		RecordIterator ri = null;
		try {
			ri = adapter.iterator();
		}
		catch (IOException e) {
			program.dbError(e);
		}
		return new RelocationIterator(ri);
	}

	@Override
	public Relocation getRelocationAfter(Address addr) {
		RecordIterator ri = null;
		try {
			ri = adapter.iterator(addr);
			if (ri.hasNext()) {
				DBRecord r = ri.next();
				Relocation relocation = getRelocation(r);
				if (!relocation.getAddress().equals(addr)) {
					return relocation;
				}
				// The previous relocation was for the address that we want one after, so try again.
				if (ri.hasNext()) {
					r = ri.next();
					return getRelocation(r);
				}
			}
		}
		catch (IOException e) {
			program.dbError(e);
		}
		return null;
	}

	@Override
	public Iterator<Relocation> getRelocations(AddressSetView set) {
		RecordIterator ri = null;
		try {
			ri = adapter.iterator(set);
		}
		catch (IOException e) {
			program.dbError(e);
		}
		return new RelocationIterator(ri);
	}

	private class RelocationIterator implements Iterator<Relocation> {
		private RecordIterator ri;

		RelocationIterator(RecordIterator ri) {
			this.ri = ri;
		}

		@Override
		public boolean hasNext() {
			if (ri == null)
				return false;
			try {
				return ri.hasNext();
			}
			catch (IOException e) {
				program.dbError(e);
			}
			return false;
		}

		@Override
		public Relocation next() {
			if (ri == null)
				return null;
			try {
				DBRecord r = ri.next();
				return getRelocation(r);
			}
			catch (IOException e) {
				program.dbError(e);
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
