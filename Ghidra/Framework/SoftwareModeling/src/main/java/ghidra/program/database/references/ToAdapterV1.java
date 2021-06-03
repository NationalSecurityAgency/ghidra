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
/*
 * Created on Sep 15, 2003
 *
 * To change the template for this generated file go to
 * Window&gt;Preferences&gt;Java&gt;Code Generation&gt;Code and Comments
 */
package ghidra.program.database.references;

import java.io.IOException;
import java.util.Iterator;
import java.util.NoSuchElementException;

import db.*;
import db.util.ErrorHandler;
import ghidra.program.database.DBObjectCache;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.map.*;
import ghidra.program.model.address.*;
import ghidra.util.exception.VersionException;

/**
 * Version 
 */
class ToAdapterV1 extends ToAdapter {

	private Table table;
	private AddressMap addrMap;
	private ErrorHandler errHandler;

	ToAdapterV1(DBHandle handle, boolean create, AddressMap addrMap, ErrorHandler errHandler)
			throws IOException, VersionException {
		this.addrMap = addrMap;
		this.errHandler = errHandler;
		if (create) {
			table = handle.createTable(TO_REFS_TABLE_NAME, TO_REFS_SCHEMA);
		}
		else {
			table = handle.getTable(TO_REFS_TABLE_NAME);
			if (table == null) {
				throw new VersionException("Missing Table: " + TO_REFS_TABLE_NAME);
			}
			else if (table.getSchema().getVersion() != 1) {
				int version = table.getSchema().getVersion();
				if (version < 1) {
					throw new VersionException(true);
				}
				throw new VersionException(VersionException.NEWER_VERSION, false);
			}
		}
	}

	@Override
	public RefList createRefList(ProgramDB program, DBObjectCache<RefList> cache, Address to)
			throws IOException {
		return new RefListV0(to, this, addrMap, program, cache, false);
	}

	@Override
	public RefList getRefList(ProgramDB program, DBObjectCache<RefList> cache, Address to,
			long toAddr) throws IOException {
		DBRecord rec = table.getRecord(toAddr);
		if (rec != null) {
			if (rec.getBinaryData(REF_DATA_COL) == null) {
				return new BigRefListV0(rec, this, addrMap, program, cache, false);
			}
			return new RefListV0(rec, this, addrMap, program, cache, false);
		}
		return null;
	}

	@Override
	boolean hasRefTo(long toAddr) throws IOException {
		// TODO: Do we need to check for empty BigRefList?
		return table.hasRecord(toAddr);
	}

	@Override
	public DBRecord createRecord(long key, int numRefs, byte refLevel, byte[] refData)
			throws IOException {
		DBRecord rec = TO_REFS_SCHEMA.createRecord(key);
		rec.setIntValue(REF_COUNT_COL, numRefs);
		rec.setBinaryData(REF_DATA_COL, refData);
		rec.setByteValue(REF_LEVEL_COL, refLevel);
		table.putRecord(rec);
		return rec;
	}

	@Override
	public DBRecord getRecord(long key) throws IOException {
		return table.getRecord(key);
	}

	@Override
	public void putRecord(DBRecord record) throws IOException {
		table.putRecord(record);
	}

	@Override
	public void removeRecord(long key) throws IOException {
		table.deleteRecord(key);
	}

	@Override
	AddressIterator getToIterator(boolean forward) throws IOException {
		return new AddressKeyAddressIterator(new AddressKeyIterator(table, addrMap, forward),
			forward, addrMap, errHandler);
	}

	@Override
	AddressIterator getToIterator(Address startAddr, boolean forward) throws IOException {
		return new AddressKeyAddressIterator(new AddressKeyIterator(table, addrMap, startAddr,
			forward), forward, addrMap, errHandler);
	}

	@Override
	AddressIterator getToIterator(AddressSetView set, boolean forward) throws IOException {
		return new AddressKeyAddressIterator(new AddressKeyIterator(table, addrMap, set,
			set.getMinAddress(), forward), forward, addrMap, errHandler);
	}

	@Override
	AddressIterator getOldNamespaceAddresses(AddressSpace addrSpace) throws IOException {
		// The min/max reflects the actual keys which get produced
		long minKey =
			addrMap.getKey(OldGenericNamespaceAddress.getMinAddress(addrSpace,
				OldGenericNamespaceAddress.OLD_MIN_NAMESPACE_ID), false);
		long maxKey =
			addrMap.getKey(OldGenericNamespaceAddress.getMaxAddress(addrSpace,
				OldGenericNamespaceAddress.OLD_MAX_NAMESPACE_ID), false);
		return new MyAddressKeyAddressIterator(table.longKeyIterator(minKey, maxKey, minKey));
	}

	@Override
	int getRecordCount() {
		return table.getRecordCount();
	}

	/**
	 * Converts an DBLongIterator into an AddressIterator
	 */
	private class MyAddressKeyAddressIterator implements AddressIterator {

		private DBLongIterator keyIter;

		public MyAddressKeyAddressIterator(DBLongIterator keyIter) {
			this.keyIter = keyIter;
		}

		/**
		 * @see java.util.Iterator#remove()
		 */
		@Override
		public void remove() {
			throw new UnsupportedOperationException();
		}

		/**
		 * @see ghidra.program.model.address.AddressIterator#hasNext()
		 */
		@Override
		public boolean hasNext() {
			try {
				return keyIter.hasNext();
			}
			catch (IOException e) {
				errHandler.dbError(e);
			}
			return false;
		}

		/**
		 * @see ghidra.program.model.address.AddressIterator#next()
		 */
		@Override
		public Address next() {
			Address addr = null;
			try {
				addr = addrMap.decodeAddress(keyIter.next());
			}
			catch (NoSuchElementException e) {
				return null;
			}
			catch (IOException e) {
				// Ignore
			}
			return addr;
		}

		@Override
		public Iterator<Address> iterator() {
			return this;
		}
	}

}
