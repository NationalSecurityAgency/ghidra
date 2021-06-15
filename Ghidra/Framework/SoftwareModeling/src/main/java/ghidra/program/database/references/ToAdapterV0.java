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

import db.*;
import db.util.ErrorHandler;
import ghidra.program.database.DBObjectCache;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.map.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.Reference;
import ghidra.util.exception.VersionException;

/**
 * 
 *
 * To change the template for this generated type comment go to
 * Window&gt;Preferences&gt;Java&gt;Code Generation&gt;Code and Comments
 */
class ToAdapterV0 extends ToAdapter {

	private Table table;
	private AddressMap addrMap;
	private ErrorHandler errHandler;

	ToAdapterV0(DBHandle handle, AddressMap addrMap, ErrorHandler errHandler)
			throws VersionException {
		this.addrMap = addrMap.getOldAddressMap();
		this.errHandler = errHandler;
		table = handle.getTable(TO_REFS_TABLE_NAME);
		if (table == null) {
			throw new VersionException("Missing Table: " + TO_REFS_TABLE_NAME);
		}
		else if (table.getSchema().getVersion() != 0) {
			throw new VersionException(false);
		}
	}

	@Override
	public RefList createRefList(ProgramDB program, DBObjectCache<RefList> cache, Address to)
			throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	public RefList getRefList(ProgramDB program, DBObjectCache<RefList> cache, Address to,
			long toAddr) throws IOException {
		DBRecord rec = translateRecord(table.getRecord(toAddr));
		if (rec != null) {
			return new RefListV0(rec, this, addrMap, program, cache, false);
		}
		return null;
	}

	@Override
	boolean hasRefTo(long toAddr) throws IOException {
		return table.hasRecord(toAddr);
	}

	@Override
	public DBRecord createRecord(long key, int numRefs, byte refLevel, byte[] refData)
			throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	public DBRecord getRecord(long key) throws IOException {
		return translateRecord(table.getRecord(key));
	}

	@Override
	public void putRecord(DBRecord record) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	public void removeRecord(long key) throws IOException {
		throw new UnsupportedOperationException();
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
		throw new UnsupportedOperationException();
	}

	@Override
	int getRecordCount() {
		return table.getRecordCount();
	}

	private DBRecord translateRecord(DBRecord oldRec) {
		if (oldRec == null) {
			return null;
		}
		DBRecord rec = TO_REFS_SCHEMA.createRecord(oldRec.getKey());
		rec.setIntValue(REF_COUNT_COL, oldRec.getIntValue(REF_COUNT_COL));
		rec.setBinaryData(REF_DATA_COL, oldRec.getBinaryData(REF_DATA_COL));
		rec.setByteValue(REF_LEVEL_COL, getRefLevel(rec));
		return rec;
	}

	private byte getRefLevel(DBRecord newRec) {
		try {
			RefList refList = new RefListV0(newRec, this, addrMap, null, null, false);
			Reference[] refs = refList.getAllRefs();
			byte refLevel = (byte) -1;
			for (Reference ref : refs) {
				byte level = RefListV0.getRefLevel(ref.getReferenceType());
				if (level > refLevel) {
					refLevel = level;
				}
			}
			return refLevel;
		}
		catch (IOException e) {
			throw new RuntimeException("IOException unexpected for ToAdapterV0 RefList");
		}
	}

	class TranslatedRecordIterator implements RecordIterator {
		private RecordIterator it;

		TranslatedRecordIterator(RecordIterator it) {
			this.it = it;
		}

		@Override
		public boolean delete() throws IOException {
			throw new UnsupportedOperationException();
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
			return translateRecord(rec);
		}

		@Override
		public DBRecord previous() throws IOException {
			DBRecord rec = it.previous();
			return translateRecord(rec);
		}
	}

}
