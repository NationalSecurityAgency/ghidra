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
package ghidra.program.database.references;

import java.io.IOException;

import db.*;
import db.util.ErrorHandler;
import ghidra.program.database.DBObjectCache;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.map.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.RefTypeFactory;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.VersionException;

class ToAdapterSharedTable extends ToAdapter {

	static final String OLD_REFS_TABLE_NAME = "Memory References";

//	Schema oldSchema = new Schema(0, "Key",
//			new Class[] {LongField.class, 
//				LongField.class,
//				ShortField.class, BooleanField.class,
//				ShortField.class, LongField.class,
//				LongField.class, BooleanField.class,
//				BooleanField.class}, 
//			new String[] {"From Address", "To Address",
//				"Op Index", "User Defined", "Ref Type",
//				"Symbol ID", "Base Address", "Is Offset",
//				"Is Primary"});

	static final int OLD_FROM_ADDR_COL = 0; // Indexed Column
	static final int OLD_TO_ADDR_COL = 1; // Indexed Column
	static final int OLD_OP_INDEX_COL = 2;
	static final int OLD_USER_DEFINED_COL = 3;
	static final int OLD_REF_TYPE_COL = 4;
	static final int OLD_SYMBOL_ID_COL = 5;
	static final int OLD_BASE_ADDR_COL = 6;
	static final int OLD_IS_OFFSET_COL = 7;
	static final int OLD_IS_PRIMARY_COL = 8;

	private Table table;
	private AddressMap addrMap;
	private ErrorHandler errHandler;

	ToAdapterSharedTable(DBHandle handle, AddressMap addrMap, ErrorHandler errHandler)
			throws VersionException {
		this.addrMap = addrMap.getOldAddressMap();
		this.errHandler = errHandler;
		table = handle.getTable(OLD_REFS_TABLE_NAME);
		if (table == null) {
			throw new VersionException("Missing Table: " + OLD_REFS_TABLE_NAME);
		}
		else if (table.getSchema().getVersion() != 0) {
			throw new VersionException(false);
		}
	}

	@Override
	RefList createRefList(ProgramDB program, DBObjectCache<RefList> cache, Address toAddr)
			throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	RefList getRefList(ProgramDB program, DBObjectCache<RefList> cache, Address to, long toAddr)
			throws IOException {
		LongField toField = new LongField(toAddr);

		RefList toRefs = new RefListV0(toAddr, addrMap, program, cache, false);

		RecordIterator iter = table.indexIterator(OLD_TO_ADDR_COL, toField, toField, true);
		while (iter.hasNext()) {
			DBRecord rec = iter.next();

			boolean isUser = rec.getBooleanValue(OLD_USER_DEFINED_COL);
			SourceType source = isUser ? SourceType.USER_DEFINED : SourceType.DEFAULT;

			toRefs.addRef(addrMap.decodeAddress(rec.getLongValue(OLD_FROM_ADDR_COL)), to,
				RefTypeFactory.get((byte) rec.getShortValue(OLD_REF_TYPE_COL)),
				rec.getShortValue(OLD_OP_INDEX_COL), rec.getLongValue(OLD_SYMBOL_ID_COL),
				rec.getBooleanValue(OLD_IS_PRIMARY_COL), source, false, false, 0);

		}
		if (toRefs.isEmpty()) {
			return null;
		}
		return toRefs;
	}

	@Override
	boolean hasRefTo(long toAddr) throws IOException {
		LongField toField = new LongField(toAddr);
		RecordIterator iter = table.indexIterator(OLD_TO_ADDR_COL, toField, toField, true);
		return iter.hasNext();
	}

	@Override
	public DBRecord createRecord(long key, int numRefs, byte refType, byte[] refData)
			throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	public DBRecord getRecord(long key) throws IOException {
		return table.getRecord(key);
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
		AddressIndexKeyIterator iter =
			new AddressIndexKeyIterator(table, OLD_TO_ADDR_COL, addrMap, forward);
		return new AddressKeyAddressIterator(iter, forward, addrMap, errHandler);
	}

	@Override
	AddressIterator getToIterator(Address startAddr, boolean forward) throws IOException {
		AddressIndexKeyIterator iter =
			new AddressIndexKeyIterator(table, OLD_TO_ADDR_COL, addrMap, startAddr, forward);
		return new AddressKeyAddressIterator(iter, forward, addrMap, errHandler);
	}

	@Override
	AddressIterator getToIterator(AddressSetView set, boolean forward) throws IOException {
		AddressIndexKeyIterator iter =
			new AddressIndexKeyIterator(table, OLD_FROM_ADDR_COL, addrMap, set, forward);
		return new AddressKeyAddressIterator(iter, forward, addrMap, errHandler);
	}

	@Override
	AddressIterator getOldNamespaceAddresses(AddressSpace addrSpace) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	int getRecordCount() {
		return table.getRecordCount();
	}

}
