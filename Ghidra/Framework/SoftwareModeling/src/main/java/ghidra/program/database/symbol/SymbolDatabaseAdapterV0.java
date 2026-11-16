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
package ghidra.program.database.symbol;

import java.io.IOException;

import db.*;
import ghidra.framework.data.OpenMode;
import ghidra.program.database.map.AddressMap;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * <code>SymbolDatabaseAdapterV0</code> handles symbol tables which were created 
 * prior to the addition of Namespace support and Function symbols.  Function symbols 
 * are synthesized for those functions whose entry point currently has a 
 * label symbol.  The ID of these synthesized function symbols is the max ID plus 
 * the function ID.  The function Namespace ID is the same as the Function ID.
 * The upgrade of this version may also add additional Function symbols for which there
 * is no corresponding label symbol.
 */
class SymbolDatabaseAdapterV0 extends PreV6SymbolDatabaseAdapter implements RecordTranslator {

/* Do not remove the following commented out schema! It shows the version 0 symbol table schema. */
//	static final Schema SYMBOL_SCHEMA = new Schema(0, "Key", 
//			new Class[] {StringField.class,
//				BooleanField.class, BooleanField.class,
//				BooleanField.class, LongField.class},
//			new String[] {"Name", "Is Dynamic", "Is Local",
//				"Is Primary", "Address"});

	private static final int VERSION = 0;

	private static final int V0_SYMBOL_NAME_COL = 0;
	private static final int V0_SYMBOL_IS_DYNAMIC_COL = 1;
	private static final int V0_SYMBOL_LOCAL_COL = 2;
	private static final int V0_SYMBOL_PRIMARY_COL = 3;
	private static final int V0_SYMBOL_ADDR_COL = 4;

	private Table symbolTable;
	private AddressMap addrMap;

	/**
	 * Construct a Version-0 Symbol Table adapter.
	 * @param handle the database handle.
	 * @param addrMap the address map
	 * @throws VersionException if the database version doesn't match this adapter.
	 */
	SymbolDatabaseAdapterV0(DBHandle handle, AddressMap addrMap) throws VersionException {
		this.addrMap = addrMap.getOldAddressMap();
		symbolTable = handle.getTable(SYMBOL_TABLE_NAME);
		if (symbolTable == null) {
			throw new VersionException("Missing Table: " + SYMBOL_TABLE_NAME);
		}
		if (symbolTable.getSchema().getVersion() != VERSION) {
			throw new VersionException(false);
		}
	}

	/**
	 * Stores local symbols information in a temporary database table because this version
	 * is so old, we don't have enough information in the record to upgrade during the normal
	 * upgrade time. So we store off the information and will complete this upgrade when
	 * {@link SymbolManager#domainObjectReady(OpenMode, int, TaskMonitor)} is called
	 * 
	 * @param handle handle to temporary database
	 * @param monitor the {@link TaskMonitor}
	 * @return the next available database key after all the records are store
	 * @throws IOException if a database I/O error occurs
	 * @throws CancelledException if the user cancels the upgrade
	 */
	long extractLocalSymbols(DBHandle handle, TaskMonitor monitor)
			throws IOException, CancelledException {

		monitor.setMessage("Extracting Local Symbols...");
		monitor.initialize(symbolTable.getRecordCount());
		int cnt = 0;
		RecordIterator iter = symbolTable.iterator();
		while (iter.hasNext()) {
			monitor.checkCancelled();
			DBRecord rec = iter.next();
			if (rec.getBooleanValue(V0_SYMBOL_LOCAL_COL)) {
				SymbolManager.saveLocalSymbol(handle, rec.getKey(),
					rec.getLongValue(V0_SYMBOL_ADDR_COL), rec.getString(V0_SYMBOL_NAME_COL),
					rec.getBooleanValue(V0_SYMBOL_PRIMARY_COL));
			}
			monitor.setProgress(++cnt);
		}
		return symbolTable.getKey();
	}

	@Override
	public DBRecord translateRecord(DBRecord record) {
		if (record == null) {
			return null;
		}
		if (record.getBooleanValue(V0_SYMBOL_IS_DYNAMIC_COL) ||
			record.getBooleanValue(V0_SYMBOL_LOCAL_COL)) {
			throw new AssertException("Unexpected Symbol");
		}
		DBRecord rec = SymbolDatabaseAdapter.SYMBOL_SCHEMA.createRecord(record.getKey());

		String symbolName = record.getString(V0_SYMBOL_NAME_COL);
		rec.setString(SymbolDatabaseAdapter.SYMBOL_NAME_COL, symbolName);
		long addressKey = record.getLongValue(V0_SYMBOL_ADDR_COL);
		rec.setLongValue(SymbolDatabaseAdapter.SYMBOL_ADDR_COL, addressKey);

		rec.setByteValue(SymbolDatabaseAdapter.SYMBOL_TYPE_COL, SymbolType.LABEL.getID());

		long namespaceId = Namespace.GLOBAL_NAMESPACE_ID;
		rec.setLongValue(SymbolDatabaseAdapter.SYMBOL_PARENT_ID_COL, namespaceId);

		rec.setByteValue(SymbolDatabaseAdapter.SYMBOL_FLAGS_COL,
			(byte) SourceType.USER_DEFINED.ordinal());

		//
		// Convert sparse columns
		//

		Field hash = computeLocatorHash(symbolName, namespaceId, addressKey);
		rec.setField(SymbolDatabaseAdapter.SYMBOL_HASH_COL, hash);

		boolean isPrimary = record.getBooleanValue(V0_SYMBOL_PRIMARY_COL);
		if (isPrimary) {
			rec.setLongValue(SymbolDatabaseAdapter.SYMBOL_PRIMARY_COL, addressKey);
		}

		return rec;
	}

	@Override
	RecordIterator getSymbols() throws IOException {
		RecordIterator it = symbolTable.iterator();
		return new TranslatedRecordIterator(it, this);
	}

	@Override
	protected int getVersion() {
		return VERSION;
	}

	@Override
	int getSymbolCount() {
		return symbolTable.getRecordCount();
	}
}
