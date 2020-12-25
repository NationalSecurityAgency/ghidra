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
import ghidra.program.database.map.AddressMap;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.Reference;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

abstract class FromAdapter implements RecordAdapter {

	static final String FROM_REFS_TABLE_NAME = "FROM REFS";

	static final Schema FROM_REFS_SCHEMA =
		new Schema(0, "From Address", new Field[] { IntField.INSTANCE, BinaryField.INSTANCE },
			new String[] { "Number of Refs", "Ref Data" });

	static final int REF_COUNT_COL = 0;
	static final int REF_DATA_COL = 1;

	static FromAdapter getAdapter(DBHandle dbHandle, int openMode, AddressMap addrMap,
			ErrorHandler errHandler, TaskMonitor monitor)
			throws VersionException, CancelledException, IOException {

		if (openMode == DBConstants.CREATE) {
			return new FromAdapterV0(dbHandle, true, addrMap, errHandler);
		}

		try {
			FromAdapter adapter = new FromAdapterV0(dbHandle, false, addrMap, errHandler);
			if (addrMap.isUpgraded()) {
				throw new VersionException(true);
			}
			return adapter;
		}
		catch (VersionException e) {
			if (!e.isUpgradable() || openMode == DBConstants.UPDATE) {
				throw e;
			}
			FromAdapter adapter = findReadOnlyAdapter(dbHandle, addrMap, errHandler);
			if (openMode == DBConstants.UPGRADE) {
				adapter = upgrade(dbHandle, addrMap, adapter, errHandler, monitor);
			}
			return adapter;
		}
	}

	private static FromAdapter findReadOnlyAdapter(DBHandle dbHandle, AddressMap addrMap,
			ErrorHandler errHandler) throws VersionException, IOException {
		try {
			return new FromAdapterV0(dbHandle, false, addrMap.getOldAddressMap(), errHandler);
		}
		catch (VersionException e) {
		}

		return new FromAdapterSharedTable(dbHandle, addrMap, errHandler);
	}

	private static FromAdapter upgrade(DBHandle dbHandle, AddressMap addrMap,
			FromAdapter oldAdapter, ErrorHandler errHandler, TaskMonitor monitor)
			throws VersionException, IOException, CancelledException {

		AddressMap oldAddrMap = addrMap.getOldAddressMap();
		DBHandle tmpHandle = new DBHandle();
		try {
			tmpHandle.startTransaction();

			monitor.setMessage("Upgrading Memory References...");
			monitor.initialize(oldAdapter.getRecordCount() * 2);
			int count = 0;

			FromAdapter tmpAdapter = new FromAdapterV0(tmpHandle, true, addrMap, errHandler);
			AddressIterator addrIter = oldAdapter.getFromIterator(true);
			while (addrIter.hasNext()) {
				if (monitor.isCancelled()) {
					throw new CancelledException();
				}
				Address from = addrIter.next();
				RefListV0 refList = (RefListV0) oldAdapter.getRefList(null, null, from,
					oldAddrMap.getKey(from, false));
				Reference[] refs = refList.getAllRefs();
				RefListV0 newRefList = new RefListV0(from, tmpAdapter, addrMap, null, null, true);
				newRefList.addRefs(refs);
				monitor.setProgress(++count);
			}

			dbHandle.deleteTable(FROM_REFS_TABLE_NAME);
			FromAdapter newAdapter = new FromAdapterV0(dbHandle, true, addrMap, errHandler);

			addrIter = tmpAdapter.getFromIterator(true);
			while (addrIter.hasNext()) {
				if (monitor.isCancelled()) {
					throw new CancelledException();
				}
				Address from = addrIter.next();
				long fromAddr = addrMap.getKey(from, true);
				RefListV0 refList = (RefListV0) tmpAdapter.getRefList(null, null, from, fromAddr);
				newAdapter.createRecord(fromAddr, refList != null ? refList.getNumRefs() : 0,
					(byte) -1, refList != null ? refList.getData() : null);
				monitor.setProgress(++count);
			}
			return newAdapter;
		}
		finally {
			tmpHandle.close();
		}
	}

	abstract int getRecordCount();

	abstract RefList createRefList(ProgramDB program, DBObjectCache<RefList> cache,
			Address fromAddr) throws IOException;

	abstract RefList getRefList(ProgramDB program, DBObjectCache<RefList> cache, Address from,
			long fromAddr) throws IOException;

	abstract boolean hasRefFrom(long fromAddr) throws IOException;

	abstract AddressIterator getFromIterator(boolean forward) throws IOException;

	abstract AddressIterator getFromIterator(Address startAddr, boolean forward) throws IOException;

	abstract AddressIterator getFromIterator(AddressSetView set, boolean forward)
			throws IOException;

}
