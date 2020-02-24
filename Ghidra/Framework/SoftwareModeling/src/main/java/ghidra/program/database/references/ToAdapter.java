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
import ghidra.program.database.map.AddressMap;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.Reference;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

abstract class ToAdapter implements RecordAdapter {

	static final String TO_REFS_TABLE_NAME = "TO REFS";
	static final int CURRENT_VERSION = 1;
	static final Schema TO_REFS_SCHEMA = new Schema(CURRENT_VERSION, "To Address",
		new Field[] { IntField.INSTANCE, BinaryField.INSTANCE, ByteField.INSTANCE },
		new String[] { "Number of Refs", "Ref Data", "Ref Level" });

	static final int REF_COUNT_COL = 0;
	static final int REF_DATA_COL = 1;
	static final int REF_LEVEL_COL = 2;

	static ToAdapter getAdapter(DBHandle dbHandle, int openMode, AddressMap addrMap,
			ErrorHandler errHandler, TaskMonitor monitor)
			throws VersionException, CancelledException, IOException {

		if (openMode == DBConstants.CREATE) {
			return new ToAdapterV1(dbHandle, true, addrMap, errHandler);
		}

		try {
			ToAdapter adapter = new ToAdapterV1(dbHandle, false, addrMap, errHandler);
			if (addrMap.isUpgraded()) {
				throw new VersionException(true);
			}
			return adapter;
		}
		catch (VersionException e) {
			if (!e.isUpgradable() || openMode == DBConstants.UPDATE) {
				throw e;
			}
			ToAdapter adapter = findReadOnlyAdapter(dbHandle, addrMap, errHandler);
			if (openMode == DBConstants.UPGRADE) {
				adapter = upgrade(dbHandle, adapter, addrMap, errHandler, monitor);
			}
			return adapter;
		}
	}

	private static ToAdapter findReadOnlyAdapter(DBHandle dbHandle, AddressMap addrMap,
			ErrorHandler errHandler) throws VersionException, IOException {
		try {
			return new ToAdapterV1(dbHandle, false, addrMap.getOldAddressMap(), errHandler);
		}
		catch (VersionException e) {
		}

		try {
			return new ToAdapterV0(dbHandle, addrMap, errHandler);
		}
		catch (VersionException e) {
		}

		return new ToAdapterSharedTable(dbHandle, addrMap, errHandler);
	}

	private static ToAdapter upgrade(DBHandle dbHandle, ToAdapter oldAdapter, AddressMap addrMap,
			ErrorHandler errHandler, TaskMonitor monitor)
			throws VersionException, IOException, CancelledException {

		AddressMap oldAddrMap = addrMap.getOldAddressMap();
		DBHandle tmpHandle = new DBHandle();
		try {
			tmpHandle.startTransaction();

			monitor.setMessage("Upgrading Memory References...");
			monitor.initialize(oldAdapter.getRecordCount() * 2);
			int count = 0;

			ToAdapter tmpAdapter = new ToAdapterV1(tmpHandle, true, addrMap, errHandler);
			AddressIterator addrIter = oldAdapter.getToIterator(true);
			while (addrIter.hasNext()) {
				if (monitor.isCancelled()) {
					throw new CancelledException();
				}
				Address to = addrIter.next();
				RefListV0 refList =
					(RefListV0) oldAdapter.getRefList(null, null, to, oldAddrMap.getKey(to, false));
				Reference[] refs = refList.getAllRefs();
				RefListV0 newRefList = new RefListV0(to, tmpAdapter, addrMap, null, null, false);
				newRefList.addRefs(refs);
				monitor.setProgress(++count);
			}

			dbHandle.deleteTable(TO_REFS_TABLE_NAME);
			ToAdapter newAdapter = new ToAdapterV1(dbHandle, true, addrMap, errHandler);

			addrIter = tmpAdapter.getToIterator(true);
			while (addrIter.hasNext()) {
				if (monitor.isCancelled()) {
					throw new CancelledException();
				}
				Address to = addrIter.next();
				long toAddr = addrMap.getKey(to, true);
				RefListV0 refList = (RefListV0) tmpAdapter.getRefList(null, null, to, toAddr);
				byte refLevel = -1;
				if (refList != null) {
					refLevel = refList.getReferenceLevel();
				}
				newAdapter.createRecord(toAddr, refList != null ? refList.getNumRefs() : 0,
					refLevel, refList != null ? refList.getData() : null);
				monitor.setProgress(++count);
			}
			return newAdapter;
		}
		finally {
			tmpHandle.close();
		}
	}

	abstract int getRecordCount();

	abstract RefList createRefList(ProgramDB program, DBObjectCache<RefList> cache, Address toAddr)
			throws IOException;

	abstract RefList getRefList(ProgramDB program, DBObjectCache<RefList> cache, Address to,
			long toAddr) throws IOException;

	abstract boolean hasRefTo(long toAddr) throws IOException;

	abstract AddressIterator getToIterator(boolean forward) throws IOException;

	abstract AddressIterator getToIterator(Address startAddr, boolean forward) throws IOException;

	abstract AddressIterator getToIterator(AddressSetView set, boolean forward) throws IOException;

	abstract AddressIterator getOldNamespaceAddresses(AddressSpace addrSpace) throws IOException;

	/* (non-Javadoc)
	 * @see ghidra.program.database.references.ToRecordAdapter#putRecord(long, int, byte, byte[])
	 */
	public void putRecord(long key, int numRefs, byte[] refData) {
		throw new UnsupportedOperationException();
	}

}
