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
package ghidra.program.database;

import java.io.IOException;
import java.util.*;

import db.*;
import ghidra.framework.data.DomainObjectDBChangeSet;
import ghidra.program.database.map.AddressMap;
import ghidra.program.database.map.NormalizedAddressSet;
import ghidra.program.database.util.SynchronizedAddressSetCollection;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.ProgramChangeSet;

/**
 * Holds changes made to a program.
 * Currently changes are summarized by an address set.
 *
 */
class ProgramDBChangeSet implements ProgramChangeSet, DomainObjectDBChangeSet {

	private static final Schema STORED_ID_SCHEMA =
		new Schema(0, "Key", new Field[] { LongField.INSTANCE }, new String[] { "value" });

	private static final Schema STORED_ADDRESS_RANGE_SCHEMA = new Schema(0, "Key",
		new Field[] { LongField.INSTANCE, LongField.INSTANCE }, new String[] { "addr1", "addr2" });

	private static final String DATATYPE_ADDITIONS = "DataType Additions";
	private static final String DATATYPE_CHANGES = "DataType Changes";
	private static final String CATEGORY_ADDITIONS = "Category Additions";
	private static final String CATEGORY_CHANGES = "Category Changes";
	private static final String PROGRAM_TREE_ADDITIONS = "Program Tree Additions";
	private static final String PROGRAM_TREE_CHANGES = "Program Tree Changes";
	private static final String ADDRESS_CHANGES = "Address Changes";
	private static final String REGISTER_ADDRESS_CHANGES = "Register Address Changes";
	private static final String SYMBOL_ADDITIONS = "Symbol Additions";
	private static final String SYMBOL_CHANGES = "Symbol Changes";
	private static final String SOURCE_ARCHIVE_ADDITIONS = "Source Archive Additions";
	private static final String SOURCE_ARCHIVE_CHANGES = "Source Archive Changes";
	private static final String FUNCTION_TAG_CHANGES = "Function Tag Changes";
	private static final String FUNCTION_TAG_ADDITIONS = "Function Tag Additions";

	// Because of use cases needed by the change bar plugin, the non-transaction
	// addressSets have been split into changesSinceCheckout, and changesSinceSave.
	// When a save occurs, the changedAddrsSinceSave is merged into changedAddrsSinceCheckout
	// In the case on non-versioned programs, the changedAddrsSinceCheckout is always empty.
	private NormalizedAddressSet changedAddrsSinceCheckout;
	private NormalizedAddressSet changedAddrsSinceSave;
	private NormalizedAddressSet changedRegAddrsSinceCheckout;
	private NormalizedAddressSet changedRegAddrsSinceSave;

	private HashSet<Long> changedDataTypeIds;
	private HashSet<Long> changedCategoryIds;
	private HashSet<Long> changedProgramTreeIds;
	private HashSet<Long> changedSymbolIds;
	private HashSet<Long> changedSourceArchiveIds;
	private HashSet<Long> changedTagIds;
	private HashSet<Long> addedDataTypeIds;
	private HashSet<Long> addedCategoryIds;
	private HashSet<Long> addedProgramTreeIds;
	private HashSet<Long> addedSymbolIds;
	private HashSet<Long> addedSourceArchiveIds;
	private HashSet<Long> addedTagIds;

	// These keep track of changes during a transaction
	private NormalizedAddressSet tmpAddrs;
	private NormalizedAddressSet tmpRegAddrs;
	private HashSet<Long> tmpChangedDataTypeIds;
	private HashSet<Long> tmpChangedCategoryIds;
	private HashSet<Long> tmpChangedProgramTreeIds;
	private HashSet<Long> tmpChangedSymbolIds;
	private HashSet<Long> tmpChangedSourceArchiveIds;
	private HashSet<Long> tmpChangedTagIds;
	private HashSet<Long> tmpAddedDataTypeIds;
	private HashSet<Long> tmpAddedCategoryIds;
	private HashSet<Long> tmpAddedProgramTreeIds;
	private HashSet<Long> tmpAddedSymbolIds;
	private HashSet<Long> tmpAddedSourceArchiveIds;
	private HashSet<Long> tmpAddedTagIds;

	private LinkedList<ChangeDiff> undoList = new LinkedList<ChangeDiff>();
	private LinkedList<ChangeDiff> redoList = new LinkedList<ChangeDiff>();

	private boolean inTransaction;
	private int numUndos = 4;

	private AddressMap addrMap;

	/**
	 * Construct a new ProgramChangeSet.
	 * @param addrMap the address map.
	 * @param numUndos the number of undo change sets to track.
	 */
	public ProgramDBChangeSet(AddressMap addrMap, int numUndos) {
		this.addrMap = addrMap;
		this.numUndos = numUndos;
		changedAddrsSinceCheckout = new NormalizedAddressSet(addrMap);
		changedRegAddrsSinceCheckout = new NormalizedAddressSet(addrMap);
		changedAddrsSinceSave = new NormalizedAddressSet(addrMap);
		changedRegAddrsSinceSave = new NormalizedAddressSet(addrMap);
		changedDataTypeIds = new HashSet<Long>();
		changedCategoryIds = new HashSet<Long>();
		changedProgramTreeIds = new HashSet<Long>();
		changedSymbolIds = new HashSet<Long>();
		changedSourceArchiveIds = new HashSet<Long>();
		changedTagIds = new HashSet<Long>();
		addedDataTypeIds = new HashSet<Long>();
		addedCategoryIds = new HashSet<Long>();
		addedProgramTreeIds = new HashSet<Long>();
		addedSymbolIds = new HashSet<Long>();
		addedSourceArchiveIds = new HashSet<Long>();
		addedTagIds = new HashSet<Long>();
	}

	@Override
	public synchronized AddressSetView getAddressSet() {
		SynchronizedAddressSetCollection addressSetCollection =
			new SynchronizedAddressSetCollection(this, changedAddrsSinceCheckout,
				changedAddrsSinceSave, tmpAddrs);
		return addressSetCollection.getCombinedAddressSet();
	}

	@Override
	public synchronized AddressSetCollection getAddressSetCollectionSinceLastSave() {
		return new SynchronizedAddressSetCollection(this, changedAddrsSinceSave, tmpAddrs);
	}

	@Override
	public synchronized AddressSetCollection getAddressSetCollectionSinceCheckout() {
		return new SynchronizedAddressSetCollection(this, changedAddrsSinceCheckout,
			changedAddrsSinceSave);

	}

	@Override
	public synchronized void add(AddressSetView addrSet) {
		if (!inTransaction) {
			throw new IllegalStateException("Not in a transaction");
		}
		tmpAddrs.add(addrSet);
	}

	@Override
	public synchronized void addRange(Address addr1, Address addr2) {
		if (!inTransaction) {
			throw new IllegalStateException("Not in a transaction");
		}
		if (addr1.isMemoryAddress() || addr1.isExternalAddress()) {
			tmpAddrs.addRange(addr1, addr2);
		}
	}

	@Override
	public synchronized void addRegisterRange(Address addr1, Address addr2) {
		if (!inTransaction) {
			throw new IllegalStateException("Not in a transaction");
		}
		tmpRegAddrs.addRange(addr1, addr2);
	}

	@Override
	public synchronized AddressSetView getRegisterAddressSet() {
		SynchronizedAddressSetCollection addressSetCollection =
			new SynchronizedAddressSetCollection(this, changedRegAddrsSinceCheckout,
				changedRegAddrsSinceSave, tmpRegAddrs);
		return addressSetCollection.getCombinedAddressSet();
	}

	@Override
	public synchronized void dataTypeChanged(long id) {
		if (!inTransaction) {
			throw new IllegalStateException("Not in a transaction");
		}
		Long lid = new Long(id);
		if (!addedDataTypeIds.contains(lid) && !tmpAddedDataTypeIds.contains(lid)) {
			tmpChangedDataTypeIds.add(lid);
		}
	}

	@Override
	public synchronized void dataTypeAdded(long id) {
		if (!inTransaction) {
			throw new IllegalStateException("Not in a transaction");
		}
		tmpAddedDataTypeIds.add(new Long(id));
	}

	@Override
	public synchronized long[] getDataTypeChanges() {
		return getLongs(changedDataTypeIds);
	}

	@Override
	public synchronized long[] getDataTypeAdditions() {
		return getLongs(addedDataTypeIds);
	}

	@Override
	public synchronized void categoryChanged(long id) {
		if (!inTransaction) {
			throw new IllegalStateException("Not in a transaction");
		}
		Long lid = new Long(id);
		if (!addedCategoryIds.contains(lid) && !tmpAddedCategoryIds.contains(lid)) {
			tmpChangedCategoryIds.add(lid);
		}
	}

	@Override
	public synchronized void categoryAdded(long id) {
		if (!inTransaction) {
			throw new IllegalStateException("Not in a transaction");
		}
		tmpAddedCategoryIds.add(new Long(id));
	}

	@Override
	public synchronized long[] getCategoryChanges() {
		return getLongs(changedCategoryIds);
	}

	@Override
	public synchronized long[] getCategoryAdditions() {
		return getLongs(addedCategoryIds);
	}

	@Override
	public synchronized void programTreeChanged(long id) {
		if (!inTransaction) {
			throw new IllegalStateException("Not in a transaction");
		}
		Long lid = new Long(id);
		if (!addedProgramTreeIds.contains(lid) && !tmpAddedProgramTreeIds.contains(lid)) {
			tmpChangedProgramTreeIds.add(lid);
		}
	}

	@Override
	public synchronized void programTreeAdded(long id) {
		if (!inTransaction) {
			throw new IllegalStateException("Not in a transaction");
		}
		tmpAddedProgramTreeIds.add(new Long(id));
	}

	@Override
	public synchronized long[] getProgramTreeChanges() {
		return getLongs(changedProgramTreeIds);
	}

	@Override
	public synchronized long[] getProgramTreeAdditions() {
		return getLongs(addedProgramTreeIds);
	}

	@Override
	public synchronized void symbolChanged(long id) {
		if (!inTransaction) {
			throw new IllegalStateException("Not in a transaction");
		}
		Long lid = new Long(id);
		if (!addedSymbolIds.contains(lid) && !tmpAddedSymbolIds.contains(lid)) {
			tmpChangedSymbolIds.add(lid);
		}
	}

	@Override
	public synchronized void symbolAdded(long id) {
		if (!inTransaction) {
			throw new IllegalStateException("Not in a transaction");
		}
		tmpAddedSymbolIds.add(new Long(id));
	}

	@Override
	public synchronized long[] getSymbolChanges() {
		return getLongs(changedSymbolIds);
	}

	@Override
	public synchronized long[] getSymbolAdditions() {
		return getLongs(addedSymbolIds);
	}

	@Override
	public synchronized void tagChanged(long id) {
		if (!inTransaction) {
			throw new IllegalStateException("Not in a transaction");
		}
		Long lid = new Long(id);
		if (!changedTagIds.contains(lid) && !tmpChangedTagIds.contains(lid)) {
			tmpChangedTagIds.add(lid);
		}
	}

	@Override
	public synchronized void tagCreated(long id) {
		if (!inTransaction) {
			throw new IllegalStateException("Not in a transaction");
		}
		tmpAddedTagIds.add(new Long(id));
	}

	@Override
	public synchronized long[] getTagChanges() {
		return getLongs(changedTagIds);
	}

	@Override
	public synchronized long[] getTagCreations() {
		return getLongs(addedTagIds);
	}

	@Override
	public void sourceArchiveAdded(long id) {
		if (!inTransaction) {
			throw new IllegalStateException("Not in a transaction");
		}
		tmpAddedSourceArchiveIds.add(new Long(id));
	}

	@Override
	public void sourceArchiveChanged(long id) {
		if (!inTransaction) {
			throw new IllegalStateException("Not in a transaction");
		}
		Long lid = new Long(id);
		if (!addedSourceArchiveIds.contains(lid) && !tmpAddedSourceArchiveIds.contains(lid)) {
			tmpChangedSourceArchiveIds.add(lid);
		}
	}

	@Override
	public long[] getSourceArchiveAdditions() {
		return getLongs(addedSourceArchiveIds);
	}

	@Override
	public long[] getSourceArchiveChanges() {
		return getLongs(changedSourceArchiveIds);
	}

	@Override
	public synchronized void clearUndo(boolean isCheckedOut) {
		if (inTransaction) {
			throw new IllegalStateException("Cannot clear in a transaction");
		}

		if (!isCheckedOut) { // if not versioned, wipe out change sets
			changedAddrsSinceCheckout.clear();
			changedRegAddrsSinceCheckout.clear();
			changedAddrsSinceSave.clear();
			changedRegAddrsSinceSave.clear();
			changedCategoryIds.clear();
			changedDataTypeIds.clear();
			changedProgramTreeIds.clear();
			changedSymbolIds.clear();
			changedSourceArchiveIds.clear();
			addedCategoryIds.clear();
			addedDataTypeIds.clear();
			addedProgramTreeIds.clear();
			addedSymbolIds.clear();
			addedSourceArchiveIds.clear();
		}

		clearUndo();
	}

	@Override
	public synchronized void startTransaction() {
		inTransaction = true;

		tmpAddrs = new NormalizedAddressSet(addrMap);
		tmpRegAddrs = new NormalizedAddressSet(addrMap);
		tmpChangedDataTypeIds = new HashSet<Long>();
		tmpChangedCategoryIds = new HashSet<Long>();
		tmpChangedProgramTreeIds = new HashSet<Long>();
		tmpChangedSymbolIds = new HashSet<Long>();
		tmpChangedSourceArchiveIds = new HashSet<Long>();
		tmpChangedTagIds = new HashSet<Long>();
		tmpAddedDataTypeIds = new HashSet<Long>();
		tmpAddedCategoryIds = new HashSet<Long>();
		tmpAddedProgramTreeIds = new HashSet<Long>();
		tmpAddedSymbolIds = new HashSet<Long>();
		tmpAddedSourceArchiveIds = new HashSet<Long>();
		tmpAddedTagIds = new HashSet<Long>();
	}

	@Override
	public synchronized void endTransaction(boolean commit) {
		if (!inTransaction) {
			return;
		}
		inTransaction = false;
		if (commit) {
			redoList.clear();

			tmpAddrs.delete(changedAddrsSinceSave);
			tmpRegAddrs.delete(changedRegAddrsSinceSave);
			tmpChangedDataTypeIds.removeAll(changedDataTypeIds);
			tmpChangedCategoryIds.removeAll(changedCategoryIds);
			tmpChangedProgramTreeIds.removeAll(changedProgramTreeIds);
			tmpChangedSymbolIds.removeAll(changedSymbolIds);
			tmpChangedSourceArchiveIds.removeAll(changedSourceArchiveIds);
			tmpChangedTagIds.removeAll(changedTagIds);

			changedAddrsSinceSave.add(tmpAddrs);
			changedRegAddrsSinceSave.add(tmpRegAddrs);
			changedDataTypeIds.addAll(tmpChangedDataTypeIds);
			changedCategoryIds.addAll(tmpChangedCategoryIds);
			changedProgramTreeIds.addAll(tmpChangedProgramTreeIds);
			changedSymbolIds.addAll(tmpChangedSymbolIds);
			changedSourceArchiveIds.addAll(tmpChangedSourceArchiveIds);
			changedTagIds.addAll(tmpChangedTagIds);
			addedDataTypeIds.addAll(tmpAddedDataTypeIds);
			addedCategoryIds.addAll(tmpAddedCategoryIds);
			addedProgramTreeIds.addAll(tmpAddedProgramTreeIds);
			addedSymbolIds.addAll(tmpAddedSymbolIds);
			addedSourceArchiveIds.addAll(tmpAddedSourceArchiveIds);
			addedTagIds.addAll(tmpAddedTagIds);

			undoList.addLast(new ChangeDiff(tmpAddrs, tmpRegAddrs, tmpChangedDataTypeIds,
				tmpChangedCategoryIds, tmpChangedProgramTreeIds, tmpChangedSymbolIds,
				tmpChangedSourceArchiveIds, tmpChangedTagIds, tmpAddedDataTypeIds,
				tmpAddedCategoryIds, tmpAddedProgramTreeIds, tmpAddedSymbolIds,
				tmpAddedSourceArchiveIds, tmpAddedTagIds));

			if (undoList.size() > numUndos) {
				undoList.removeFirst();
			}
		}

		tmpAddrs = null;
		tmpRegAddrs = null;
		tmpChangedDataTypeIds = null;
		tmpChangedCategoryIds = null;
		tmpChangedProgramTreeIds = null;
		tmpChangedSymbolIds = null;
		tmpChangedSourceArchiveIds = null;
		tmpChangedTagIds = null;
		tmpAddedDataTypeIds = null;
		tmpAddedCategoryIds = null;
		tmpAddedProgramTreeIds = null;
		tmpAddedSymbolIds = null;
		tmpAddedSourceArchiveIds = null;
		tmpAddedTagIds = null;
	}

	@Override
	public synchronized void undo() {
		ChangeDiff diff = undoList.removeLast();
		changedAddrsSinceSave.delete(diff.set);
		changedRegAddrsSinceSave.delete(diff.regSet);
		changedDataTypeIds.removeAll(diff.changedDts);
		changedCategoryIds.removeAll(diff.changedCats);
		changedProgramTreeIds.removeAll(diff.changedPts);
		changedSymbolIds.removeAll(diff.changedSyms);
		changedSourceArchiveIds.removeAll(diff.changedArchives);
		changedTagIds.removeAll(diff.changedTags);
		addedDataTypeIds.removeAll(diff.addedDts);
		addedCategoryIds.removeAll(diff.addedCats);
		addedProgramTreeIds.removeAll(diff.addedPts);
		addedSymbolIds.removeAll(diff.addedSyms);
		addedSourceArchiveIds.removeAll(diff.addedArchives);
		addedTagIds.removeAll(diff.addedTags);
		redoList.addLast(diff);
	}

	@Override
	public synchronized void redo() {
		ChangeDiff diff = redoList.removeLast();
		changedAddrsSinceSave.add(diff.set);
		changedRegAddrsSinceSave.add(diff.regSet);
		changedDataTypeIds.addAll(diff.changedDts);
		changedCategoryIds.addAll(diff.changedCats);
		changedProgramTreeIds.addAll(diff.changedPts);
		changedSymbolIds.addAll(diff.changedSyms);
		changedSourceArchiveIds.addAll(diff.changedArchives);
		changedTagIds.addAll(diff.changedTags);
		addedDataTypeIds.addAll(diff.addedDts);
		addedCategoryIds.addAll(diff.addedCats);
		addedProgramTreeIds.addAll(diff.addedPts);
		addedSymbolIds.addAll(diff.addedSyms);
		addedSourceArchiveIds.addAll(diff.addedArchives);
		addedTagIds.addAll(diff.addedTags);
		undoList.addLast(diff);
	}

	@Override
	public synchronized void clearUndo() {
		undoList.clear();
		redoList.clear();
	}

	@Override
	public synchronized void setMaxUndos(int numUndos) {
		this.numUndos = numUndos;
	}

	@Override
	public synchronized void read(DBHandle dbh) throws IOException {

		readIdRecords(dbh, DATATYPE_ADDITIONS, addedDataTypeIds);
		readIdRecords(dbh, DATATYPE_CHANGES, changedDataTypeIds);
		readIdRecords(dbh, CATEGORY_ADDITIONS, addedCategoryIds);
		readIdRecords(dbh, CATEGORY_CHANGES, changedCategoryIds);
		readIdRecords(dbh, PROGRAM_TREE_ADDITIONS, addedProgramTreeIds);
		readIdRecords(dbh, PROGRAM_TREE_CHANGES, changedProgramTreeIds);
		readIdRecords(dbh, SYMBOL_ADDITIONS, addedSymbolIds);
		readIdRecords(dbh, SYMBOL_CHANGES, changedSymbolIds);
		readIdRecords(dbh, SOURCE_ARCHIVE_ADDITIONS, addedSourceArchiveIds);
		readIdRecords(dbh, SOURCE_ARCHIVE_CHANGES, changedSourceArchiveIds);
		readIdRecords(dbh, FUNCTION_TAG_ADDITIONS, addedTagIds);
		readIdRecords(dbh, FUNCTION_TAG_CHANGES, changedTagIds);

		// we want to read address change records directly into the "since checkout" set.
		readAddressRangeRecords(dbh, ADDRESS_CHANGES, changedAddrsSinceCheckout);
		readAddressRangeRecords(dbh, REGISTER_ADDRESS_CHANGES, changedRegAddrsSinceCheckout);

		clearUndo();
	}

	private void readIdRecords(DBHandle dbh, String tableName, Set<Long> ids) throws IOException {
		Table table = dbh.getTable(tableName);
		if (table != null) {
			if (table.getSchema().getVersion() != 0) {
				throw new IOException("Change data produced with newer version of Ghidra");
			}
			RecordIterator it = table.iterator();
			while (it.hasNext()) {
				DBRecord rec = it.next();
				ids.add(rec.getLongValue(0));
			}
		}
	}

	private void readAddressRangeRecords(DBHandle dbh, String tableName, NormalizedAddressSet set)
			throws IOException {
		Table table = dbh.getTable(tableName);
		if (table != null) {
			if (table.getSchema().getVersion() != 0) {
				throw new IOException("Change data produced with newer version of Ghidra");
			}
			RecordIterator it = table.iterator();
			while (it.hasNext()) {
				DBRecord rec = it.next();
				Address addr1 = addrMap.decodeAddress(rec.getLongValue(0));
				Address addr2 = addrMap.decodeAddress(rec.getLongValue(1));
				// Memory addresses or external addresses are the only ones that should be in here.
				if (addr1.isMemoryAddress() || addr1.isExternalAddress()) {
					set.addRange(addr1, addr2);
				}
			}
		}
	}

	@Override
	public synchronized void write(DBHandle dbh, boolean isRecoverySave) throws IOException {

		// we are in a save, first move changes since last save into since last checkout set.
		changedAddrsSinceCheckout.add(changedAddrsSinceSave);
		changedRegAddrsSinceCheckout.add(changedRegAddrsSinceSave);

		// when the user saves a program clear out these sets. (They are saved just above in the "since checkout" sets.)
		if (!isRecoverySave) {
			changedAddrsSinceSave.clear();
			changedRegAddrsSinceSave.clear();
		}

		long txId = dbh.startTransaction();
		boolean success = false;
		try {

			writeIdRecords(dbh, DATATYPE_ADDITIONS, addedDataTypeIds);
			writeIdRecords(dbh, DATATYPE_CHANGES, changedDataTypeIds);
			writeIdRecords(dbh, CATEGORY_ADDITIONS, addedCategoryIds);
			writeIdRecords(dbh, CATEGORY_CHANGES, changedCategoryIds);
			writeIdRecords(dbh, PROGRAM_TREE_ADDITIONS, addedProgramTreeIds);
			writeIdRecords(dbh, PROGRAM_TREE_CHANGES, changedProgramTreeIds);
			writeIdRecords(dbh, SYMBOL_ADDITIONS, addedSymbolIds);
			writeIdRecords(dbh, SYMBOL_CHANGES, changedSymbolIds);
			writeIdRecords(dbh, SOURCE_ARCHIVE_ADDITIONS, addedSourceArchiveIds);
			writeIdRecords(dbh, SOURCE_ARCHIVE_CHANGES, changedSourceArchiveIds);
			writeIdRecords(dbh, FUNCTION_TAG_ADDITIONS, addedTagIds);
			writeIdRecords(dbh, FUNCTION_TAG_CHANGES, changedTagIds);

			writeAddressRangeRecords(dbh, ADDRESS_CHANGES, changedAddrsSinceCheckout);
			writeAddressRangeRecords(dbh, REGISTER_ADDRESS_CHANGES, changedRegAddrsSinceCheckout);

			success = true;
		}
		finally {
			dbh.endTransaction(txId, success);
		}
	}

	private void writeIdRecords(DBHandle dbh, String tableName, Set<Long> ids) throws IOException {
		if (ids.size() > 0) {
			Table table = dbh.createTable(tableName, STORED_ID_SCHEMA);
			DBRecord rec = STORED_ID_SCHEMA.createRecord(0);
			int key = 1;
			for (long id : ids) {
				rec.setKey(key++);
				rec.setLongValue(0, id);
				table.putRecord(rec);
			}
		}
	}

	private void writeAddressRangeRecords(DBHandle dbh, String tableName, AddressSetView set)
			throws IOException {
		if (!set.isEmpty()) {
			Table table = dbh.createTable(tableName, STORED_ADDRESS_RANGE_SCHEMA);
			DBRecord rec = STORED_ADDRESS_RANGE_SCHEMA.createRecord(0);
			int key = 1;
			for (KeyRange range : addrMap.getKeyRanges(set, false, false)) {
				rec.setKey(key++);
				rec.setLongValue(0, range.minKey);
				rec.setLongValue(1, range.maxKey);
				table.putRecord(rec);
			}
		}
	}

	private long[] getLongs(HashSet<Long> set) {
		long[] result = new long[set.size()];
		Iterator<Long> it = set.iterator();
		int i = 0;
		while (it.hasNext()) {
			result[i++] = it.next().longValue();
		}
		return result;
	}

	@Override
	public boolean hasChanges() {
		if (changedAddrsSinceSave.isEmpty() && changedRegAddrsSinceSave.isEmpty() &&
			changedDataTypeIds.isEmpty() && changedCategoryIds.isEmpty() &&
			changedProgramTreeIds.isEmpty() && changedSymbolIds.isEmpty() &&
			changedSourceArchiveIds.isEmpty() && changedTagIds.isEmpty() &&
			addedDataTypeIds.isEmpty() && addedCategoryIds.isEmpty() &&
			addedProgramTreeIds.isEmpty() && addedSymbolIds.isEmpty() &&
			addedSourceArchiveIds.isEmpty() && addedTagIds.isEmpty()) {
			return false;
		}
		return true;
	}
}

class ChangeDiff {
	NormalizedAddressSet set;
	NormalizedAddressSet regSet;
	HashSet<Long> changedDts;
	HashSet<Long> changedCats;
	HashSet<Long> changedPts;
	HashSet<Long> changedSyms;
	HashSet<Long> changedArchives;
	HashSet<Long> changedTags;
	HashSet<Long> addedDts;
	HashSet<Long> addedCats;
	HashSet<Long> addedPts;
	HashSet<Long> addedSyms;
	HashSet<Long> addedArchives;
	HashSet<Long> addedTags;

	ChangeDiff(NormalizedAddressSet set, NormalizedAddressSet regSet, HashSet<Long> changedDts,
			HashSet<Long> changedCats, HashSet<Long> changedPts, HashSet<Long> changedSyms,
			HashSet<Long> changedArchives, HashSet<Long> changedTags, HashSet<Long> addedDts,
			HashSet<Long> addedCats, HashSet<Long> addedPts, HashSet<Long> addedSyms,
			HashSet<Long> addedArchives, HashSet<Long> addedTags) {
		this.set = set;
		this.regSet = regSet;
		this.changedDts = changedDts;
		this.changedCats = changedCats;
		this.changedPts = changedPts;
		this.changedSyms = changedSyms;
		this.changedArchives = changedArchives;
		this.changedTags = changedTags;
		this.addedDts = addedDts;
		this.addedCats = addedCats;
		this.addedPts = addedPts;
		this.addedSyms = addedSyms;
		this.addedArchives = addedArchives;
		this.addedTags = addedTags;
	}
}
