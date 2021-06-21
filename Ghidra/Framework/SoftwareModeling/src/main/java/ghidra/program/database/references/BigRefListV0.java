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
 * Created on Sep 16, 2003
 *
 * To change the template for this generated file go to
 * Window&gt;Preferences&gt;Java&gt;Code Generation&gt;Code and Comments
 */
package ghidra.program.database.references;

import java.io.IOException;
import java.util.Iterator;

import db.*;
import ghidra.program.database.DBObjectCache;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.map.AddressMap;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.*;

/**
 * 
 *
 * To change the template for this generated type comment go to
 * Window&gt;Preferences&gt;Java&gt;Code Generation&gt;Code and Comments
 */
class BigRefListV0 extends RefList {

	private static final String BASE_TABLE_NAME = "BigRefList_";

	private static final Schema BIG_REFS_SCHEMA = new Schema(1, "RefID",
		new Field[] { LongField.INSTANCE, ByteField.INSTANCE, ByteField.INSTANCE,
			ByteField.INSTANCE, LongField.INSTANCE, LongField.INSTANCE },
		new String[] { "Address", "Flags", "Type", "OpIndex", "SymbolID", "Offset" });

	private static int ADDRESS_COL = 0;
	private static int FLAGS_COL = 1;
	private static int TYPE_COL = 2;
	private static int OPINDEX_COL = 3;
	private static int SYMBOL_ID_COL = 4;
	private static int OFFSET_COL = 5;

	private byte refLevel = -1;
	private Table table;
	private DBRecord record;

	/**
	 * Construct new empty reference list
	 * @param address address associated with this list
	 * @param adapter entry record storage adapter
	 * @param addrMap address map for encoding/decoding addresses
	 * @param program associated Program
	 * @param cache RefList object cache
	 * @param isFrom true for from-adapter use, false for to-adapter use
	 * @throws IOException if database IO error occurs
	 */
	BigRefListV0(Address address, RecordAdapter adapter, AddressMap addrMap, ProgramDB program,
			DBObjectCache<RefList> cache, boolean isFrom) throws IOException {
		super(addrMap.getKey(address, true), address, adapter, addrMap, program, cache, isFrom);
		record = ToAdapter.TO_REFS_SCHEMA.createRecord(key);
		table = program.getDBHandle()
				.createTable(getTableName(), BIG_REFS_SCHEMA, new int[] { ADDRESS_COL });
	}

	/**
	 * Construct reference list for existing record
	 * @param rec existing refList record
	 * @param adapter entry record storage adapter
	 * @param addrMap address map for encoding/decoding addresses
	 * @param program associated Program
	 * @param cache RefList object cache
	 * @param isFrom true for from-adapter use, false for to-adapter use
	 * @throws IOException if database IO error occurs
	 */
	BigRefListV0(DBRecord rec, RecordAdapter adapter, AddressMap addrMap, ProgramDB program,
			DBObjectCache<RefList> cache, boolean isFrom) throws IOException {
		super(rec.getKey(), addrMap.decodeAddress(rec.getKey()), adapter, addrMap, program, cache,
			isFrom);
		if (rec.getBinaryData(ToAdapter.REF_DATA_COL) != null) {
			throw new IllegalArgumentException("Invalid reference record");
		}
		table = program.getDBHandle().getTable(getTableName());
		if (table == null) {
			throw new IOException(
				"BigRefList table not found for " + address + " (" + getTableName() + ")");
		}
		if (!isFrom) {
			refLevel = rec.getByteValue(ToAdapter.REF_LEVEL_COL);
		}
		record = rec;
	}

	private String getTableName() {
		String prefix = isFrom ? "From" : "";
		return prefix + BASE_TABLE_NAME + Long.toHexString(key);
	}

	@Override
	public RefList checkRefListSize(DBObjectCache<RefList> cache, int newSpaceRequired) {
		return this;
	}

	@Override
	protected boolean refresh() {
		return false;
	}

	@Override
	void addRef(Address fromAddr, Address toAddr, RefType refType, int opIndex, long symbolID,
			boolean isPrimary, SourceType source, boolean isOffset, boolean isShift,
			long offsetOrShift) throws IOException {

		appendRef(fromAddr, toAddr, opIndex, refType, source, isPrimary, symbolID, isOffset,
			isShift, offsetOrShift);
		updateRecord();
	}

	synchronized void addRefs(ReferenceIterator refIter) throws IOException {
		while (refIter.hasNext()) {
			Reference ref = refIter.next();
			boolean isPrimary = ref.isPrimary();
			long symbolID = ref.getSymbolID();
			boolean isOffset = false;
			boolean isShifted = false;
			long offsetOrShift = 0;
			if (ref instanceof MemReferenceDB) {
				MemReferenceDB memRef = (MemReferenceDB) ref;
				isOffset = memRef.isOffset();
				isShifted = memRef.isShifted();
				offsetOrShift = memRef.getOffsetOrShift();
			}
			appendRef(ref.getFromAddress(), ref.getToAddress(), ref.getOperandIndex(),
				ref.getReferenceType(), ref.getSource(), isPrimary, symbolID, isOffset, isShifted,
				offsetOrShift);

		}
		updateRecord();
	}

	synchronized void addRefs(Reference[] refs) throws IOException {
		for (Reference ref : refs) {

			boolean isPrimary = ref.isPrimary();
			long symbolID = ref.getSymbolID();
			boolean isOffset = false;
			boolean isShifted = false;
			long offsetOrShift = 0;
			if (ref instanceof MemReferenceDB) {
				MemReferenceDB memRef = (MemReferenceDB) ref;
				isOffset = memRef.isOffset();
				isShifted = memRef.isShifted();
				offsetOrShift = memRef.getOffsetOrShift();
			}

			appendRef(ref.getFromAddress(), ref.getToAddress(), ref.getOperandIndex(),
				ref.getReferenceType(), ref.getSource(), isPrimary, symbolID, isOffset, isShifted,
				offsetOrShift);

		}
		updateRecord();
	}

	private void appendRef(Address fromAddr, Address toAddr, int opIndex, RefType refType,
			SourceType source, boolean isPrimary, long symbolID, boolean isOffset,
			boolean isShifted, long offsetOrShift) throws IOException {

		if (!isFrom) {
			byte level = getRefLevel(refType);
			if (level > refLevel) {
				refLevel = level;
			}
		}
		long id = table.getMaxKey() + 1;
		if (id < 0) {
			id = 0;
		}
		DBRecord refRec = BIG_REFS_SCHEMA.createRecord(id);
		refRec.setLongValue(ADDRESS_COL, addrMap.getKey(isFrom ? toAddr : fromAddr, true));
		RefListFlagsV0 flags =
			new RefListFlagsV0(isPrimary, isOffset, symbolID >= 0, isShifted, source);
		refRec.setByteValue(FLAGS_COL, flags.getValue());
		refRec.setByteValue(TYPE_COL, refType.getValue());
		refRec.setByteValue(OPINDEX_COL, (byte) opIndex);
		refRec.setLongValue(SYMBOL_ID_COL, symbolID);
		refRec.setLongValue(OFFSET_COL, offsetOrShift);
		table.putRecord(refRec);
	}

	private ReferenceDB getRef(DBRecord rec) {
		long symbolID = -1;
		long addr = rec.getLongValue(ADDRESS_COL);

		RefListFlagsV0 flags = new RefListFlagsV0(rec.getByteValue(FLAGS_COL));
		RefType refType = RefTypeFactory.get(rec.getByteValue(TYPE_COL));
		byte opIndex = rec.getByteValue(OPINDEX_COL);

		SourceType source = flags.getSource();

		long offsetOrShift = 0;

		if (flags.hasSymbolID()) {
			symbolID = rec.getLongValue(SYMBOL_ID_COL);
		}
		Address from = isFrom ? address : addrMap.decodeAddress(addr);
		Address to = isFrom ? addrMap.decodeAddress(addr) : address;
		if (flags.isOffsetRef() || flags.isShiftRef()) {
			offsetOrShift = rec.getLongValue(OFFSET_COL);
			if (flags.isShiftRef()) {
				return new ShiftedReferenceDB(program, from, to, refType, opIndex, source,
					flags.isPrimary(), symbolID, (int) offsetOrShift);
			}
			return new OffsetReferenceDB(program, from, to, refType, opIndex, source,
				flags.isPrimary(), symbolID, offsetOrShift);
		}
		else if (to.isExternalAddress()) {
			return new ExternalReferenceDB(program, from, to, refType, opIndex, source);
		}
		else if (from.equals(Address.EXT_FROM_ADDRESS)) {
			return new EntryPointReferenceDB(from, to, refType, opIndex, source, flags.isPrimary(),
				symbolID);
		}
		else if (to.isStackAddress()) {
			return new StackReferenceDB(program, from, to, refType, opIndex, source,
				flags.isPrimary(), symbolID);
		}
		return new MemReferenceDB(program, from, to, refType, opIndex, source, flags.isPrimary(),
			symbolID);
	}

	@Override
	synchronized Reference[] getAllRefs() throws IOException {
		Reference[] refs = new Reference[getNumRefs()];
		ReferenceIterator it = getRefs();
		for (int i = 0; i < refs.length; i++) {
			refs[i] = it.next();
		}
		return refs;
	}

	@Override
	int getNumRefs() {
		return table.getRecordCount();
	}

	@Override
	boolean hasReference(int opIndex) throws IOException {
		if (!isFrom) {
			return false;
		}
		ReferenceIterator it = getRefs();
		while (it.hasNext()) {
			Reference ref = it.next();
			if (ref.getOperandIndex() == opIndex) {
				return true;
			}
		}
		return false;
	}

	@Override
	synchronized Reference getPrimaryRef(int opIndex) throws IOException {
		if (!isFrom) {
			return null;
		}
		RecordIterator iterator = table.iterator();
		while (iterator.hasNext()) {
			DBRecord rec = iterator.next();
			if (rec.getByteValue(OPINDEX_COL) != opIndex) {
				continue;
			}
			RefListFlagsV0 flags = new RefListFlagsV0(rec.getByteValue(FLAGS_COL));
			if (flags.isPrimary()) {
				return getRef(rec);
			}
		}
		return null;
	}

	@Override
	synchronized ReferenceDB getRef(Address refAddress, int opIndex) throws IOException {
		LongField addrField = new LongField(addrMap.getKey(refAddress, false));
		for (Field id : table.findRecords(addrField, ADDRESS_COL)) {
			DBRecord rec = table.getRecord(id);
			if (rec.getByteValue(OPINDEX_COL) == (byte) opIndex) {
				return getRef(rec);
			}
		}
		return null;
	}

	@Override
	synchronized ReferenceIterator getRefs() throws IOException {
		return new RefIterator();
	}

	@Override
	boolean isEmpty() {
		return table == null || table.getRecordCount() == 0;
	}

	@Override
	byte getReferenceLevel() {
		return refLevel;
	}

	@Override
	synchronized void removeAll() throws IOException {
		table.deleteAll();
		program.getDBHandle().deleteTable(table.getName());
		table = null;
		adapter.removeRecord(key);
		refLevel = -1;
		setInvalid();
	}

	@Override
	synchronized boolean removeRef(Address deleteAddr, int opIndex) throws IOException {
		LongField addrField = new LongField(addrMap.getKey(deleteAddr, false));
		for (Field id : table.findRecords(addrField, ADDRESS_COL)) {
			DBRecord rec = table.getRecord(id);
			if (rec.getByteValue(OPINDEX_COL) == (byte) opIndex) {
				table.deleteRecord(id);
				if (table.getRecordCount() == 0) {
					removeAll();
				}
				else {
					if (!isFrom) {
						byte level = getRefLevel(RefTypeFactory.get(rec.getByteValue(TYPE_COL)));
						if (refLevel <= level) {
							// get the new highest ref level
							refLevel = findHighestRefLevel(refLevel);
						}
					}
					updateRecord();
				}
				return true;
			}
		}
		return false;
	}

	private byte findHighestRefLevel(byte currentRefLevel) throws IOException {
		byte maxLevel = (byte) -1;
		ReferenceIterator it = getRefs();
		while (it.hasNext()) {
			Reference ref = it.next();
			byte level = getRefLevel(ref.getReferenceType());
			if (maxLevel < level) {
				maxLevel = level;
			}
			if (level >= currentRefLevel) {
				return level;
			}
		}
		return maxLevel;
	}

	@Override
	synchronized boolean setPrimary(Reference ref, boolean isPrimary) throws IOException {
		int opIndex = ref.getOperandIndex();
		Address changeAddr = isFrom ? ref.getToAddress() : ref.getFromAddress();
		LongField addrField = new LongField(addrMap.getKey(changeAddr, false));
		for (Field id : table.findRecords(addrField, ADDRESS_COL)) {
			DBRecord rec = table.getRecord(id);
			if (rec.getByteValue(OPINDEX_COL) == (byte) opIndex) {
				RefListFlagsV0 flags = new RefListFlagsV0(rec.getByteValue(FLAGS_COL));
				if (flags.isPrimary() == isPrimary) {
					return false; // change not required
				}
				flags.setPrimary(isPrimary);
				rec.setByteValue(FLAGS_COL, flags.getValue());
				table.putRecord(rec);
				return true;
			}
		}
		return false;
	}

	@Override
	synchronized boolean setSymbolID(Reference ref, long symbolID) throws IOException {
		boolean hasSymbolID = symbolID >= 0;
		int opIndex = ref.getOperandIndex();
		Address changeAddr = isFrom ? ref.getToAddress() : ref.getFromAddress();
		LongField addrField = new LongField(addrMap.getKey(changeAddr, false));
		for (Field id : table.findRecords(addrField, ADDRESS_COL)) {
			DBRecord rec = table.getRecord(id);
			if (rec.getByteValue(OPINDEX_COL) == (byte) opIndex) {
				RefListFlagsV0 flags = new RefListFlagsV0(rec.getByteValue(FLAGS_COL));
				if (flags.hasSymbolID() == hasSymbolID &&
					symbolID == rec.getLongValue(SYMBOL_ID_COL)) {
					return false; // change not required
				}
				flags.setHasSymbolID(hasSymbolID);
				rec.setLongValue(SYMBOL_ID_COL, symbolID);
				table.putRecord(rec);
				return true;
			}
		}
		return false;
	}

	@Override
	synchronized void updateRefType(Address changeAddr, int opIndex, RefType refType)
			throws IOException {
		boolean updateRefLevel = false;
		byte newLevel = getRefLevel(refType);
		if (!isFrom) {
			updateRefLevel = (newLevel != refLevel);
		}
		LongField addrField = new LongField(addrMap.getKey(changeAddr, false));
		for (Field id : table.findRecords(addrField, ADDRESS_COL)) {
			DBRecord rec = table.getRecord(id);
			if (rec.getByteValue(OPINDEX_COL) == (byte) opIndex) {
				if (refType.getValue() == rec.getByteValue(TYPE_COL)) {
					return; // change not required
				}
				rec.setByteValue(TYPE_COL, refType.getValue());
				table.putRecord(rec);

				if (updateRefLevel) {
					if (newLevel > refLevel) {
						refLevel = newLevel;
					}
					else {
						refLevel = findHighestRefLevel((byte) -1);
					}
					updateRecord();
				}
				break;
			}
		}
	}

	private void updateRecord() throws IOException {
		record.setIntValue(ToAdapter.REF_COUNT_COL, table.getRecordCount());
		record.setBinaryData(ToAdapter.REF_DATA_COL, null);
		if (!isFrom) {
			record.setByteValue(ToAdapter.REF_LEVEL_COL, refLevel);
		}
		adapter.putRecord(record);
	}

	static byte getRefLevel(RefType rt) {
		if (rt == RefType.EXTERNAL_REF) {
			return (byte) SymbolUtilities.EXT_LEVEL;
		}
		if (rt.isCall()) {
			return (byte) SymbolUtilities.SUB_LEVEL;
		}
		if (rt.isData() || rt.isIndirect()) {
			return (byte) SymbolUtilities.DAT_LEVEL;
		}
		if (rt.isFlow()) {
			return (byte) SymbolUtilities.LAB_LEVEL;
		}
		return (byte) SymbolUtilities.UNK_LEVEL;
	}

	class RefIterator implements ReferenceIterator {

		private RecordIterator recIter;

		RefIterator() throws IOException {
			recIter = table.iterator();
		}

		@Override
		public boolean hasNext() {
			try {
				return recIter.hasNext();
			}
			catch (IOException e) {
				program.dbError(e);
			}
			return false;
		}

		@Override
		public Reference next() {
			try {
				if (hasNext()) {
					return getRef(recIter.next());
				}
			}
			catch (IOException e) {
				program.dbError(e);
			}
			return null;
		}

		@Override
		public void remove() {
			throw new UnsupportedOperationException();
		}

		@Override
		public Iterator<Reference> iterator() {
			return this;
		}
	}
}
