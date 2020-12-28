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

import db.DBRecord;
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
class RefListV0 extends RefList {

	private static final byte[] EMPTY_DATA = new byte[0];
	private static final int BASE_REF_SIZE = 11;
	private static final int OFFSET_SIZE = 8;
	private static final int SYMBOL_ID_SIZE = 8;

	private int numRefs;
	private byte refLevel = -1;
	private byte[] refData;
	private DBRecord record;

	/**
	 * Construct new temporary empty reference list
	 * @param key address key corresponding to the address parameter
	 * @param adapter entry record storage adapter (may be null to prevent database update)
	 * @param addrMap address map for encoding/decoding addresses
	 * @param program may be null for upgrade in which 
	 * 		case resulting reference objects are not suitable for general use.
	 * @param cache RefList object cache
	 * @param isFrom true for from-adapter use, false for to-adapter use
	 */
	RefListV0(long addrKey, AddressMap addrMap, ProgramDB program, DBObjectCache<RefList> cache,
			boolean isFrom) {
		super(addrKey, addrMap.decodeAddress(addrKey), null, addrMap, program, cache, isFrom);
		this.refData = EMPTY_DATA;
		numRefs = 0;
		if (adapter != null) {
			record = ToAdapter.TO_REFS_SCHEMA.createRecord(key);
			record.setByteValue(ToAdapter.REF_LEVEL_COL, (byte) -1);
		}
	}

	/**
	 * Construct new empty reference list
	 * @param address address associated with this list (a new key will be generated if required)
	 * @param adapter entry record storage adapter (may be null to prevent database update)
	 * @param addrMap address map for encoding/decoding addresses
	 * @param program may be null for upgrade in which 
	 * 		case resulting reference objects are not suitable for general use.
	 * @param cache RefList object cache
	 * @param isFrom true for from-adapter use, false for to-adapter use
	 */
	RefListV0(Address address, RecordAdapter adapter, AddressMap addrMap, ProgramDB program,
			DBObjectCache<RefList> cache, boolean isFrom) {
		super(addrMap.getKey(address, true), address, adapter, addrMap, program, cache, isFrom);
		this.refData = EMPTY_DATA;
		numRefs = 0;
		if (adapter != null) {
			record = ToAdapter.TO_REFS_SCHEMA.createRecord(key);
			record.setByteValue(ToAdapter.REF_LEVEL_COL, (byte) -1);
		}
	}

	/**
	 * Construct reference list for existing record
	 * @param rec existing refList record
	 * @param adapter entry record storage adapter
	 * @param addrMap address map for encoding/decoding addresses
	 * @param program may be null for upgrade in which 
	 * 		case resulting reference objects are not suitable for general use.
	 * @param cache RefList object cache
	 * @param isFrom true for from-adapter use, false for to-adapter use
	 */
	RefListV0(DBRecord rec, RecordAdapter adapter, AddressMap addrMap, ProgramDB program,
			DBObjectCache<RefList> cache, boolean isFrom) {
		super(rec.getKey(), addrMap.decodeAddress(rec.getKey()), adapter, addrMap, program, cache,
			isFrom);
		refData = rec.getBinaryData(ToAdapter.REF_DATA_COL);
		numRefs = rec.getIntValue(ToAdapter.REF_COUNT_COL);
		if (!isFrom) {
			refLevel = rec.getByteValue(ToAdapter.REF_LEVEL_COL);
		}
		record = rec;
	}

	@Override
	protected boolean refresh() {
		return false;
	}

	// TODO: Try to elliminate - this is a little kludgey!
	byte[] getData() {
		return refData;
	}

	/* (non-Javadoc)
	 * @see ghidra.program.database.references.RefList#addRef(ghidra.program.model.address.Address, ghidra.program.model.address.Address, ghidra.program.model.symbol.RefType, boolean, int, long, boolean)
	 */
	@Override
	void addRef(Address fromAddr, Address toAddr, RefType refType, int opIndex, long symbolID,
			boolean isPrimary, SourceType source, boolean isOffset, boolean isShift,
			long offsetOrShift) throws IOException {

		appendRef(fromAddr, toAddr, opIndex, refType, source, isPrimary, symbolID, isOffset,
			isShift, offsetOrShift);
		updateRecord();
	}

	synchronized void addRefs(Reference[] refs) throws IOException {
		for (int i = 0; i < refs.length; i++) {

			boolean isPrimary = refs[i].isPrimary();
			long symbolID = refs[i].getSymbolID();
			boolean isOffset = false;
			boolean isShifted = false;
			long offsetOrShift = 0;
			if (refs[i].isMemoryReference()) {
				MemReferenceDB memRef = (MemReferenceDB) refs[i];
				isOffset = memRef.isOffset();
				isShifted = memRef.isShifted();
				offsetOrShift = memRef.getOffsetOrShift();
			}

			appendRef(refs[i].getFromAddress(), refs[i].getToAddress(), refs[i].getOperandIndex(),
				refs[i].getReferenceType(), refs[i].getSource(), isPrimary, symbolID, isOffset,
				isShifted, offsetOrShift);

		}
		updateRecord();
	}

	private void appendRef(Address fromAddr, Address toAddr, int opIndex, RefType refType,
			SourceType source, boolean isPrimary, long symbolID, boolean isOffset,
			boolean isShifted, long offsetOrShift) {

		if (!isFrom) {
			byte level = getRefLevel(refType);
			if (level > refLevel) {
				refLevel = level;
			}
		}

		byte[] bytes =
			encode(fromAddr, toAddr, refType, source, opIndex, symbolID, isPrimary, isOffset,
				isShifted, offsetOrShift);

		byte[] newData = new byte[refData.length + bytes.length];
		System.arraycopy(refData, 0, newData, 0, refData.length);
		System.arraycopy(bytes, 0, newData, refData.length, bytes.length);
		refData = newData;
		numRefs++;
	}

	/* (non-Javadoc)
	 * @see ghidra.program.database.references.RefList#getAllRefs()
	 */
	@Override
	synchronized Reference[] getAllRefs() {
		Reference[] refs = new Reference[numRefs];
		ReferenceIterator it = getRefs();
		for (int i = 0; i < numRefs; i++) {
			refs[i] = it.next();
		}
		return refs;
	}

	/* (non-Javadoc)
	 * @see ghidra.program.database.references.RefList#getNumRefs()
	 */
	@Override
	int getNumRefs() {
		return numRefs;
	}

	/*
	 * @see ghidra.program.database.references.RefList#hasReference(int)
	 */
	@Override
	boolean hasReference(int opIndex) {
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

	/* (non-Javadoc)
	 * @see ghidra.program.database.references.RefList#getPrimaryRef()
	 */
	@Override
	synchronized Reference getPrimaryRef(int opIndex) {
		if (!isFrom) {
			return null;
		}
		ReferenceIterator it = getRefs();
		while (it.hasNext()) {
			Reference ref = it.next();
			if (ref.isPrimary() && ref.getOperandIndex() == opIndex) {
				return ref;
			}
		}
		return null;
	}

	/* (non-Javadoc)
	 * @see ghidra.program.database.references.RefList#getRef(ghidra.program.model.address.Address, int)
	 */
	@Override
	synchronized ReferenceDB getRef(Address refAddress, int opIndex) {
		ReferenceIterator it = getRefs();
		while (it.hasNext()) {
			Reference ref = it.next();
			if (ref.getOperandIndex() == opIndex) {
				Address addr = isFrom ? ref.getToAddress() : ref.getFromAddress();
				if (refAddress.equals(addr)) {
					return (ReferenceDB) ref;
				}
			}
		}
		return null;

	}

	/* (non-Javadoc)
	 * @see ghidra.program.database.references.RefList#getRefs()
	 */
	@Override
	synchronized ReferenceIterator getRefs() {
		return new RefIterator();
	}

	/* (non-Javadoc)
	 * @see ghidra.program.database.references.RefList#isEmpty()
	 */
	@Override
	boolean isEmpty() {
		return numRefs == 0;
	}

	@Override
	byte getReferenceLevel() {
		return refLevel;
	}

	/* (non-Javadoc)
	 * @see ghidra.program.database.references.RefList#removeAll()
	 */
	@Override
	synchronized void removeAll() throws IOException {
		numRefs = 0;
		refData = EMPTY_DATA;
		if (adapter != null) {
			adapter.removeRecord(key);
		}
	}

	/* (non-Javadoc)
	 * @see ghidra.program.database.references.RefList#removeRef(ghidra.program.model.symbol.MemReference)
	 */
	@Override
	synchronized boolean removeRef(Address deleteAddr, int opIndex) throws IOException {
		ReferenceDB[] result = new ReferenceDB[1];
		int pos = 0;
		int newPos = 0;
		for (int i = 0; i < numRefs; i++) {
			newPos = decode(refData, pos, result);
			if (result[0].getOperandIndex() == opIndex) {
				Address addr = isFrom ? result[0].getToAddress() : result[0].getFromAddress();
				if (deleteAddr.equals(addr)) {
					byte[] newData = new byte[refData.length - (newPos - pos)];
					System.arraycopy(refData, 0, newData, 0, pos);
					System.arraycopy(refData, newPos, newData, pos, newData.length - pos);
					numRefs--;
					if (numRefs == 0) {
						refData = EMPTY_DATA;
						if (adapter != null) {
							adapter.removeRecord(key);
						}
						setInvalid();
					}
					else {
						refData = newData;
						if (!isFrom) {
							byte level = getRefLevel(result[0].getReferenceType());
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
			pos = newPos;
		}
		return false;
	}

	private byte findHighestRefLevel(byte currentRefLevel) {
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

	/* (non-Javadoc)
	 * @see ghidra.program.database.references.RefList#setPrimary(ghidra.program.model.symbol.MemReference, boolean)
	 */
	@Override
	synchronized boolean setPrimary(Reference ref, boolean isPrimary) throws IOException {
		int opIndex = ref.getOperandIndex();
		Address changeAddr = isFrom ? ref.getToAddress() : ref.getFromAddress();

		Reference[] result = new Reference[1];
		int pos = 0;
		int newPos = 0;
		for (int i = 0; i < numRefs; i++) {
			newPos = decode(refData, pos, result);
			Reference r = result[0];
			if (r.getOperandIndex() == opIndex) {
				Address addr = isFrom ? r.getToAddress() : r.getFromAddress();
				if (changeAddr.equals(addr)) {
					if (isPrimary == r.isPrimary()) {
						return false; // change not required
					}
					boolean isOffset = false;
					boolean isShifted = false;
					long offsetOrShift = 0;
					if (r.isMemoryReference()) {
						isOffset = ((MemReferenceDB) r).isOffset();
						isShifted = ((MemReferenceDB) r).isShifted();
						offsetOrShift = ((MemReferenceDB) r).getOffsetOrShift();
					}

					byte[] bytes =
						encode(r.getFromAddress(), r.getToAddress(), r.getReferenceType(),
							r.getSource(), r.getOperandIndex(), r.getSymbolID(), isPrimary,
							isOffset, isShifted, offsetOrShift);

					System.arraycopy(bytes, 0, refData, pos, bytes.length);
					updateRecord();
					return true;
				}
			}
			pos = newPos;
		}
		return false;
	}

	/* (non-Javadoc)
	 * @see ghidra.program.database.references.RefList#setSymbolID(ghidra.program.model.symbol.MemReference, long)
	 */
	@Override
	synchronized boolean setSymbolID(Reference ref, long symbolID) throws IOException {
		int opIndex = ref.getOperandIndex();
		Address changeAddr = isFrom ? ref.getToAddress() : ref.getFromAddress();

		Reference[] result = new Reference[1];
		int pos = 0;
		int newPos = 0;
		for (int i = 0; i < numRefs; i++) {
			newPos = decode(refData, pos, result);
			Reference r = result[0];
			if (r.getOperandIndex() == opIndex) {
				Address addr = isFrom ? r.getToAddress() : r.getFromAddress();
				if (changeAddr.equals(addr)) {
					boolean isPrimary = ref.isPrimary();
					boolean isOffset = false;
					boolean isShifted = false;
					long offsetOrShift = 0;
					if (r.isMemoryReference()) {
						isOffset = ((MemReferenceDB) r).isOffset();
						isShifted = ((MemReferenceDB) r).isShifted();
						offsetOrShift = ((MemReferenceDB) r).getOffsetOrShift();
					}

					byte[] bytes =
						encode(r.getFromAddress(), r.getToAddress(), r.getReferenceType(),
							r.getSource(), r.getOperandIndex(), symbolID, isPrimary, isOffset,
							isShifted, offsetOrShift);

					if (bytes.length == newPos - pos) {
						System.arraycopy(bytes, 0, refData, pos, bytes.length);
					}
					else {
						byte[] newData = new byte[refData.length - (newPos - pos) + bytes.length];
						System.arraycopy(refData, 0, newData, 0, pos);
						System.arraycopy(bytes, 0, newData, pos, bytes.length);
						System.arraycopy(refData, newPos, newData, pos + bytes.length,
							refData.length - newPos);
						refData = newData;
					}
					updateRecord();
					return true;
				}
			}
			pos = newPos;
		}
		return false;
	}

	/* (non-Javadoc)
	 * @see ghidra.program.database.references.RefList#updateRefType(ghidra.program.model.address.Address, int, ghidra.program.model.symbol.RefType)
	 */
	@Override
	synchronized void updateRefType(Address changeAddr, int opIndex, RefType refType)
			throws IOException {
		boolean updateRefLevel = false;
		byte newLevel = getRefLevel(refType);
		byte highestRefLevel = 0;
		if (!isFrom) {
			updateRefLevel = (newLevel != refLevel);
		}
		Reference[] result = new Reference[1];
		int pos = 0;
		int newPos = 0;
		for (int i = 0; i < numRefs; i++) {
			newPos = decode(refData, pos, result);
			Reference ref = result[0];
			if (ref.getOperandIndex() == opIndex) {
				Address addr = isFrom ? ref.getToAddress() : ref.getFromAddress();
				if (changeAddr.equals(addr)) {
					boolean isPrimary = ref.isPrimary();
					long symbolID = ref.getSymbolID();
					boolean isOffset = false;
					boolean isShifted = false;
					long offsetOrShift = 0;
					if (ref.isMemoryReference()) {
						isOffset = ((MemReferenceDB) ref).isOffset();
						isShifted = ((MemReferenceDB) ref).isShifted();
						offsetOrShift = ((MemReferenceDB) ref).getOffsetOrShift();
					}

					byte[] bytes =
						encode(ref.getFromAddress(), ref.getToAddress(), refType, ref.getSource(),
							ref.getOperandIndex(), symbolID, isPrimary, isOffset, isShifted,
							offsetOrShift);

					System.arraycopy(bytes, 0, refData, pos, bytes.length);

					if (updateRefLevel) {
						if (newLevel > refLevel) {
							highestRefLevel = newLevel;
							break;
						}
						if (newLevel > highestRefLevel) {
							highestRefLevel = newLevel;
						}
					}
					else {
						break;
					}
				}
			}
			else if (updateRefLevel) {
				byte level = getRefLevel(ref.getReferenceType());
				if (level > highestRefLevel) {
					highestRefLevel = level;
				}
			}
			pos = newPos;
		}
		if (updateRefLevel) {
			refLevel = highestRefLevel;
		}
		updateRecord();
	}

	private void updateRecord() throws IOException {
		if (adapter != null) {
			record.setIntValue(ToAdapter.REF_COUNT_COL, numRefs);
			record.setBinaryData(ToAdapter.REF_DATA_COL, refData);
			if (!isFrom) {
				record.setByteValue(ToAdapter.REF_LEVEL_COL, refLevel);
			}
			adapter.putRecord(record);
		}
	}

	private byte[] encode(Address fromAddr, Address toAddr, RefType type, SourceType source,
			int opIndex, long symbolID, boolean isPrimary, boolean isOffsetRef, boolean isShiftRef,
			long offsetOrShift) {
		int length = BASE_REF_SIZE;
		boolean hasSymbolID = symbolID >= 0;
		if (isOffsetRef || isShiftRef) {
			length += OFFSET_SIZE;
		}
		if (hasSymbolID) {
			length += SYMBOL_ID_SIZE;
		}
		RefListFlagsV0 flags =
			new RefListFlagsV0(isPrimary, isOffsetRef, hasSymbolID, isShiftRef, source);

		byte[] data = new byte[length];
		Address addr = isFrom ? toAddr : fromAddr;
		int offset = putLong(data, 0, addrMap.getKey(addr, true));
		data[offset++] = flags.getValue();
		data[offset++] = type.getValue();
		data[offset++] = (byte) opIndex;
		if (hasSymbolID) {
			offset = putLong(data, offset, symbolID);
		}
		if (isOffsetRef || isShiftRef) {
			offset = putLong(data, offset, offsetOrShift);
		}
		return data;
	}

	private int decode(byte[] data, int offset, Reference[] result) {
		long symbolID = -1;
		long addr = getLong(data, offset);
		offset += 8;
		RefListFlagsV0 flags = new RefListFlagsV0(data[offset++]);
		RefType refType = RefTypeFactory.get(data[offset++]);
		byte opIndex = data[offset++];

		SourceType source = flags.getSource();

		long offsetOrShift = 0;

		if (flags.hasSymbolID()) {
			symbolID = getLong(data, offset);
			offset += 8;
		}
		Address from = isFrom ? address : addrMap.decodeAddress(addr);
		Address to = isFrom ? addrMap.decodeAddress(addr) : address;
		if (flags.isOffsetRef() || flags.isShiftRef()) {
			offsetOrShift = getLong(data, offset);
			offset += 8;
			if (flags.isShiftRef()) {
				result[0] =
					new ShiftedReferenceDB(program, from, to, refType, opIndex, source,
						flags.isPrimary(), symbolID, (int) offsetOrShift);
			}
			else {
				result[0] =
					new OffsetReferenceDB(program, from, to, refType, opIndex, source,
						flags.isPrimary(), symbolID, offsetOrShift);
			}
		}
		else if (to.isExternalAddress()) {
			result[0] = new ExternalReferenceDB(program, from, to, refType, opIndex, source);
		}
		else if (from.equals(Address.EXT_FROM_ADDRESS)) {
			result[0] =
				new EntryPointReferenceDB(from, to, refType, opIndex, source, flags.isPrimary(),
					symbolID);
		}
		else if (to.isStackAddress()) {
			result[0] =
				new StackReferenceDB(program, from, to, refType, opIndex, source,
					flags.isPrimary(), symbolID);
		}
		else {
			result[0] =
				new MemReferenceDB(program, from, to, refType, opIndex, source, flags.isPrimary(),
					symbolID);
		}
		return offset;
	}

	public static int putLong(byte[] data, int offset, long v) {
		data[offset] = (byte) (v >> 56);
		data[++offset] = (byte) (v >> 48);
		data[++offset] = (byte) (v >> 40);
		data[++offset] = (byte) (v >> 32);
		data[++offset] = (byte) (v >> 24);
		data[++offset] = (byte) (v >> 16);
		data[++offset] = (byte) (v >> 8);
		data[++offset] = (byte) v;
		return ++offset;
	}

	public static long getLong(byte[] data, int offset) {
		return (((long) data[offset] & 0xff) << 56) | (((long) data[++offset] & 0xff) << 48) |
			(((long) data[++offset] & 0xff) << 40) | (((long) data[++offset] & 0xff) << 32) |
			(((long) data[++offset] & 0xff) << 24) | (((long) data[++offset] & 0xff) << 16) |
			(((long) data[++offset] & 0xff) << 8) | ((long) data[++offset] & 0xff);
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
		byte[] data;
		int n;
		int pos = 0;
		int index = 0;
		Reference[] refs = new Reference[1];

		RefIterator() {
			data = refData;
			n = numRefs;
		}

		/* (non-Javadoc)
		 * @see ghidra.program.model.symbol.MemReferenceIterator#hasNext()
		 */
		@Override
		public boolean hasNext() {
			return index < n;
		}

		/* (non-Javadoc)
		 * @see ghidra.program.model.symbol.MemReferenceIterator#next()
		 */
		@Override
		public Reference next() {
			if (hasNext()) {
				pos = decode(data, pos, refs);
				index++;
				return refs[0];
			}
			return null;
		}

		/**
		 * @see java.util.Iterator#remove()
		 */
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
