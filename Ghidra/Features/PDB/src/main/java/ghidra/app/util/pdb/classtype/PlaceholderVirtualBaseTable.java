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
package ghidra.app.util.pdb.classtype;

import java.util.*;

import ghidra.app.util.bin.format.pdb2.pdbreader.PdbException;

/**
 * Virtual Base Table without a program
 */
public class PlaceholderVirtualBaseTable extends VirtualBaseTable {

	private int entrySize;

	private int maxIndexSeen = -1;
	private Map<Integer, VBTableEntry> entriesByIndex = new HashMap<>();

	/**
	 * Constructor
	 * @param owner the class that owns the table
	 * @param parentage the parentage of the base class(es) of the table
	 * @param entrySize the size of the index field for each table entry as it would be in memory
	 */
	public PlaceholderVirtualBaseTable(ClassID owner, List<ClassID> parentage, int entrySize) {
		super(owner, parentage);
		if (entrySize != 4 && entrySize != 8) {
			throw new IllegalArgumentException("Invalid size (" + entrySize + "): must be 4 or 8.");
		}
		this.entrySize = entrySize;
	}

	/*
	 * For the next method below... once we determine the number of virtual bases (virtual and
	 * indirect virtual) for each class (from PDB or other), we can determine the number of
	 * entries in each VBT.  For a VBT for the main class, the number is equal... if for some
	 * parentage, then the number can reflect the number of the parent.
	 * TODO: can VBT overlay/extend one from parent????????????????????????????????????????????
	 */
	/**
	 * TBD: need to determine table size to do this.  Might want to place a symbol (diff method?).
	 */
	void createTableDataType(int numEntries) {

	}

	int getMaxIndex() {
		return maxIndexSeen;
	}

	public void setBaseClassOffsetAndId(int index, Long offset, ClassID baseId) {
		VBTableEntry entry = entriesByIndex.get(index);
		if (entry == null) {
			entry = new VirtualBaseTableEntry(offset, baseId);
			entriesByIndex.put(index, entry);
		}
		else {
			entry.setOffset(offset);
			entry.setClassId(baseId);
		}
		maxIndexSeen = Integer.max(maxIndexSeen, index);
	}

	public void setBaseClassId(int index, ClassID baseId) {
		VBTableEntry entry = entriesByIndex.get(index);
		if (entry == null) {
			entry = new VirtualBaseTableEntry(baseId);
			entriesByIndex.put(index, entry);
		}
		else {
			entry.setClassId(baseId);
		}
		maxIndexSeen = Integer.max(maxIndexSeen, index);
	}

	public void setBaseOffset(int index, Long offset) {
		VBTableEntry entry = entriesByIndex.get(index);
		if (entry == null) {
			entry = new VirtualBaseTableEntry(offset);
			entriesByIndex.put(index, entry);
		}
		else {
			entry.setOffset(offset);
		}
		maxIndexSeen = Integer.max(maxIndexSeen, index);
	}

	@Override
	public Long getBaseOffset(int index) throws PdbException {
		VBTableEntry entry = entriesByIndex.get(index);
		Long offset = (entry == null) ? null : entry.getOffset();
		maxIndexSeen = Integer.max(maxIndexSeen, index);
		return offset;
	}

	@Override
	public ClassID getBaseClassId(int index) {
		VBTableEntry entry = entriesByIndex.get(index);
		ClassID id = (entry == null) ? null : entry.getClassId();
		maxIndexSeen = Integer.max(maxIndexSeen, index);
		return id;
	}

	@Override
	public VBTableEntry getBase(int index) throws PdbException {
		VBTableEntry entry = entriesByIndex.get(index);
		if (entry != null) {
			maxIndexSeen = Integer.max(maxIndexSeen, index);
		}
		return entry;
	}

}
