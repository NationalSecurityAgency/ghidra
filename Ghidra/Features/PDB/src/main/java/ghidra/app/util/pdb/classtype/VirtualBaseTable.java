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
import ghidra.program.model.data.*;
import ghidra.program.model.gclass.ClassID;
import ghidra.program.model.gclass.ClassUtils;

/**
 * Abstract class for virtual base tables
 */
public abstract class VirtualBaseTable implements VBTable {

	protected ClassID owner; // Does this belong here in this abstract class?
	protected List<ClassID> parentage; // Not sure this belongs in this abstract class
	/**
	 * The number of entries in the table, as specified by the user
	 */
	protected Integer userSpecifiedNumEntries;
	/**
	 * This is the offset within the class where we expect to find the pointer that can point to
	 *  this table
	 */
	protected Long ptrOffsetInClass;

	protected int maxTableIndexSeen;
	protected Map<Integer, VirtualBaseTableEntry> entryByTableIndex;
	protected Map<Integer, Long> baseOffsetByTableIndex;

	// result of compile/build
	private Structure tableStructure;
	private boolean isBuilt;

	/**
	 * Virtual Base Table for a base (parent) class within an owner class.  The owner and parent
	 * class can be null if not known, but methods are offered to fill them in if/when this
	 * information becomes available
	 * @param owner class that owns this VBT (can own more than one). Can be null
	 * @param parentage class of parents for which this VBT is used (when "this" cast to parent).
	 */
	public VirtualBaseTable(ClassID owner, List<ClassID> parentage) {
		this.owner = owner;
		this.parentage = new ArrayList<>(parentage);
		maxTableIndexSeen = -1;
		entryByTableIndex = new HashMap<>();
		baseOffsetByTableIndex = new HashMap<>();
	}

	protected abstract VirtualBaseTableEntry getNewEntry(ClassID baseId);

	/**
	 * Method to add an entry to the virtual base table
	 * @param tableIndex the index location in the virtual base table for the entry
	 * @param baseId class id of the base
	 */
	public void addEntry(int tableIndex, ClassID baseId) {
		VirtualBaseTableEntry entry = getNewEntry(baseId);
		entryByTableIndex.put(tableIndex, entry);
		maxTableIndexSeen = Integer.max(maxTableIndexSeen, tableIndex);
	}

	int getMaxTableIndex() {
		return maxTableIndexSeen;
	}

	public Map<Integer, VirtualBaseTableEntry> getEntriesByTableIndex() {
		return entryByTableIndex;
	}

	/**
	 * Returns the base class entry for the table tableIndex
	 * @param tableIndex the index location in the virtual base table for the entry
	 * @return the entry for the base class
	 */
	public VBTableEntry getEntry(int tableIndex) {
		return entryByTableIndex.get(tableIndex);
	}

	/**
	 * Returns the offset of the base class in the layout class pertaining whose entry in the
	 * VBTable is at the tableIndex location
	 * @param tableIndex the index location in the virtual base table for the entry
	 * @return the offset in the layout class
	 * @throws PdbException if problem retrieving the offset value
	 */
	public abstract Long getBaseOffset(int tableIndex) throws PdbException;

	/**
	 * Sets the base class id for the table index; the table index is based at 1
	 * @param tableIndex the index location in the table
	 * @param baseId the base class id
	 */
	public void setBaseClassId(int tableIndex, ClassID baseId) {
		VirtualBaseTableEntry entry = entryByTableIndex.get(tableIndex);
		if (entry == null) {
			entry = new VirtualBaseTableEntry(baseId);
			entryByTableIndex.put(tableIndex, entry);
		}
		else {
			entry.setClassId(baseId);
		}
		maxTableIndexSeen = Integer.max(maxTableIndexSeen, tableIndex);
	}

	/**
	 * Returns the ClassID of the base class in the layout class pertaining whose entry in the
	 * VBTable is at the tableIndex location; the table index is based at 1
	 * @param tableIndex the index location in the virtual base table for the entry
	 * @return the ClassID of the base class
	 * @throws PdbException if an entry does not exist for the tableIndex
	 */
	public ClassID getBaseClassId(int tableIndex) throws PdbException {
		VBTableEntry entry = entryByTableIndex.get(tableIndex);
		if (entry == null) {
			return null;
		}
		maxTableIndexSeen = Integer.max(maxTableIndexSeen, tableIndex);
		return entry.getClassId();
	}

	/**
	 * Returns the owning class
	 * @return the owner
	 */
	public ClassID getOwner() {
		return owner;
	}

	/**
	 * Returns the parentage of the table
	 * @return the parentage
	 */
	public List<ClassID> getParentage() {
		return parentage;
	}

	/**
	 * Returns the number of entries in the table
	 * @return the number of entries
	 */
	public int getNumEntries() {
		return entryByTableIndex.size();
	}

	/**
	 * Returns the number of entries in the table, as specified by the user
	 * @return the number of entries
	 */
	public int getUserSpecifiedNumEntries() {
		return userSpecifiedNumEntries;
	}

	/**
	 * Gets the offset within the class for the pointer that can point to this table
	 * @return the offset; {@code null} if not initialized
	 */
	public Long getPtrOffsetInClass() {
		return ptrOffsetInClass;
	}

	/**
	 * Sets the owner of the table
	 * @param ownerArg the class to set as owner
	 */
	public void setOwner(ClassID ownerArg) {
		owner = ownerArg;
	}

	/**
	 * Sets the parentage of the parentage for the table
	 * @param parentage the parentage
	 */
	public void setParentage(List<ClassID> parentage) {
		this.parentage = parentage;
	}

	/**
	 * Sets the number of entries for the table
	 * @param numEntriesArg the number of entries
	 */
	public void setNumEntries(Integer numEntriesArg) {
		userSpecifiedNumEntries = numEntriesArg;
	}

	/**
	 * Sets the offset within the class for the pointer that can point to this table
	 * @param offset the offset
	 */
	public void setPtrOffsetInClass(Long offset) {
		ptrOffsetInClass = offset;
	}

	void emit(StringBuilder builder) {
		builder.append("VBT for the following parentage within: " + owner);
		builder.append("\n");
		for (ClassID id : parentage) {
			builder.append("   " + id);
			builder.append("\n");
		}
	}

	/**
	 * Returns the built data type for this vftable for the current entries
	 * @param dtm the data type manager
	 * @param categoryPath category path for the table
	 * @return the structure of the vftable
	 */
	public Structure getLayout(DataTypeManager dtm, CategoryPath categoryPath) {
		if (!isBuilt) { // what if we want to rebuild... what should we do?
			build(dtm, categoryPath);
		}
		return tableStructure;
	}

	private void build(DataTypeManager dtm, CategoryPath categoryPath) {
		if (ptrOffsetInClass == null || maxTableIndexSeen == -1) {
			tableStructure = null;
			isBuilt = true;
			return;
		}
		String name = ClassUtils.getSpecialVxTableName(ptrOffsetInClass);
		DataType defaultEntry = ClassUtils.getVbtDefaultEntry(dtm);
		// Holding onto next line for now
		//int entrySize = defaultEntry.getLength();
		// Note that maxTableIndexSeen comes from addEntry() and those have what seems to be
		//  a base 1 "index" (vs. base 0 vs. offset)
		int tableNumEntries =
			(userSpecifiedNumEntries != null) ? userSpecifiedNumEntries : maxTableIndexSeen;
		// Holding onto next line for now
		//int tableSize = tableNumEntries * entrySize;
		StructureDataType dt = new StructureDataType(categoryPath, name, 0, dtm);
		int masterOrdinal = 0;
		for (Map.Entry<Integer, VirtualBaseTableEntry> mapEntry : entryByTableIndex.entrySet()) {
			// Note that entrie's tableIndex is based at 1 instead of 0
			int ordinal = mapEntry.getKey() - 1;
			VBTableEntry entry = mapEntry.getValue();
			while (masterOrdinal < ordinal) {
				dt.add(defaultEntry, "", "");
				masterOrdinal++;
			}
			String comment = entry.getClassId().getSymbolPath().toString();
			dt.add(defaultEntry, "", comment); // we could add a comment here
			masterOrdinal++;
		}
		while (masterOrdinal < tableNumEntries) {
			dt.add(defaultEntry, "", "");
			masterOrdinal++;
		}
		dt.align(defaultEntry.getAlignedLength());
		dt.setToDefaultPacking();
		tableStructure = (Structure) dtm.resolve(dt, null);
		//System.out.println(tableStructure.toString());
		isBuilt = true;
	}

}
