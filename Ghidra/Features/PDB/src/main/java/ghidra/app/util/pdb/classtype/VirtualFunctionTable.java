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

import ghidra.app.util.SymbolPath;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbException;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.gclass.ClassID;
import ghidra.program.model.gclass.ClassUtils;

public abstract class VirtualFunctionTable implements VFTable {

	protected ClassID owner;
	protected List<ClassID> parentage;
	/**
	 * The number of entries in the table, as specified by the user
	 */
	protected int userSpecifiedNumEntries;
	/**
	 * This is the offset within the class where we expect to find the pointer that can point to
	 *  this table
	 */
	protected Long ptrOffsetInClass;

	protected int maxTableIndexSeen;
	protected Map<Integer, VirtualFunctionTableEntry> entriesByTableIndex;

	// result of compile/build
	private Structure tableStructure;
	private boolean isBuilt;

	/**
	 * Constructor.
	 * Virtual Function Table for a base (parent) class within an owner class.  The owner and parent
	 * class can be null if not known, but methods are offered to fill them in if/when this
	 * information becomes available
	 * @param owner class that owns this VBT (can own more than one); can be {@code null}
	 * @param parentage parentage for which this VFT is used; can be {@code null}
	 */
	VirtualFunctionTable(ClassID owner, List<ClassID> parentage) {
		this.owner = owner;
		this.parentage = new ArrayList<>(parentage);
		userSpecifiedNumEntries = 0;
		maxTableIndexSeen = -1;
		entriesByTableIndex = new TreeMap<>();
	}

	/**
	 * Returns the address value at the table offset
	 * @param tableIndex the index location in the virtual function table for the entry; based at 1
	 * @return the address
	 * @throws PdbException upon error retrieving the value
	 */
	public abstract Address getAddress(int tableIndex) throws PdbException;

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
	 * Gets the offset within the class for the pointer that can point to this table
	 * @return the offset
	 */
	public Long getPtrOffsetInClass() {
		return ptrOffsetInClass;
	}

	protected abstract VirtualFunctionTableEntry getNewEntry(SymbolPath originalMethodPath,
			SymbolPath overrideMethodPath, Pointer functionPointer);

	/**
	 * Method to add an entry to the virtual function table
	 * @param tableIndex the index location in the virtual function table for the entry; based at 1
	 * @param originalMethodPath the symbol path of the method
	 * @param overrideMethodPath the symbol path of the override method
	 * @param functionPointer pointer to the function definition of the method
	 */
	public void addEntry(int tableIndex, SymbolPath originalMethodPath,
			SymbolPath overrideMethodPath, Pointer functionPointer) {
		VirtualFunctionTableEntry entry =
			getNewEntry(originalMethodPath, overrideMethodPath, functionPointer);
		entriesByTableIndex.put(tableIndex, entry);
		maxTableIndexSeen = Integer.max(maxTableIndexSeen, tableIndex);
	}

	/**
	 * Returns the entry for the table offset
	 * @param tableIndex the index location in the virtual function table for the entry; based at 1
	 * @return the entry
	 */
	public VirtualFunctionTableEntry getEntry(int tableIndex) {
		return entriesByTableIndex.get(tableIndex);
	}

	/**
	 * Returns the number of entries in the table
	 * @return the number of entries
	 */
	public int getNumEntries() {
		return entriesByTableIndex.size();
	}

	/**
	 * Returns the number of entries in the table, as specified by the user
	 * @return the number of entries
	 */
	public int getUserSpecifiedNumEntries() {
		return userSpecifiedNumEntries;
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
	 * Sets the offset within the class for the pointer that can point to this table
	 * @param offset the offset
	 */
	public void setPtrOffsetInClass(Long offset) {
		ptrOffsetInClass = offset;
	}

	/**
	 * Sets the "expected" number of entries for the table
	 * @param numEntriesArg the number of entries
	 */
	public void setNumEntries(int numEntriesArg) {
		userSpecifiedNumEntries = numEntriesArg;
	}

	void emit(StringBuilder builder) {
		builder.append("VBT for the following classes within: " + owner);
		builder.append("\n");
		for (ClassID id : parentage) {
			builder.append("   " + id);
			builder.append("\n");
		}
	}

	public int size() {
		return entriesByTableIndex.size();
	}

	public int getMaxTableIndex() {
		return maxTableIndexSeen;
	}

	public Map<Integer, VirtualFunctionTableEntry> getEntriesByTableIndex() {
		return entriesByTableIndex;
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
		DataType defaultEntry = ClassUtils.getVftDefaultEntry(dtm);
		int entrySize = defaultEntry.getLength();
		StructureDataType dt = new StructureDataType(categoryPath, name, 0, dtm);
		int masterOffset = 0;
		for (Map.Entry<Integer, VirtualFunctionTableEntry> mapEntry : entriesByTableIndex
				.entrySet()) {
			int tableIndex = mapEntry.getKey();
			VFTableEntry tableEntry = mapEntry.getValue();
			while (masterOffset < tableIndex) {
				dt.add(defaultEntry, "", "");
				masterOffset += entrySize;
			}
			dt.add(tableEntry.getFunctionPointer(), tableEntry.getOverridePath().toString(), "");
			masterOffset += entrySize;
		}
		tableStructure = (Structure) dtm.resolve(dt, null);
		//System.out.println(tableStructure.toString());
		isBuilt = true;
	}

}
