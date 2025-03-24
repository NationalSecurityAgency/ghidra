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

import java.util.List;

import ghidra.app.util.bin.format.pdb2.pdbreader.PdbException;
import ghidra.program.model.gclass.ClassID;

/**
 * Virtual Base Table without a program
 */
public class PlaceholderVirtualBaseTable extends VirtualBaseTable {

	/**
	 * Constructor
	 * @param owner the class that owns the table
	 * @param parentage the parentage of the base class(es) of the table
	 */
	public PlaceholderVirtualBaseTable(ClassID owner, List<ClassID> parentage) {
		super(owner, parentage);
	}

	public void setBaseClassOffsetAndId(int tableIndex, Long offset, ClassID baseId) {
		PlaceholderVirtualBaseTableEntry entry = entry(tableIndex);
		if (entry == null) {
			entry = new PlaceholderVirtualBaseTableEntry(offset, baseId);
			entryByTableIndex.put(tableIndex, entry);
			maxTableIndexSeen = Integer.max(maxTableIndexSeen, tableIndex);
		}
		else {
			entry.setOffset(offset);
			entry.setClassId(baseId);
		}
	}

	public void setBaseOffset(int tableIndex, Long offset) {
		PlaceholderVirtualBaseTableEntry entry = entry(tableIndex);
		if (entry == null) {
			entry = new PlaceholderVirtualBaseTableEntry(offset);
			entryByTableIndex.put(tableIndex, entry);
			maxTableIndexSeen = Integer.max(maxTableIndexSeen, tableIndex);
		}
		else {
			entry.setOffset(offset);
		}
	}

	@Override
	public PlaceholderVirtualBaseTableEntry getEntry(int tableIndex) {
		return (PlaceholderVirtualBaseTableEntry) entryByTableIndex.get(tableIndex);
	}

	@Override
	public Long getBaseOffset(int tableIndex) throws PdbException {
		PlaceholderVirtualBaseTableEntry entry = entry(tableIndex);
		Long offset = (entry == null) ? null : entry.getOffset();
		return offset;
	}

	@Override
	protected PlaceholderVirtualBaseTableEntry getNewEntry(ClassID baseId) {
		return new PlaceholderVirtualBaseTableEntry(baseId);
	}

	private PlaceholderVirtualBaseTableEntry entry(int tableIndex) {
		return (PlaceholderVirtualBaseTableEntry) entryByTableIndex.get(tableIndex);
	}

	private PlaceholderVirtualBaseTableEntry existing(int tableIndex) throws PdbException {
		PlaceholderVirtualBaseTableEntry entry = entry(tableIndex);
		if (entry == null) {
			throw new PdbException(
				"No entry in Virtual Base Table for table index: " + tableIndex);
		}
		return entry;
	}

}
