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

import ghidra.app.util.SymbolPath;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbException;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.gclass.ClassID;

public class PlaceholderVirtualFunctionTable extends VirtualFunctionTable {

	/**
	 * Constructor.
	 * Virtual Function Table for a base (parent) class within an owner class.  The owner and parent
	 * class can be null if not known, but methods are offered to fill them in if/when this
	 * information becomes available
	 * @param owner class that owns this VBT (can own more than one); can be {@code null}
	 * @param parentage parentage for which this VFT is used; can be {@code null}
	 */
	public PlaceholderVirtualFunctionTable(ClassID owner, List<ClassID> parentage) {
		super(owner, parentage);
	}

	public void setAddress(int tableIndex, Address address) throws PdbException {
		PlaceholderVirtualFunctionTableEntry entry = existing(tableIndex);
		entry.setAddress(address);
	}

	@Override
	public Address getAddress(int tableIndex) throws PdbException {
		PlaceholderVirtualFunctionTableEntry entry = existing(tableIndex);
		return entry.getAddress();
	}

	@Override
	protected VirtualFunctionTableEntry getNewEntry(SymbolPath originalMethodPath,
			SymbolPath overrideMethodPath, Pointer functionPointer) {
		return new PlaceholderVirtualFunctionTableEntry(originalMethodPath, overrideMethodPath,
			functionPointer);
	}

	@Override
	public void emit(StringBuilder builder) {
		builder.append(
			"Placeholder VFT for the following classes within owner:\n   " + owner + "\n");
		builder.append(String.format("For Classes:\n"));
		for (ClassID id : parentage) {
			builder.append(String.format("   %-10s\n", id.toString()));
		}
		builder.append("VftPtrOffset within Owner" + ptrOffsetInClass + "\n");
		PlaceholderVirtualFunctionTableEntry.emitHeader(builder);
		for (int tableIndex : entriesByTableIndex.keySet()) {
			entry(tableIndex).emit(builder, ptrOffsetInClass);
		}
	}

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		emit(builder);
		return builder.toString();
	}

	private PlaceholderVirtualFunctionTableEntry entry(int tableIndex) {
		return (PlaceholderVirtualFunctionTableEntry) entriesByTableIndex.get(tableIndex);
	}

	private PlaceholderVirtualFunctionTableEntry existing(int tableIndex) throws PdbException {
		PlaceholderVirtualFunctionTableEntry entry = entry(tableIndex);
		if (entry == null) {
			throw new PdbException(
				"No entry in Virtual Function Table for table offset: " + tableIndex);
		}
		return entry;
	}

}
