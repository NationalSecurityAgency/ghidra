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

// This script displays a table showing the base address of each source map entry
// in the program along with a count of the number of entries starting at the address.
// @category SourceMapping
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import ghidra.app.script.GhidraScript;
import ghidra.app.tablechooser.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.sourcemap.SourceMapEntry;
import ghidra.program.model.sourcemap.SourceMapEntryIterator;
import ghidra.util.datastruct.Counter;


public class ShowSourceMapEntryStartsScript extends GhidraScript {

	@Override
	protected void run() throws Exception {
		if (isRunningHeadless()) {
			println("This script must be run through the Ghidra gui.");
			return;
		}
		if (currentProgram == null) {
			println("This script requires an open program.");
			return;
		}

		Address startAddress = currentProgram.getMinAddress();
		SourceMapEntryIterator iter =
			currentProgram.getSourceFileManager().getSourceMapEntryIterator(startAddress, true);
		if (!iter.hasNext()) {
			popup(currentProgram.getName() + " has no source map entries");
			return;
		}

		TableChooserDialog tableDialog =
			createTableChooserDialog(currentProgram.getName() + " Source Map Entries", null);
		configureTableColumns(tableDialog);
		tableDialog.show();

		Map<Address, Counter> entryCounts = new HashMap<>();
		while (iter.hasNext()) {
			SourceMapEntry entry = iter.next();
			Address addr = entry.getBaseAddress();
			Counter count = entryCounts.getOrDefault(addr, new Counter());
			count.increment();
			entryCounts.put(addr, count);
		}

		int totalCount = 0;
		for (Entry<Address, Counter> entryCount : entryCounts.entrySet()) {
			int count = entryCount.getValue().intValue();
			tableDialog.add(new SourceMapRowObject(entryCount.getKey(), count));
			totalCount += count;
		}
		tableDialog.setTitle(
			currentProgram.getName() + " Source Map Entries (" + totalCount + " total)");

	}

	private void configureTableColumns(TableChooserDialog tableDialog) {

		ColumnDisplay<Integer> numEntriesColumn = new AbstractComparableColumnDisplay<>() {

			@Override
			public Integer getColumnValue(AddressableRowObject rowObject) {
				return ((SourceMapRowObject) rowObject).getNumEntries();
			}

			@Override
			public String getColumnName() {
				return "Num Entries";
			}
		};

		tableDialog.addCustomColumn(numEntriesColumn);

	}

	class SourceMapRowObject implements AddressableRowObject {

		private Address address;
		private int numEntries;

		SourceMapRowObject(Address address, int numEntries) {
			this.address = address;
			this.numEntries = numEntries;
		}

		@Override
		public Address getAddress() {
			return address;
		}

		public int getNumEntries() {
			return numEntries;
		}
	}

}
