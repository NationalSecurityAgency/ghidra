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
// Add a source map entry for the current selection.
// The current selection must consist of a single address range.
// If there is no selection, a length 0 entry will be added at the current address.
//@category SourceMapping
import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.features.base.values.GhidraValuesMap;
import ghidra.program.database.sourcemap.SourceFile;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.sourcemap.*;
import ghidra.util.MessageType;

public class AddSourceMapEntryScript extends GhidraScript {

	private static final String LINE_NUM = "Line Number";
	private static final String SOURCE_FILE = "Source File";

	@Override
	protected void run() throws Exception {
		if (isRunningHeadless()) {
			println("This script must be run through the Ghidra GUI");
			return;
		}
		if (currentProgram == null) {
			popup("This script requires an open program");
			return;
		}
		if (!currentProgram.hasExclusiveAccess()) {
			popup("This script requires exclusive access to the program");
			return;
		}

		SourceFileManager sourceManager = currentProgram.getSourceFileManager();
		List<SourceFile> sourceFiles = sourceManager.getAllSourceFiles();
		if (sourceFiles.isEmpty()) {
			popup("You must first add at least one source file to the program");
			return;
		}

		boolean valid = isCurrentSelectionValid();
		if (!valid) {
			return; // checkCurrentSelection will tell the user what the problem is
		}

		Address baseAddr =
			currentSelection == null ? currentAddress : currentSelection.getMinAddress();
		long length = currentSelection == null ? 0 : currentSelection.getNumAddresses();

		AddressRange currentRange =
			currentSelection == null ? null : currentSelection.getAddressRanges().next();

		Map<String, SourceFile> stringsToSourceFiles = new HashMap<>();
		sourceFiles.forEach(sf -> stringsToSourceFiles.put(sf.toString(), sf));

		GhidraValuesMap values = new GhidraValuesMap();
		values.defineInt(LINE_NUM, 1);
		String[] sourceFileArray = stringsToSourceFiles.keySet().toArray(new String[0]);
		Arrays.sort(sourceFileArray);
		values.defineChoice(SOURCE_FILE, sourceFileArray[0], sourceFileArray);

		values.setValidator((valueMap, status) -> {
			int lineNum = values.getInt(LINE_NUM);
			if (lineNum < 0) {
				status.setStatusText("Line number cannot be negative", MessageType.ERROR);
				return false;
			}
			if (currentRange == null) {
				return true; // length 0 entry, nothing else to check
			}
			SourceFile source = new SourceFile(values.getChoice(SOURCE_FILE));

			for (SourceMapEntry entry : sourceManager.getSourceMapEntries(source, lineNum)) {
				// because checkCurrentSelection returned true, if the entries intersect
				// they must be equal
				if (entry.getLength() != 0 && entry.getRange().intersects(currentRange)) {
					status.setStatusText(currentSelection + " is already mapped to " +
						source.getPath() + ":" + lineNum);
					return false;
				}
			}
			return true;
		});

		askValues("Source Map Info", "Enter Source Map Info (length = " + length + ")", values);
		int lineNum = values.getInt(LINE_NUM);
		String fileString = values.getChoice(SOURCE_FILE);
		SourceFile source = stringsToSourceFiles.get(fileString);
		sourceManager.addSourceMapEntry(source, lineNum, baseAddr, length);
	}

	// check that the selected range doesn't already intersect a SourceMapEntry with a 
	// conflicting range.
	private boolean isCurrentSelectionValid() {
		if (currentSelection == null) {
			return true;
		}
		if (currentSelection.getNumAddressRanges() != 1) {
			popup("This script requires the current selection to be a single address range");
			return false;
		}
		AddressRange range = currentSelection.getFirstRange();
		Address end = range.getMaxAddress();
		SourceMapEntryIterator iter =
			currentProgram.getSourceFileManager().getSourceMapEntryIterator(end, false);
		while (iter.hasNext()) {
			SourceMapEntry entry = iter.next();
			if (!entry.getBaseAddress().getAddressSpace().equals(range.getAddressSpace())) {
				return true;  // iterator has exhausted entries in the address space, no conflicts
							// are possible
			}
			if (entry.getLength() == 0) {
				continue;  // length 0 entries can't conflict
			}
			AddressRange entryRange = entry.getRange();
			if (entryRange.equals(range)) {
				return true; // range is the same as a range already in the db, so no problems
			}
			if (entryRange.intersects(range)) {
				popup("Selection conflicts with existing entry " + entry.toString());
				return false;
			}
			if (entryRange.getMaxAddress().compareTo(range.getMinAddress()) < 0) {
				return true; // no conflicting entries exists
			}
		}
		return true;
	}

}
