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
// Select and remove a source map entry at the current address.
//@category SourceMapping
import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.features.base.values.GhidraValuesMap;
import ghidra.program.model.sourcemap.SourceMapEntry;

public class RemoveSourceMapEntryScript extends GhidraScript {

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
			popup("Modifying the source map requires exclusive access to the program");
			return;
		}
		List<SourceMapEntry> entries =
			currentProgram.getSourceFileManager().getSourceMapEntries(currentAddress);
		if (entries.isEmpty()) {
			popup("No source map entries at " + currentAddress);
			return;
		}

		Map<String, SourceMapEntry> stringToEntry = new HashMap<>();
		List<String> choices = new ArrayList<>();
		for (SourceMapEntry entry : entries) {
			String entryString = entry.toString();
			stringToEntry.put(entryString, entry);
			choices.add(entryString);
		}
		GhidraValuesMap values = new GhidraValuesMap();
		String[] choiceArray = choices.toArray(new String[] {});
		values.defineChoice("Entry", choiceArray[0], choiceArray);
		askValues("Select SourceMapEntry to remove", null, values);
		String selectedString = values.getChoice("Entry");
		SourceMapEntry toDelete = stringToEntry.get(selectedString);
		currentProgram.getSourceFileManager().removeSourceMapEntry(toDelete);
	}

}
