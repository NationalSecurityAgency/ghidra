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
// Sets the current selection based on source file and line number parameters
//@category SourceMapping
import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.features.base.values.GhidraValuesMap;
import ghidra.program.database.sourcemap.SourceFile;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.sourcemap.SourceFileManager;
import ghidra.program.model.sourcemap.SourceMapEntry;
import ghidra.util.MessageType;
import ghidra.util.SourceFileUtils;
import ghidra.util.SourceFileUtils.SourceLineBounds;

public class SelectAddressesMappedToSourceFileScript extends GhidraScript {

	private static final String SOURCE_FILE = "Source File";
	private static final String MIN_LINE = "Minimum Source Line";
	private static final String MAX_LINE = " Maximum Source Line";

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

		SourceFileManager sourceManager = currentProgram.getSourceFileManager();

		List<SourceFile> sourceFiles = sourceManager.getMappedSourceFiles();
		if (sourceFiles.isEmpty()) {
			popup(currentProgram.getName() + " contains no mapped source files");
			return;
		}

		GhidraValuesMap sourceFileValue = new GhidraValuesMap();

		Map<String, SourceFile> stringsToSourceFiles = new HashMap<>();
		sourceFiles.forEach(sf -> stringsToSourceFiles.put(sf.toString(), sf));
		String[] sourceFileArray = stringsToSourceFiles.keySet().toArray(new String[0]);
		Arrays.sort(sourceFileArray);

		sourceFileValue.defineChoice(SOURCE_FILE, sourceFileArray[0], sourceFileArray);
		askValues("Select Source File", "Source File", sourceFileValue);
		String sfString = sourceFileValue.getChoice(SOURCE_FILE);

		SourceFile mappedSourceFile = stringsToSourceFiles.get(sfString);
		SourceLineBounds bounds =
			SourceFileUtils.getSourceLineBounds(currentProgram, mappedSourceFile);
		GhidraValuesMap boundValues = new GhidraValuesMap();
		boundValues.defineInt(MIN_LINE, bounds.min());
		boundValues.setInt(MIN_LINE, bounds.min());
		boundValues.defineInt(MAX_LINE, bounds.max());
		boundValues.setInt(MAX_LINE, bounds.max());

		boundValues.setValidator((valueMap, status) -> {
			int minLine = boundValues.getInt(MIN_LINE);
			if (minLine < 0) {
				status.setStatusText("Line number cannot be negative", MessageType.ERROR);
				return false;
			}
			int maxLine = boundValues.getInt(MAX_LINE);
			if (maxLine < minLine) {
				status.setStatusText("Max line cannot be less than min line", MessageType.ERROR);
				return false;
			}
			return true;
		});

		setReusePreviousChoices(false);
		askValues("Select Line Bounds", "Bounds for " + mappedSourceFile.getFilename(),
			boundValues);
		setReusePreviousChoices(true);

		int minLine = boundValues.getInt(MIN_LINE);
		int maxLine = boundValues.getInt(MAX_LINE);
		AddressSet selection = new AddressSet();
		List<SourceMapEntry> entries =
			sourceManager.getSourceMapEntries(mappedSourceFile, minLine, maxLine);
		for (SourceMapEntry entry : entries) {
			if (entry.getLength() == 0) {
				selection.add(entry.getBaseAddress());
				continue;
			}
			selection.add(entry.getRange());
		}
		if (selection.isEmpty()) {
			popup("No addresses for the selected file and range");
			return;
		}
		setCurrentSelection(selection);
	}

}
