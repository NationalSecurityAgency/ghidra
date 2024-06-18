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
// Genericize mangled names from a list.
//  Input is a file name with a name on each line.  Output is a file with the corresponding output
//  on each line.
// If a name cannot be demangled, it will not be genericized.  The line for that name will
//  be output as follows:  !Failed(<reason>): inputName
//
//@category Demangler

import java.io.*;
import java.util.List;

import org.apache.commons.io.FilenameUtils;
import org.apache.commons.lang3.StringUtils;

import docking.widgets.values.GValuesMap;
import ghidra.app.script.GhidraScript;
import ghidra.features.base.values.GhidraValuesMap;
import ghidra.util.MessageType;
import ghidra.util.StatusListener;
import mdemangler.MDException;
import mdemangler.MDMangGenericize;
import utilities.util.FileUtilities;

public class MDMangDeveloperGenericizeMangledNamesScript extends GhidraScript {

	private static final String TITLE = "Genericize Mangled Names";
	private static final String INPUT_PROMPT = "Choose an input file";
	private static final String OUTPUT_PROMPT = "Choose an output file";

	private static boolean validateInputFile(GValuesMap valueMap, StatusListener status) {
		File file = valueMap.getFile(INPUT_PROMPT);
		if (file == null) {
			status.setStatusText("Input file must be selected.", MessageType.ERROR);
			return false;
		}
		if (!file.exists()) {
			status.setStatusText(file.getAbsolutePath() + " is not a valid file.",
				MessageType.ERROR);
			return false;
		}
		return true;
	}

	private static boolean validateOutputFile(GValuesMap valueMap, StatusListener status) {
		File fileIn = valueMap.getFile(INPUT_PROMPT);
		File fileOut = valueMap.getFile(OUTPUT_PROMPT);
		String fileNameIn = fileIn.getAbsolutePath();
		String fileNameOut = fileOut.getAbsolutePath();
		if (fileNameOut.equals(fileNameIn)) {
			status.setStatusText("Output file cannot be same as input file '" + fileNameOut + "').",
				MessageType.ERROR);
			return false;
		}
		return true;
	}

	@Override
	protected void run() throws Exception {

		GhidraValuesMap values = new GhidraValuesMap();

		values.defineFile(INPUT_PROMPT, null);
		values.setValidator((valueMap, status) -> {
			return validateInputFile(valueMap, status);
		});
		values = askValues(TITLE, null, values);
		File inputFile = values.getFile(INPUT_PROMPT);
		String inputFileName = inputFile.getAbsolutePath();

		// creating a default output and asking again, to include output file query
		String outputFileName = FilenameUtils.removeExtension(inputFileName) + ".gen." +
			FilenameUtils.getExtension(inputFileName);
		values.defineFile(OUTPUT_PROMPT, new File(outputFileName));
		values.setValidator((valueMap, status) -> {
			return validateInputFile(valueMap, status) && validateOutputFile(valueMap, status);
		});
		setReusePreviousChoices(false); // false for second pass... want our default output
		values = askValues(TITLE, null, values);
		inputFile = values.getFile(INPUT_PROMPT); // might have changed
		inputFileName = inputFile.getAbsolutePath(); // might have changed
		File outputFile = values.getFile(OUTPUT_PROMPT);

		if (outputFile.exists()) {
			if (!askYesNo("Confirm Overwrite", "Overwrite file: " + outputFile.getName())) {
				println("Operation canceled");
				return;
			}
		}

		FileWriter fileWriter = new FileWriter(outputFile);
		try (BufferedWriter bufferedWriter = new BufferedWriter(fileWriter)) {
			String message = "Processing " + inputFileName;
			monitor.setMessage(message);
			println(message);
			List<String> lines = FileUtilities.getLines(inputFile);
			for (String name : lines) {
				monitor.checkCancelled();
				String output = getProcessedName(name);
				bufferedWriter.append(output);
				bufferedWriter.append("\n");
			}
			message = "Results located in: " + outputFile.getAbsolutePath();
			monitor.setMessage(message);
			println(message);
		}
	}

	private String getProcessedName(String name) {
		if (StringUtils.containsWhitespace(name)) {
			return getError(name, "contains white space");
		}
		MDMangGenericize demangler = new MDMangGenericize();
		try {
			demangler.demangle(name, false);
		}
		catch (MDException e) {
			return getError(name, e.getMessage());
		}
		return demangler.getGenericSymbol();
	}

	private String getError(String name, String reason) {
		return "!Failed(" + reason + "): " + name;
	}

}
