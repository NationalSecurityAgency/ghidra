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
// Developer script to process, line-by-line, mangled symbols from an input file to an output file,
// where each output line is only the symbol's variable name
//@category Demangler
import java.io.*;
import java.util.List;

import org.apache.commons.io.FilenameUtils;
import org.apache.commons.lang3.StringUtils;

import docking.widgets.values.GValuesMap;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.SymbolPath;
import ghidra.features.base.values.GhidraValuesMap;
import ghidra.util.MessageType;
import ghidra.util.StatusListener;
import mdemangler.*;
import utilities.util.FileUtilities;

public class MDMangDeveloperDemangleNamesScript extends GhidraScript {

	private static final String TITLE = "Demangle Names";
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
		String outputFileName = FilenameUtils.removeExtension(inputFileName) + ".out." +
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
		MDMang demangler = new MDMang();
		demangler.setMangledSymbol(name);
		try {
			MDParsableItem item = demangler.demangle();
			//return item.toString(); // Use this code to just return the demangled symbol
			// The following attempts to grab the symbol path to output as the name.
			SymbolPath sp = MDMangUtils.getSymbolPath(item);
			if (sp != null) {
				String s = sp.toString();
				if (s.matches("(?s).*\\r?\\n.*")) {
					// Symbols that are found at string locations in a program generally begin
					// with "??_C" and contain and encoding of the user string to make the symbol
					// unique.  During demangling, we chose to decode these symbols and if such
					// symbols have an encoded newline character, the demangled output will contain
					// a newline.  Since we want the ability to match our file output line by line
					// with the file input, we want to remove those newlines here.  If for some
					// reason, there are newlines in a demangled output that are not due to the
					// demangling of a string symbol, we output error messages for further
					// investigation.
					if (!name.startsWith("??_C")) {
						printerr("FOUND MULTI-LINE RESULT for input: " + name +
							"\n--- START MULTI-LINE ---\n" + s + "\n--- END MULTI-LINE ---");
					}
				}
				return sp.toString().replaceAll("[\\r\\n]+", " ");
			}
			return "COULD NOT GET SYMBOLPATH FOR: " + name;
		}
		catch (MDException e) {
			String cleanMessage = e.getMessage() != null
					? e.getMessage().replaceAll("[\\r\\n]+", " ")
					: "Unknown MDException";
			return getError(name, cleanMessage);
		}
	}

	private String getError(String name, String reason) {
		return "!Failed(" + reason + "): " + name;
	}

}
