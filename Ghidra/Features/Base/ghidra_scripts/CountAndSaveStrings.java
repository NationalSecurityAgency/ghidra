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
//Counts the number of defined strings in the current selection, or current program if no selection is made,
//and saves the results to a file.
//@category CustomerSubmission.Strings

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramSelection;

import java.io.*;

public class CountAndSaveStrings extends GhidraScript {
	private Listing listing;
	private File saveFile;

	@Override
	public void run() throws Exception {
		listing = currentProgram.getListing();
		saveFile = getSaveFile();
		if (saveFile == null) {
			println("You chose not to overwrite the selected file. Stopping execution.");
			return;
		}
		int stringsFound = findAndPrintMatches(getDataIterator(currentSelection));
		if (stringsFound == -1) {
			println("File " + saveFile + " was not found");
			return;
		}
		println(stringsFound + " strings were writtin to " + saveFile.getName());
	}

	private File getSaveFile() throws Exception {
		File file = askFile("Choose File Location", "Save");
		if (file.exists()) {
			if (!askYesNo("File Already Exists", "A file already exists with the name you "
				+ "chose.\nDo you want to overwrite it?")) {
				return null;
			}
		}
		return file;
	}

	private DataIterator getDataIterator(ProgramSelection selection) {
		if (selection != null) {
			return listing.getDefinedData(currentSelection, true);
		}
		return listing.getDefinedData(true);
	}

	private int findAndPrintMatches(DataIterator dataIt) {
		PrintWriter fileWriter;
		try {
			fileWriter = new PrintWriter(new FileOutputStream(saveFile));
		}
		catch (FileNotFoundException e) {
			return -1;
		}
		Data data;
		String type;
		int counter = 0;
		while (dataIt.hasNext() && !monitor.isCancelled()) {
			data = dataIt.next();
			type = data.getDataType().getName().toLowerCase();
			if ((type.contains("unicode") || type.contains("string")) &&
				data.getDefaultValueRepresentation().length() > 4) {
				counter++;
				fileWriter.println(data.getDefaultValueRepresentation());
			}
		}
		fileWriter.close();
		return counter;
	}
}
