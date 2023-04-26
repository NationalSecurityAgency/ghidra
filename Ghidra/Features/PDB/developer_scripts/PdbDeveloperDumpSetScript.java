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
// Developer Script to dump PDB information from a set of PDB files to output files.
// User selects an input file in which each line of text is a tab-separated input/output pair
// of PDB file and output text file.  Blank lines and lines beginning with # are ignored.  Example:
// myFile1.pdb	myFile1.pdb.txt
// myFile2.pdb	myFile2.pdb.txt
//
//@category PDB

import java.io.*;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.format.pdb2.pdbreader.*;
import ghidra.util.exception.CancelledException;

public class PdbDeveloperDumpSetScript extends GhidraScript {

	private record IOEntry(String input, String output) {};

	@Override
	protected void run() throws Exception {
		File controlFile = askFile(
			"Choose control file with a tab-separated PDB-input/text-output pair per line", "OK");
		if (controlFile == null) {
			printerr("Canceled execution: no input file");
			return;
		}

		List<IOEntry> entries = parseControlFile(controlFile);
		if (entries == null) {
			return;
		}

		dumpFiles(entries);
	}

	private List<IOEntry> parseControlFile(File controlFile) throws IOException {
		List<IOEntry> entries = new ArrayList<>();

		try (BufferedReader bufferedReader = new BufferedReader(new FileReader(controlFile))) {
			String line;
			int lineNumber = 0;
			while ((line = bufferedReader.readLine()) != null) {
				lineNumber++;
				if (line.isBlank() || line.trim().startsWith("#")) {
					continue;
				}
				String[] parts = line.split("\\t");
				if (parts.length != 2) {
					printerr("Canceled execution (no files processed): control file, line " +
						lineNumber + " does not contain a valid, tab-delimited pair: \"" + line +
						"\"");
					return null;
				}
				File inputFile = new File(parts[0]);
				if (!inputFile.exists()) {
					printerr("Canceled execution (no files processed): control file, line " +
						lineNumber + ", input file does not exist: " + parts[0]);
					return null;
				}
				entries.add(new IOEntry(parts[0], parts[1]));
			}
		}
		return entries;
	}

	private void dumpFiles(List<IOEntry> entries) throws CancelledException, PdbException {
		for (IOEntry entry : entries) {
			monitor.checkCancelled();
			println("Processing PDB Dump of: " + entry.input());
			try (AbstractPdb pdb =
				PdbParser.parse(entry.input(), new PdbReaderOptions(), monitor)) {
				pdb.deserialize();
				try (BufferedWriter bufferedWriter =
					new BufferedWriter(new FileWriter(new File(entry.output())))) {
					outputHeaderMessage(bufferedWriter, entry.input());
					pdb.dumpDirectory(bufferedWriter);
					pdb.dumpSubStreams(bufferedWriter);
					println("Results located in: " + entry.output());
				}
				catch (IOException ioe) {
					printerr("Error writing output file: " + ioe.getMessage());
				}
			}
			catch (IOException ioe) {
				printerr("Error processing PDB file: " + ioe.getMessage());
			}
		}
	}

	private void outputHeaderMessage(BufferedWriter bufferedWriter, String name)
			throws IOException {
		bufferedWriter.append(getClass().getSimpleName() + " dump of: " + name +
			"\nWARNING: FORMAT SUBJECT TO CHANGE WITHOUT NOTICE--DO NOT PARSE\n\n");
	}

}
