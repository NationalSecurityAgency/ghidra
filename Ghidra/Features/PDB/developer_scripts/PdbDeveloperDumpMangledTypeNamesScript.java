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
// Dump PDB mangled type names for PDB developer use
//
//@category PDB

import java.io.*;

import docking.widgets.values.GValuesMap;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.format.pdb2.pdbreader.*;
import ghidra.app.util.bin.format.pdb2.pdbreader.type.AbstractComplexMsType;
import ghidra.app.util.bin.format.pdb2.pdbreader.type.AbstractMsType;
import ghidra.features.base.values.GhidraValuesMap;
import ghidra.util.MessageType;
import ghidra.util.StatusListener;
import ghidra.util.exception.CancelledException;

public class PdbDeveloperDumpMangledTypeNamesScript extends GhidraScript {

	private static final String TITLE = "Dump PDB Mangled Type Names";
	private static final String PDB_PROMPT = "Choose a PDB file";
	private static final String OUTPUT_PROMPT = "Choose an output file";

	private static boolean validatePdb(GValuesMap valueMap, StatusListener status) {
		File file = valueMap.getFile(PDB_PROMPT);
		if (file == null) {
			status.setStatusText("PDB file must be selected.", MessageType.ERROR);
			return false;
		}
		if (!file.exists()) {
			status.setStatusText(file.getAbsolutePath() + " is not a valid file.",
				MessageType.ERROR);
			return false;
		}
		String fileName = file.getAbsolutePath();
		if (!fileName.endsWith(".pdb") && !fileName.endsWith(".PDB")) {
			status.setStatusText("Expected .pdb file extenstion (got '" + fileName + "').",
				MessageType.ERROR);
			return false;
		}
		// We do not need to check the existence of an image base because we provide a default
		//  value
		return true;
	}

	private static boolean validateOutput(GValuesMap valueMap, StatusListener status) {
		File file = valueMap.getFile(OUTPUT_PROMPT);
		// File will exist, as we supplied a default value
		String fileName = file.getAbsolutePath();
		if (fileName.endsWith(".pdb") || fileName.endsWith(".PDB")) {
			status.setStatusText("Output file may not end with .pdb (got '" + fileName + "').",
				MessageType.ERROR);
			return false;
		}
		return true;
	}

	@Override
	protected void run() throws Exception {

		GhidraValuesMap values = new GhidraValuesMap();

		values.defineFile(PDB_PROMPT, null);
		values.setValidator((valueMap, status) -> {
			return validatePdb(valueMap, status);
		});
		values = askValues(TITLE, null, values);
		File pdbFile = values.getFile(PDB_PROMPT);
		String pdbFileName = pdbFile.getAbsolutePath();

		// creating a default output and asking again; PDB file should retain its current value
		//  from above
		String outputFileName = pdbFileName + ".MangledTypeNames.txt";
		values.defineFile(OUTPUT_PROMPT, new File(outputFileName));
		values.setValidator((valueMap, status) -> {
			return validatePdb(valueMap, status) && validateOutput(valueMap, status);
		});
		setReusePreviousChoices(false); // false for second pass... want our default output
		values = askValues(TITLE, null, values);
		pdbFile = values.getFile(PDB_PROMPT); // might have changed
		pdbFileName = pdbFile.getAbsolutePath(); // might have changed
		File dumpFile = values.getFile(OUTPUT_PROMPT);

		if (dumpFile.exists()) {
			if (!askYesNo("Confirm Overwrite", "Overwrite file: " + dumpFile.getName())) {
				println("Operation canceled");
				return;
			}
		}

		String message = "Processing PDB Dump of: " + pdbFileName;
		println(message);
		try (AbstractPdb pdb = PdbParser.parse(pdbFile, new PdbReaderOptions(), monitor)) {
			pdb.deserialize();
			FileWriter fileWriter = new FileWriter(dumpFile);
			BufferedWriter bufferedWriter = new BufferedWriter(fileWriter);
			dumpMangledTypeNames(pdb, bufferedWriter);
			bufferedWriter.close();
		}
		catch (IOException ioe) {
			println(ioe.getMessage());
			popup(ioe.getMessage());
		}
		message = "Results located in: " + dumpFile.getAbsoluteFile();
		println(message);
	}

	private void dumpMangledTypeNames(AbstractPdb pdb, Writer myWriter)
			throws CancelledException, IOException {
		TypeProgramInterface tpi = pdb.getTypeProgramInterface();
		if (tpi == null) {
			return;
		}
		for (int indexNumber = tpi.getTypeIndexMin(); indexNumber < tpi
				.getTypeIndexMaxExclusive(); indexNumber++) {
			monitor.checkCancelled();
			RecordNumber recordNumber = RecordNumber.typeRecordNumber(indexNumber);
			AbstractMsType msType = pdb.getTypeRecord(recordNumber);
			if (msType instanceof AbstractComplexMsType type) {
				String mangled = type.getMangledName();
				if (mangled != null) {
					myWriter.write(mangled);
					myWriter.write("\n");
				}
			}
		}
	}

}
