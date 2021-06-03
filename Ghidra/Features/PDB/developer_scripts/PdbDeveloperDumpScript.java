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
// Dump PDB information from AbstractPdb for PDB developer use.
//
//@category PDB

import java.io.*;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.format.pdb2.pdbreader.*;
import ghidra.util.Msg;

public class PdbDeveloperDumpScript extends GhidraScript {

	@Override
	protected void run() throws Exception {
		File pdbFile = askFile("Choose a PDB file", "OK");
		if (pdbFile == null) {
			Msg.info(this, "Canceled execution due to no input file");
			return;
		}
		if (!pdbFile.exists()) {
			String message = pdbFile.getAbsolutePath() + " is not a valid file.";
			Msg.info(this, message);
			popup(message);
			return;
		}
		String pdbFileName = pdbFile.getAbsolutePath();
		if (!pdbFileName.endsWith(".pdb") && !pdbFileName.endsWith(".PDB")) {
			String message = "Aborting: Expected input file to have extension of type .pdb (got '" +
				pdbFileName + "').";
			Msg.info(this, message);
			popup(message);
			return;
		}

		File dumpFile = askFile("Choose an output file", "OK");
		if (dumpFile == null) {
			Msg.info(this, "Canceled execution due to no output file");
			return;
		}
		if (dumpFile.exists()) {
			if (!askYesNo("Confirm Overwrite", "Overwrite file: " + dumpFile.getName())) {
				Msg.info(this, "Operation canceled");
				return;
			}
		}

		String message = "Processing PDB Dump of: " + pdbFileName;
		monitor.setMessage(message);
		Msg.info(this, message);
		try (AbstractPdb pdb = PdbParser.parse(pdbFileName, new PdbReaderOptions(), monitor)) {
			pdb.deserialize(monitor);
			FileWriter fileWriter = new FileWriter(dumpFile);
			BufferedWriter bufferedWriter = new BufferedWriter(fileWriter);
			outputHeaderMessage(bufferedWriter, pdbFileName);
			pdb.dumpDirectory(bufferedWriter);
			pdb.dumpSubStreams(bufferedWriter);
			bufferedWriter.close();
		}
		catch (IOException ioe) {
			Msg.info(this, ioe.getMessage());
			popup(ioe.getMessage());
		}
		message = "Results located in: " + dumpFile.getAbsoluteFile();
		monitor.setMessage(message);
		Msg.info(this, message);
	}

	private void outputHeaderMessage(BufferedWriter bufferedWriter, String name) throws Exception {
		bufferedWriter.append(getClass().getSimpleName() + " dump of: " + name +
			"\nWARNING: FORMAT SUBJECT TO CHANGE WITHOUT NOTICE--DO NOT PARSE\n\n");
	}

}
