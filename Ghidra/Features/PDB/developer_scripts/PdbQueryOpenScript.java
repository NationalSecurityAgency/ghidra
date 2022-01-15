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
// Opens a PDB for the PdbQuery package.
//
//@category PDB

import java.io.File;

import org.apache.commons.lang3.StringUtils;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbIdentifiers;
import pdb.PdbUtils;
import pdbquery.PdbFactory;

public class PdbQueryOpenScript extends GhidraScript {

	@Override
	protected void run() throws Exception {
		File pdbFile = askFile("Choose a PDB file", "OK");
		if (pdbFile == null) {
			println("Aborting: no file chosen.");
			return;
		}

		String pdbFilename = pdbFile.getAbsolutePath();

		if (!pdbFile.exists()) {
			println("Aborting: " + pdbFilename + " is not a valid file.");
			return;
		}
		if (!StringUtils.endsWithIgnoreCase(pdbFilename, ".pdb")) {
			println("Aborting: filename missing .pdb extension: " + pdbFilename);
			return;
		}

		PdbIdentifiers identifiers = PdbUtils.getPdbIdentifiers(pdbFile, monitor);

		String fileAndIdentifiers =
			pdbFilename + ", " + identifiers + " (File, GUID/Signature, Age, Version, Processor)";
		if (!askYesNo("Confirm Load", fileAndIdentifiers)) {
			println("Aborting: " + pdbFilename + " not confirmed.");
			return;
		}

		PdbFactory.openPdb(this, pdbFilename, monitor);
		println("PDB Opened: " + fileAndIdentifiers);
	}
}
