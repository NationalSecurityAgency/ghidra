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
// Apply PDB information from AbstractPdb to a dummy program -- for PDB developer use.
//
//@category PDB

import java.io.File;
import java.io.IOException;

import ghidra.app.script.GhidraScript;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.bin.format.pdb2.pdbreader.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.pdb.pdbapplicator.DefaultPdbApplicator;
import ghidra.app.util.pdb.pdbapplicator.PdbApplicatorOptions;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageService;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.mem.Memory;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.Msg;

public class PdbDeveloperApplyDummyScript extends GhidraScript {

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

		MessageLog log = new MessageLog();

		// Can do more with various reader and applicator options here
		PdbReaderOptions pdbReaderOptions = new PdbReaderOptions();
		PdbApplicatorOptions pdbApplicatorOptions = new PdbApplicatorOptions();

		LanguageService ls = DefaultLanguageService.getLanguageService();
		Processor processor_x86 = Processor.findOrPossiblyCreateProcessor("x86");
		Language x86 = ls.getDefaultLanguage(processor_x86);
		ProgramDB program = new ProgramDB("Test", x86, x86.getDefaultCompilerSpec(), this);

		ProgramManager programManager = state.getTool().getService(ProgramManager.class);
		programManager.openProgram(program);

		int txID = program.startTransaction("ApplyPDB");
		Memory memory = program.getMemory();
		memory.createUninitializedBlock(pdbFileName, program.getImageBase(),
			Memory.MAX_BLOCK_SIZE / 16, false);

		try (AbstractPdb pdb = PdbParser.parse(pdbFile.getPath(), pdbReaderOptions, monitor)) {
			monitor.setMessage("PDB: Parsing " + pdbFile + "...");
			pdb.deserialize();
			DefaultPdbApplicator applicator = new DefaultPdbApplicator(pdb);
			applicator.applyTo(program, program.getDataTypeManager(), program.getImageBase(),
				pdbApplicatorOptions, log);
		}
		catch (PdbException | IOException e) {
			log.appendMsg(getClass().getName(),
				"Issue processing PDB file:  " + pdbFile + ":\n   " + e.toString());
			return;
		}
		finally {
			program.endTransaction(txID, true);
			program.release(this);
		}
	}

}
