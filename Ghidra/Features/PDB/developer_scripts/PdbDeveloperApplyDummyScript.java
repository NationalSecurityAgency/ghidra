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

import db.Transaction;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.bin.format.pdb2.pdbreader.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.pdb.pdbapplicator.DefaultPdbApplicator;
import ghidra.app.util.pdb.pdbapplicator.PdbApplicatorOptions;
import ghidra.features.base.values.GhidraValuesMap;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageService;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.mem.Memory;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.MessageType;

public class PdbDeveloperApplyDummyScript extends GhidraScript {

	private static final String PDB_PROMPT = "Choose a PDB file";
	private static final String IMAGE_BASE_PROMPT = "Image Base";

	@Override
	protected void run() throws Exception {

		LanguageService ls = DefaultLanguageService.getLanguageService();
		Processor processor_x86 = Processor.findOrPossiblyCreateProcessor("x86");
		Language x86 = ls.getDefaultLanguage(processor_x86);
		ProgramDB program = new ProgramDB("Test", x86, x86.getDefaultCompilerSpec(), this);
		Address imageBase =
			program.getAddressFactory().getDefaultAddressSpace().getAddress(0x400000L);

		GhidraValuesMap values = new GhidraValuesMap();

		values.defineFile(PDB_PROMPT, null);
		values.defineAddress(IMAGE_BASE_PROMPT, imageBase, program);

		// Validator for values
		values.setValidator((valueMap, status) -> {
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
		});

		// asks the script to show a dialog where the user can give values for all the items
		// in the ValuesMap.

		values = askValues("Enter Values", null, values);

		File pdbFile = values.getFile(PDB_PROMPT);
		String pdbFileName = pdbFile.getAbsolutePath();
		imageBase = values.getAddress(IMAGE_BASE_PROMPT);

		MessageLog log = new MessageLog();

		// Can do more with various reader and applicator options here
		PdbReaderOptions pdbReaderOptions = new PdbReaderOptions();
		PdbApplicatorOptions pdbApplicatorOptions = new PdbApplicatorOptions();

		try (Transaction tx = program.openTransaction("Set Image Base")) {
			program.setImageBase(imageBase, true);
		}

		ProgramManager programManager = state.getTool().getService(ProgramManager.class);
		programManager.openProgram(program);

		int txID = program.startTransaction("ApplyPDB");
		Memory memory = program.getMemory();
		memory.createUninitializedBlock(pdbFileName, program.getImageBase(),
			Memory.MAX_BLOCK_SIZE / 16, false);

		try (AbstractPdb pdb = PdbParser.parse(pdbFile, pdbReaderOptions, monitor)) {
			monitor.setMessage("PDB: Parsing " + pdbFile + "...");
			pdb.deserialize();
			DefaultPdbApplicator applicator = new DefaultPdbApplicator(pdb, program,
				program.getDataTypeManager(), program.getImageBase(), pdbApplicatorOptions, log);
			applicator.applyNoAnalysisState();
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
