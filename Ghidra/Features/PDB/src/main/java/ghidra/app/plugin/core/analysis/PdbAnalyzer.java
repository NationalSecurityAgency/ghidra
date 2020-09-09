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
package ghidra.app.plugin.core.analysis;

import java.io.File;

import ghidra.app.services.*;
import ghidra.app.util.bin.format.pdb.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.PeLoader;
import ghidra.framework.options.Options;
import ghidra.framework.preferences.Preferences;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Finds and applies PDB debug information to the given Windows executable.
 */
public class PdbAnalyzer extends AbstractAnalyzer {
	private static final String NAME = "PDB";
	private static final String DESCRIPTION = "Automatically loads a PDB file if found.";

	private static final String ERROR_TITLE = "Error in PDB Analyzer";

	private static final String SYMBOLPATH_OPTION_NAME = "Symbol Repository Path";
	private static final String SYMBOLPATH_OPTION_DESCRIPTION =
		"Directory path to root of Microsoft Symbol Repository Directory";
	private static final String SYMBOLPATH_OPTION_DEFAULT_VALUE = "C:\\Symbols";

	private String symbolsRepositoryPath = SYMBOLPATH_OPTION_DEFAULT_VALUE;

	//==============================================================================================
	// Include the PE-Header-Specified PDB path for searching for appropriate PDB file.
	private static final String OPTION_NAME_INCLUDE_PE_PDB_PATH =
		"Unsafe: Include PE PDB Path in PDB Search";
	private static final String OPTION_DESCRIPTION_INCLUDE_PE_PDB_PATH =
		"If checked, specifically searching for PDB in PE-Header-Specified Location.";

	private boolean includePeSpecifiedPdbPath = false;

	//==============================================================================================
	public PdbAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setDefaultEnablement(true);
		setPriority(AnalysisPriority.FORMAT_ANALYSIS.after());
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) {

		if (PdbParser.isAlreadyLoaded(program)) {
			return true;
		}

		File pdb = lookForPdb(program, includePeSpecifiedPdbPath, log);

		if (pdb == null) {
			return false;
		}
		Msg.info(this, getClass().getSimpleName() + " configured to use: " + pdb.getAbsolutePath());

		AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
		return parsePdb(pdb, program, mgr, monitor, log);
	}

	private static class PdbMissingState implements AnalysisState {
		// object existence indicates missing PDB has already been reported
	}

	File lookForPdb(Program program, boolean includePeSpecifiedPdbPath, MessageLog log) {
		String message = "";
		File pdb;

		try {

			pdb = PdbParser.findPDB(program, includePeSpecifiedPdbPath, symbolsRepositoryPath);

			if (pdb == null) {

				PdbMissingState missingState =
					AnalysisStateInfo.getAnalysisState(program, PdbMissingState.class);
				if (missingState != null) {
					return null; // already notified user
				}
				AnalysisStateInfo.putAnalysisState(program, new PdbMissingState());

				String pdbName = program.getOptions(Program.PROGRAM_INFO).getString(
					PdbParserConstants.PDB_FILE, (String) null);
				if (pdbName == null) {
					message = "Program has no associated PDB file.";
				}
				else {
					message = "Unable to locate PDB file \"" + pdbName + "\" with matching GUID.";
				}
				if (SystemUtilities.isInHeadlessMode()) {
					message += "\n Use a script to set the PDB file location. I.e.,\n" +
						"    setAnalysisOption(currentProgram, \"PDB.Symbol Repository Path\", \"/path/to/pdb/folder\");\n" +
						" This must be done using a pre-script (prior to analysis).";
				}
				else {
					message += "\n You may set the PDB \"Symbol Repository Path\"" +
						"\n using \"Edit->Options for [program]\" prior to analysis." +
						"\nIt is important that a PDB is used during initial analysis " +
						"\nif available.";
				}
			}

			return pdb;
		}
		catch (PdbException pe) {
			message += pe.getMessage();
		}
		finally {
			if (message.length() > 0) {
				log.appendMsg(getName(), message);
				log.setStatus(message);
			}
		}

		return null;
	}

	boolean parsePdb(File pdb, Program program, AutoAnalysisManager mgr, TaskMonitor monitor,
			MessageLog log) {
		DataTypeManagerService dataTypeManagerService = mgr.getDataTypeManagerService();
		PdbParser parser = new PdbParser(pdb, program, dataTypeManagerService, true, monitor);

		String message;

		try {
			parser.parse();
			parser.openDataTypeArchives();
			parser.applyTo(log);
			return true;
		}
		catch (PdbException e) {
			message = e.getMessage();
			log.appendMsg(getName(), message);
			log.setStatus(message);
			return false;
		}
		catch (CancelledException e) {
			return false;
		}
		catch (Exception e) {
			String msg = e.getMessage();
			if (msg == null) {
				msg = e.toString();
			}
			Msg.showError(this, null, ERROR_TITLE, msg, e);
			return false;
		}

	}

	@Override
	public boolean canAnalyze(Program program) {
		return PeLoader.PE_NAME.equals(program.getExecutableFormat());
	}

	@Override
	public void registerOptions(Options options, Program program) {

		String pdbStorageLocation =
			Preferences.getProperty(PdbParser.PDB_STORAGE_PROPERTY, null, true);
		if (pdbStorageLocation != null) {
			File pdbDirectory = new File(pdbStorageLocation);

			if (pdbDirectory.isDirectory()) {
				options.registerOption(SYMBOLPATH_OPTION_NAME, pdbStorageLocation, null,
					SYMBOLPATH_OPTION_DESCRIPTION);
			}
		}
		else {
			options.registerOption(SYMBOLPATH_OPTION_NAME, SYMBOLPATH_OPTION_DEFAULT_VALUE, null,
				SYMBOLPATH_OPTION_DESCRIPTION);
		}

		options.registerOption(OPTION_NAME_INCLUDE_PE_PDB_PATH, includePeSpecifiedPdbPath, null,
			OPTION_DESCRIPTION_INCLUDE_PE_PDB_PATH);
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		String symbolPath =
			options.getString(SYMBOLPATH_OPTION_NAME, SYMBOLPATH_OPTION_DEFAULT_VALUE);
		setSymbolsRepositoryPath(symbolPath);

		Preferences.setProperty(PdbParser.PDB_STORAGE_PROPERTY, symbolPath);
		Preferences.store();

		includePeSpecifiedPdbPath =
			options.getBoolean(OPTION_NAME_INCLUDE_PE_PDB_PATH, includePeSpecifiedPdbPath);
	}

	public void setSymbolsRepositoryPath(String symbolPath) {
		symbolsRepositoryPath = symbolPath;
	}

}
