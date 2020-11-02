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

import org.apache.commons.lang3.StringUtils;

import ghidra.app.services.*;
import ghidra.app.util.bin.format.pdb.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.PeLoader;
import ghidra.app.util.pdb.PdbLocator;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;
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
	static final String NAME = "PDB MSDIA";
	static final boolean DEFAULT_ENABLEMENT = !PdbUniversalAnalyzer.DEFAULT_ENABLEMENT;
	private static final String DESCRIPTION =
		"PDB Analyzer.\n" + "Requires MS DIA-SDK for raw PDB processing (Windows only).\n" +
			"Also supports pre-processed XML files.";

	private static final String ERROR_TITLE = "Error in PDB Analyzer";

	private static final String SYMBOLPATH_OPTION_NAME = "Symbol Repository Path";
	private static final String SYMBOLPATH_OPTION_DESCRIPTION =
		"Directory path to root of Microsoft Symbol Repository Directory";

	private File symbolsRepositoryDir = PdbLocator.DEFAULT_SYMBOLS_DIR;

	//==============================================================================================
	// Include the PE-Header-Specified PDB path for searching for appropriate PDB file.
	private static final String OPTION_NAME_INCLUDE_PE_PDB_PATH =
		"Unsafe: Include PE PDB Path in PDB Search";
	private static final String OPTION_DESCRIPTION_INCLUDE_PE_PDB_PATH =
		"If checked, specifically searching for PDB in PE-Header-Specified Location.";

	private boolean includePeSpecifiedPdbPath = false;

	// only try once per transaction due to extensive error logging which may get duplicated
	private long lastTransactionId = -1;

	//==============================================================================================
	public PdbAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setDefaultEnablement(DEFAULT_ENABLEMENT);
		setPriority(AnalysisPriority.FORMAT_ANALYSIS.after());
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) {

		// Only run once per transaction - avoid message duplication
		long txId = program.getCurrentTransaction().getID();
		if (txId == lastTransactionId) {
			return false;
		}
		lastTransactionId = txId;

		// Only run if restricted set corresponds to entire program
		if (!set.contains(program.getMemory())) {
			return false;
		}

		if (PdbParser.isAlreadyLoaded(program)) {
			if (!PdbUniversalAnalyzer.isEnabled(program)) { // yield to other analyzer complaining
				Msg.info(this, "Skipping PDB analysis since it has previouslu run.");
				Msg.info(this, ">> Clear 'PDB Loaded' program property or use Load PDB action if " +
					"additional PDB processing required.");
			}
			return true;
		}

		if (PdbUniversalAnalyzer.isEnabled(program)) {
			log.appendMsg(getName(),
				"Stopped: Cannot run with " + PdbUniversalAnalyzer.NAME + " Analyzer enabled");
			return false;
		}

		File pdb = lookForPdb(program, log);

		if (pdb == null) {
			Msg.info(this, "PDB analyzer failed to locate PDB file");
			return false;
		}
		Msg.info(this, "PDB analyzer parsing file: " + pdb.getAbsolutePath());

		AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
		return parsePdb(pdb, program, mgr, monitor, log);
	}

	private static class PdbMissingState implements AnalysisState {
		// object existence indicates missing PDB has already been reported
	}

	File lookForPdb(Program program, MessageLog log) {
		String message = "";
		File pdb;

		try {

			pdb = PdbParser.findPDB(program, includePeSpecifiedPdbPath, symbolsRepositoryDir);

			if (pdb == null) {

				PdbMissingState missingState =
					AnalysisStateInfo.getAnalysisState(program, PdbMissingState.class);
				if (missingState != null) {
					return null; // already notified user
				}
				AnalysisStateInfo.putAnalysisState(program, new PdbMissingState());

				String pdbName = program.getOptions(Program.PROGRAM_INFO).getString(
					PdbParserConstants.PDB_FILE, (String) null);
				if (StringUtils.isBlank(pdbName)) {
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
		finally {
			if (message.length() > 0) {
				log.appendMsg(getName(), message);
				log.setStatus(message);
			}
		}

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

		symbolsRepositoryDir = PdbLocator.getDefaultPdbSymbolsDir();

		options.registerOption(SYMBOLPATH_OPTION_NAME, OptionType.FILE_TYPE, symbolsRepositoryDir,
			null, SYMBOLPATH_OPTION_DESCRIPTION);

		options.registerOption(OPTION_NAME_INCLUDE_PE_PDB_PATH, includePeSpecifiedPdbPath, null,
			OPTION_DESCRIPTION_INCLUDE_PE_PDB_PATH);
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		
		File symbolsDir = options.getFile(SYMBOLPATH_OPTION_NAME, symbolsRepositoryDir);
		if (!symbolsDir.equals(symbolsRepositoryDir)) {
			symbolsRepositoryDir = symbolsDir;
			PdbLocator.setDefaultPdbSymbolsDir(symbolsDir);
		}

		includePeSpecifiedPdbPath =
			options.getBoolean(OPTION_NAME_INCLUDE_PE_PDB_PATH, includePeSpecifiedPdbPath);
	}

}
