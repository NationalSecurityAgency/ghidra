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
import ghidra.app.util.bin.format.pdb.PdbException;
import ghidra.app.util.bin.format.pdb.PdbParser;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Finds and applies PDB debug information to the given Windows executable.
 */
public class PdbAnalyzer extends AbstractAnalyzer {
	static final String NAME = "PDB MSDIA";
	static final boolean DEFAULT_ENABLEMENT = !PdbUniversalAnalyzer.DEFAULT_ENABLEMENT;
	private static final String DESCRIPTION =
		"PDB Analyzer.\n" +
			"Requires MS DIA-SDK for raw PDB processing (Windows only).\n" +
			"Also supports pre-processed XML files.\n" +
			"PDB Symbol Server searching is configured in Edit -> Symbol Server Config.\n";

	private static final String ERROR_TITLE = "Error in PDB Analyzer";

	private boolean searchRemoteLocations = false;

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

		File pdbFile = PdbAnalyzerCommon.findPdb(this, program, searchRemoteLocations, monitor);
		if (pdbFile == null) {
			// warnings have already been logged
			return false;
		}

		AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
		return parsePdb(pdbFile, program, mgr, monitor, log);
	}

	boolean parsePdb(File pdb, Program program, AutoAnalysisManager mgr, TaskMonitor monitor,
			MessageLog log) {
		DataTypeManagerService dataTypeManagerService = mgr.getDataTypeManagerService();
		PdbParser parser =
			new PdbParser(pdb, program, dataTypeManagerService, true, false, monitor);

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
		return PdbAnalyzerCommon.canAnalyzeProgram(program);
		//return PeLoader.PE_NAME.equals(program.getExecutableFormat());
	}

	@Override
	public void registerOptions(Options options, Program program) {

		options.registerOption(PdbAnalyzerCommon.OPTION_NAME_SEARCH_REMOTE_LOCATIONS,
			searchRemoteLocations, null,
			PdbAnalyzerCommon.OPTION_DESCRIPTION_SEARCH_REMOTE_LOCATIONS);
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		searchRemoteLocations = options.getBoolean(
			PdbAnalyzerCommon.OPTION_NAME_SEARCH_REMOTE_LOCATIONS, searchRemoteLocations);
	}

	/**
	 * Sets the PDB file that will be used by the analyzer when it is next invoked
	 * on the specified program.
	 * <p>
	 * Normally the analyzer would locate the PDB file on its own, but if a
	 * headless script wishes to override the analyzer's behaivor, it can
	 * use this method to specify a file.
	 * 
	 * @param program {@link Program}
	 * @param pdbFile the pdb file
	 */
	public static void setPdbFileOption(Program program, File pdbFile) {
		PdbAnalyzerCommon.setPdbFileOption(NAME, program, pdbFile);
	}

	/**
	 * Sets the "allow remote" option that will be used by the analyzer when it is next invoked
	 * on the specified program.
	 * <p>
	 * Normally when the analyzer attempts to locate a matching PDB file it
	 * will default to NOT searching remote symbol servers.  A headless script could
	 * use this method to allow the analyzer to search remote symbol servers.
	 * 
	 * @param program {@link Program}
	 * @param allowRemote boolean flag, true means analyzer can search remote symbol
	 * servers
	 */
	public static void setAllowRemoteOption(Program program, boolean allowRemote) {
		PdbAnalyzerCommon.setAllowRemoteOption(NAME, program, allowRemote);
	}
}
