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
import java.io.IOException;
import java.util.Date;

import ghidra.app.services.*;
import ghidra.app.util.bin.format.pdb2.pdbreader.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.pdb.PdbProgramAttributes;
import ghidra.app.util.pdb.pdbapplicator.DefaultPdbApplicator;
import ghidra.app.util.pdb.pdbapplicator.PdbApplicatorOptions;
import ghidra.framework.*;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

// TODO:  Need to refactor packaging/classes/methods associated with "Features PDB" that are
//  taken and used here.  Need to make them available to both previous and this new analyzers
//   in their own special ways.  Make utility classes that are better split/organized.  Some
//   items are also used in other plugins/loaders (e.g, PdbException).
//  For example, we do not use the XML format here.  The code that was taken was strewn across
//  classes and should be reorganized.  For example, why is PdbParserNEW in control of the logic
//  of where a PDB file might be found?

/**
 * PDB Universal Reader/Analyzer.  Uses raw PDB files (not XML-converted PDBs). Attempts to
 * apply the information to a program.  It has Universal in the name to describe the fact that
 * it written in java, making it platform independent, unlike a previous PDB analyzer.
 */
public class PdbUniversalAnalyzer extends AbstractAnalyzer {

	// Developer turn on/off options that are in still in development.
	private static final boolean developerMode = false;

	//==============================================================================================
	static final String NAME = "PDB Universal";
	// TODO: decide which PDB Analyzer should be enabled by default for release
	static final boolean DEFAULT_ENABLEMENT = true;
	private static final String DESCRIPTION =
		"Platform-independent PDB analyzer (No XML support).\n" +
			"NOTE: still undergoing development, so options may change.\n" +
			"PDB Symbol Server searching is configured in Edit -> Symbol Server Config.\n";

	//==============================================================================================
	// Force-load a PDB file.
	private static final String OPTION_NAME_DO_FORCELOAD = "Do Force-Load";
	private static final String OPTION_DESCRIPTION_DO_FORCELOAD =
		"If checked, uses the 'Force Load' file without validation.";
	private boolean doForceLoad = false;

	// The file to force-load.
	private static final String OPTION_NAME_FORCELOAD_FILE = "Force-Load FilePath";
	private static final String OPTION_DESCRIPTION_FORCELOAD_FILE =
		"This file is force-loaded if the '" + OPTION_NAME_DO_FORCELOAD + "' option is checked";

	// Default symbol directory guessing
	private static final File DEFAULT_SYMBOLS_DIR =
		Platform.CURRENT_PLATFORM.getOperatingSystem() == OperatingSystem.WINDOWS
				? new File("C:\\Symbols")
				: new File(new File(System.getProperty("user.home")), "Symbols");

	private File DEFAULT_FORCE_LOAD_FILE = new File(DEFAULT_SYMBOLS_DIR, "sample.pdb");
	private File forceLoadFile;

	private boolean searchRemoteLocations = false;

	//==============================================================================================
	// Additional instance data
	//==============================================================================================
	private PdbReaderOptions pdbReaderOptions;
	private PdbApplicatorOptions pdbApplicatorOptions;

	// only try once per transaction due to extensive error logging which may get duplicated
	private long lastTransactionId = -1;

	//==============================================================================================
	//==============================================================================================
	public PdbUniversalAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		//setPrototype();
		setDefaultEnablement(DEFAULT_ENABLEMENT);
		setPriority(AnalysisPriority.FORMAT_ANALYSIS.after());
		setSupportsOneTimeAnalysis();

		pdbReaderOptions = new PdbReaderOptions();
		pdbApplicatorOptions = new PdbApplicatorOptions();
	}

	static boolean isEnabled(Program program) {
		Options analysisOptions = program.getOptions(Program.ANALYSIS_PROPERTIES);
		return analysisOptions.getBoolean(NAME, DEFAULT_ENABLEMENT);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		// Only run once per transaction - avoid message duplication
		long txId = program.getCurrentTransactionInfo().getID();
		if (txId == lastTransactionId) {
			return false;
		}
		lastTransactionId = txId;

		// Only run if restricted set corresponds to entire program
		if (!set.contains(program.getMemory())) {
			return false;
		}

// NOTE: Legacy PDB Analyzer currently yields to this analyzer if both are enabled
//		if (PdbAnalyzer.isEnabled(program)) {
//			log.appendMsg(getName(),
//				"Stopped: Cannot run with Legacy PDB Analyzer enabled");
//			return false;
//		}

		// TODO:
		// Work on use cases...
		// Code for checking if the PDB is already loaded (... assumes it was analyzed as well).
		//  Need different logic... perhaps we could have multiple PDBs loaded already and need
		//  to decide if any of those is the "correct" one or even look for another one.
		//  NOTE: if PDB previously applied the PDB load should be used instead of analyzer.
		// Probably still need to have a loader separate from the loader/analyzer, but then have
		//  the ability to analyze (apply) any given already-loaded PDB to the program.  A PDB
		//  loader should probably be able to load an optionally apply data types to its own
		//  category manager.  Question would be if/how we "might" try to resolve any of these
		//  against the "main" category data types.

		PdbProgramAttributes programAttributes = new PdbProgramAttributes(program);
		if (programAttributes.isPdbLoaded()) {
			Msg.info(this, "Skipping PDB analysis since it has previously run.");
			Msg.info(this, ">> Clear 'PDB Loaded' program property or use Load PDB action if " +
				"additional PDB processing required.");
			return true;
		}

		File pdbFile = null;
		if (doForceLoad && forceLoadFile != null) {
			if (!forceLoadFile.isFile()) {
				logFailure("Force-load PDB file does not exist: " + forceLoadFile, log);
				return false;
			}
			pdbFile = forceLoadFile;
		}
		else {
			pdbFile = PdbAnalyzerCommon.findPdb(this, program, searchRemoteLocations, monitor);
		}
		if (pdbFile == null) {
			// warnings have already been logged
			return false;
		}

		return doAnalysis(program, pdbFile, pdbReaderOptions, pdbApplicatorOptions, log, monitor);
	}

	/**
	 * Initializes and calls the methods of the PdbApplicator pertaining to the various phases
	 *  of PDB analysis.  These methods can be called via scheduled background commands set with
	 *  the appropriate analysis priorities to allow the work to be done at the appropriate time
	 *  amongst other analyzers.  The return PDB
	 * @param program the program to which the PDB is being applied
	 * @param pdbFile the PDB file to be applied
	 * @param pdbReaderOptions the PDB "reader" options to use
	 * @param pdbApplicatorOptions the PDB "applicator" options to use
	 * @param log the message log to which messages will be written
	 * @param monitor the task monitor
	 * @return {@code true} if the first phase of analysis has completed without error.  Follow-on
	 *  background commands will also have return values, which will include a {@code false} value
	 *  upon user cancellation during those phases.
	 * @throws CancelledException upon user cancellation
	 */
	public static boolean doAnalysis(Program program, File pdbFile,
			PdbReaderOptions pdbReaderOptions, PdbApplicatorOptions pdbApplicatorOptions,
			MessageLog log, TaskMonitor monitor) throws CancelledException {
		PdbLog.message(
			"================================================================================");
		PdbLog.message(new Date(System.currentTimeMillis()).toString() + "\n");
		PdbLog.message("Ghidra Version: " + Application.getApplicationVersion());
		PdbLog.message(NAME);
		PdbLog.message(DESCRIPTION);
		PdbLog.message("PDB Filename: " + pdbFile + "\n");

		try (AbstractPdb pdb = PdbParser.parse(pdbFile, pdbReaderOptions, monitor)) {
			monitor.setMessage("PDB: Parsing " + pdbFile + "...");
			pdb.deserialize();

			DefaultPdbApplicator applicator = new DefaultPdbApplicator(pdb, program,
				program.getDataTypeManager(), program.getImageBase(), pdbApplicatorOptions, log);
			applicator.applyDataTypesAndMainSymbolsAnalysis();

			AutoAnalysisManager aam = AutoAnalysisManager.getAnalysisManager(program);

			// TODO: Consider the various types of work we might want to do... they probably
			//  shouldn't all be the same priority.
			//   * function nested scopes, local/scope variables, static locals (might be in
			//     scopes).  Includes register/stack scopes of local/scoped variables
			//   * parameters
			//   * code source module/file/line numbers

			Msg.info(PdbUniversalAnalyzer.class,
				NAME + ": scheduling PDB Function Internals Analysis");
			// TODO: set this to appropriate priority (this is a guess for locals/params/scopes)
			// Initial thought on priority:  AnalysisPriority.FUNCTION_ANALYSIS.priority()
			// From meeting:
			//  * before/after parameter ID
			//  different statement:
			//  * run before stack reference analysis runs (maybe turn it that one off)
			// 902  Decompiler Parameter ID (DecompilerFunctionAnalyzer)
			// 903  Stack (StackVariableAnalyzer)
			aam.schedule(
				new ProcessPdbFunctionInternalsCommand(pdbFile, pdbReaderOptions,
					pdbApplicatorOptions, log),
				AnalysisPriority.DATA_TYPE_PROPOGATION.after().after().after().priority());

			// Following is intended to be the last PDB analysis background command
			aam.schedule(new PdbReportingBackgroundCommand(),
				AnalysisPriority.DATA_TYPE_PROPOGATION.after().after().after().after().priority());

		}
		catch (PdbException | IOException e) {
			log.appendMsg(NAME, "Issue processing PDB file:  " + pdbFile + ":\n   " + e.toString());
			return false;
		}

		return true;
	}

	@Override
	public boolean canAnalyze(Program program) {
		return PdbAnalyzerCommon.canAnalyzeProgram(program);
	}

	@Override
	public void registerOptions(Options options, Program program) {

		// PDB file location information
		if (developerMode) {
			options.registerOption(OPTION_NAME_DO_FORCELOAD, Boolean.FALSE, null,
				OPTION_DESCRIPTION_DO_FORCELOAD);
			options.registerOption(OPTION_NAME_FORCELOAD_FILE, OptionType.FILE_TYPE,
				DEFAULT_FORCE_LOAD_FILE, null, OPTION_DESCRIPTION_FORCELOAD_FILE);
		}
		options.registerOption(PdbAnalyzerCommon.OPTION_NAME_SEARCH_REMOTE_LOCATIONS,
			searchRemoteLocations, null,
			PdbAnalyzerCommon.OPTION_DESCRIPTION_SEARCH_REMOTE_LOCATIONS);

		pdbReaderOptions.registerOptions(options);
		pdbApplicatorOptions.registerAnalyzerOptions(options);

		pdbReaderOptions.loadOptions(options);
		pdbApplicatorOptions.loadAnalyzerOptions(options);
	}

	@Override
	public void optionsChanged(Options options, Program program) {

		if (developerMode) {
			doForceLoad = options.getBoolean(OPTION_NAME_DO_FORCELOAD, doForceLoad);
			forceLoadFile = options.getFile(OPTION_NAME_FORCELOAD_FILE, forceLoadFile);
		}

		searchRemoteLocations = options.getBoolean(
			PdbAnalyzerCommon.OPTION_NAME_SEARCH_REMOTE_LOCATIONS, searchRemoteLocations);

		pdbReaderOptions.loadOptions(options);
		pdbApplicatorOptions.loadAnalyzerOptions(options);
	}

	//==============================================================================================

	private void logFailure(String msg, MessageLog log) {
		log.appendMsg(getName(), msg);
		log.appendMsg(getName(), "Skipping PDB processing");
		log.setStatus(msg);
	}

	/**
	 * Sets the PDB file that will be used by the analyzer when it is next invoked
	 * on the specified program.
	 * <p>
	 * Normally the analyzer would locate the PDB file on its own, but if a
	 * headless script wishes to override the analyzer's behavior, it can
	 * use this method to specify a file.
	 *
	 * @param program the program
	 * @param pdbFile the PDB file
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

	//==============================================================================================
	/**
	 * A background command that performs additional PDB analysis after after other analysis
	 *  works on function internals.  The first phase must have been run, as it reads the PDB
	 *  and processes data types, retaining the information needed for this step.  Not what all
	 *  processing we will do here and whether we might need additional commands like this one.
	 *    For now, we want this one for doing global/module symbol function processing to
	 *    set up locals/params/scopes, but some of the data encountered could be for static
	 *    local variables and other things that might make sense to process in the first phase
	 *    (for now, they will be in the second phase).
	 */
	private static class ProcessPdbFunctionInternalsCommand extends BackgroundCommand<Program> {

		File pdbFile;
		private PdbReaderOptions pdbReaderOptions;
		private PdbApplicatorOptions pdbApplicatorOptions;
		private MessageLog log;

		public ProcessPdbFunctionInternalsCommand(File pdbFile, PdbReaderOptions pdbReaderOptions,
				PdbApplicatorOptions pdbApplicatorOptions, MessageLog log) {
			super("PDB Universal Function Internals", false, false, false);
			this.pdbFile = pdbFile;
			this.pdbReaderOptions = pdbReaderOptions;
			this.pdbApplicatorOptions = pdbApplicatorOptions;
			this.log = log;
		}

		@Override
		public boolean applyTo(Program program, TaskMonitor monitor) {
			try (AbstractPdb pdb = PdbParser.parse(pdbFile, pdbReaderOptions, monitor)) {
				monitor.setMessage("PDB: Parsing " + pdbFile + "...");
				pdb.deserialize();
				DefaultPdbApplicator applicator =
					new DefaultPdbApplicator(pdb, program, program.getDataTypeManager(),
						program.getImageBase(), pdbApplicatorOptions, log);
				applicator.applyFunctionInternalsAnalysis();
				return true;
			}
			catch (PdbException | IOException e) {
				log.appendMsg(getName(),
					"Issue processing PDB file:  " + pdbFile + ":\n   " + e.toString());
				return false;
			}
			catch (CancelledException e) {
				return false;
			}
		}
	}

	/**
	 * A background command that performs final PDB analysis reporting.
	 */
	private static class PdbReportingBackgroundCommand extends BackgroundCommand<Program> {

		public PdbReportingBackgroundCommand() {
			super("PDB Universal Reporting", false, false, false);
		}

		@Override
		public boolean applyTo(Program program, TaskMonitor monitor) {
			try {
				DefaultPdbApplicator.applyAnalysisReporting(program);
				return true;
			}
			catch (CancelledException e) {
				return false;
			}
		}

	}

}
