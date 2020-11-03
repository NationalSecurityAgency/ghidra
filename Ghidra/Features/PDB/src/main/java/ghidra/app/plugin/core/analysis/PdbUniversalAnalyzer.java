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

import org.apache.commons.lang3.StringUtils;

import ghidra.app.services.*;
import ghidra.app.util.bin.format.pdb2.pdbreader.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.PeLoader;
import ghidra.app.util.pdb.PdbLocator;
import ghidra.app.util.pdb.PdbProgramAttributes;
import ghidra.app.util.pdb.pdbapplicator.*;
import ghidra.framework.Application;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.CharsetInfo;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
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
			"NOTE: still undergoing development, so options may change.";

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
	private File DEFAULT_FORCE_LOAD_FILE = new File(PdbLocator.DEFAULT_SYMBOLS_DIR, "sample.pdb");
	private File forceLoadFile;

	// Symbol Repository Path.
	private static final String OPTION_NAME_SYMBOLPATH = "Symbol Repository Path";
	private static final String OPTION_DESCRIPTION_SYMBOLPATH =
		"Directory path to root of Microsoft Symbol Repository Directory";
	private File symbolsRepositoryDir;

	// Include the PE-Header-Specified PDB path for searching for appropriate PDB file.
	private static final String OPTION_NAME_INCLUDE_PE_PDB_PATH =
		"Unsafe: Include PE PDB Path in PDB Search";
	private static final String OPTION_DESCRIPTION_INCLUDE_PE_PDB_PATH =
		"If checked, specifically searching for PDB in PE-Header-Specified Location.";
	private boolean includePeSpecifiedPdbPath = false;

	//==============================================================================================
	// Logging options
	//==============================================================================================
	// Perform logging of PDB information for debugging/development.
	//  NOTE: This logging mechanism is not intended to live the full life of this tool, but to
	//  aid in getting feedback from the field during its early development.
	private static final String OPTION_NAME_PDB_READER_ANALYZER_LOGGING =
		"[PDB Reader/Analyzer Debug Logging]";
	private static final String OPTION_DESCRIPTION_PDB_READER_ANALYZER_LOGGING =
		"If checked, logs information to the pdb.analyzer.log file for debug/development.";
	private boolean pdbLogging = false;

	//==============================================================================================
	// PdbReader options
	//==============================================================================================
	// Sets the one-byte Charset to be used for PDB processing.
	//  NOTE: This "Option" is not intended as a permanent part of this analyzer.  Should be
	//  replaced by target-specific Charset.
	private static final String OPTION_NAME_ONE_BYTE_CHARSET_NAME = "PDB One-Byte Charset Name";
	private static final String OPTION_DESCRIPTION_ONE_BYTE_CHARSET_NAME =
		"Charset used for processing of one-byte (or multi) encoded Strings: " +
			PdbReaderOptions.getOneByteCharsetNames();
	private String oneByteCharsetName = CharsetInfo.UTF8;

	// Sets the wchar_t Charset to be used for PDB processing.
	//  NOTE: This "Option" is not intended as a permanent part of this analyzer.  Should be
	//  replaced by target-program-specific Charset.
	private static final String OPTION_NAME_WCHAR_CHARSET_NAME = "PDB Wchar_t Charset Name";
	private static final String OPTION_DESCRIPTION_WCHAR_CHARSET_NAME =
		"Charset used for processing of wchar_t encoded Strings: " +
			PdbReaderOptions.getTwoByteCharsetNames();
	private String wideCharCharsetName = CharsetInfo.UTF16;

	//==============================================================================================
	// PdbApplicator options
	//==============================================================================================
	// Applicator Restrictions.
	private static final String OPTION_NAME_PROCESSING_RESTRICTIONS = "Processing Restrictions";
	private static final String OPTION_DESCRIPTION_PROCESSING_RESTRICTIONS =
		"Restrictions on applicator processing.";
	private static PdbApplicatorRestrictions restrictions;

	// Apply Code Block Comments.
	private static final String OPTION_NAME_APPLY_CODE_SCOPE_BLOCK_COMMENTS =
		"Apply Code Scope Block Comments";
	private static final String OPTION_DESCRIPTION_APPLY_CODE_SCOPE_BLOCK_COMMENTS =
		"If checked, pre/post-comments will be applied when code scope blocks are specified.";
	private boolean applyCodeScopeBlockComments;

	// Apply Instruction Labels information.
	private static final String OPTION_NAME_APPLY_INSTRUCTION_LABELS = "Apply Instruction Labels";
	private static final String OPTION_DESCRIPTION_APPLY_INSTRUCTION_LABELS =
		"If checked, labels associated with instructions will be applied.";
	private boolean applyInstructionLabels;

	// Attempt to map address using existing mangled symbols.
	private static final String OPTION_NAME_ADDRESS_REMAP = "Address Remap Using Existing Symbols";
	private static final String OPTION_DESCRIPTION_ADDRESS_REMAP =
		"If checked, attempts to remap address to those matching existing public symbols.";
	private boolean remapAddressUsingExistingPublicMangledSymbols;

	// Allow a mangled symbol to be demoted from being a primary symbol if another symbol and
	//  associated explicit data type will be laid down at the location.  This option exists
	//  because we expect the PDB explicit data type will be more accurate than trying to
	//  have the demangler lay down the data type.
	private static final String OPTION_NAME_ALLOW_DEMOTE_MANGLED_PRIMARY =
		"Allow demote mangled symbol from primary";
	private static final String OPTION_DESCRIPTION_ALLOW_DEMOTE_MANGLED_PRIMARY =
		"If checked, allows a mangled symbol to be demoted from primary if a possibly " +
			"better data type can be laid down with a nonmangled symbol.";
	private boolean allowDemotePrimaryMangledSymbol;

	// Apply Function Variables
	private static final String OPTION_NAME_APPLY_FUNCTION_VARIABLES = "Apply Function Variables";
	private static final String OPTION_DESCRIPTION_APPLY_FUNCTION_VARIABLES =
		"If checked, attempts to apply function parameters and local variables for program functions.";
	private boolean applyFunctionVariables;

	// Sets the composite layout.
	// Legacy
	//   - similar to existing DIA-based PDB Analyzer, only placing current composite direct
	//     members (none from parent classes.
	// Warning: the remaining experimental layout choices may not be kept and are not guaranteed
	//          to result in data types that will be compatible with future Ghidra releases: 
	// Complex with Basic Fallback
	//   - Performs Complex layout, but if the current class has no parent classes, it will not
	//     encapsulate the current class's 'direct' members.
	// Simple
	//   - Performs Complex layout, except in rare instances where , so in most cases is the same
	//     as 'Complex with Basic Fallback' layout.
	// Complex
	//   - Puts all current class members and 'direct' parents' 'direct' components into an
	//     encapsulating 'direct' container
	private static final String OPTION_NAME_COMPOSITE_LAYOUT = "Composite Layout Choice";
	private static final String OPTION_DESCRIPTION_COMPOSITE_LAYOUT =
		"Legacy layout like original PDB Analyzer. Warning: other choices have no compatibility" +
			" guarantee with future Ghidra releases or minor PDB Analyzer changes";
	private ObjectOrientedClassLayout compositeLayout;

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
		long txId = program.getCurrentTransaction().getID();
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
			Msg.info(this, "Skipping PDB analysis since it has previouslu run.");
			Msg.info(this,
				">> Clear 'PDB Loaded' program property or use Load PDB action if " +
					"additional PDB processing required.");
			return true;
		}

		if (failMissingFilename(programAttributes, log) ||
			failMissingAttributes(programAttributes, log)) {
			return true;
		}

		setPdbLogging(log);

		String pdbFilename;
		if (doForceLoad) {
			if (!confirmFile(forceLoadFile)) {
				logFailure("Force-load PDB file does not exist: " + forceLoadFile, log);
				return false;
			}
			pdbFilename = forceLoadFile.getAbsolutePath();
		}
		else {
			PdbLocator locator = new PdbLocator(symbolsRepositoryDir);
			pdbFilename =
				locator.findPdb(program, programAttributes, !SystemUtilities.isInHeadlessMode(),
					includePeSpecifiedPdbPath, monitor, log, getName());
			if (pdbFilename == null) {
				if (!confirmDirectory(symbolsRepositoryDir)) {
					logFailure("PDB symbol repository directory not found: " + symbolsRepositoryDir,
						log);
				}
				Msg.info(this, "PDB analyzer failed to locate PDB file");
				return false;
			}
		}
		Msg.info(this, "PDB analyzer parsing file: " + pdbFilename);

		PdbLog.message(
			"================================================================================");
		PdbLog.message(new Date(System.currentTimeMillis()).toString() + "\n");
		PdbLog.message("Ghidra Version: " + Application.getApplicationVersion());
		PdbLog.message(NAME);
		PdbLog.message(DESCRIPTION);
		PdbLog.message("PDB Filename: " + pdbFilename + "\n");

		try (AbstractPdb pdb = PdbParser.parse(pdbFilename, pdbReaderOptions, monitor)) {
			monitor.setMessage("PDB: Parsing " + pdbFilename + "...");
			pdb.deserialize(monitor);
			PdbApplicator applicator = new PdbApplicator(pdbFilename, pdb);
			applicator.applyTo(program, program.getDataTypeManager(), program.getImageBase(),
				pdbApplicatorOptions, monitor, log);

		}
		catch (PdbException | IOException e) {
			log.appendMsg(getName(),
				"Issue processing PDB file:  " + pdbFilename + ":\n   " + e.toString());
			return false;
		}

		return true;
	}

	// TODO: I changed this method from what was lifted in the old code.  I check for null string
	//  and I also check for MSCOFF_NAME (TODO: check on the validity of this!!!).  Also, changed
	//  the comparison to a substring search from a .equals).
	@Override
	public boolean canAnalyze(Program program) {
		String executableFormat = program.getExecutableFormat();
		return executableFormat != null && (executableFormat.indexOf(PeLoader.PE_NAME) != -1);
		// TODO: Check for MSCOFF_NAME.  Initial investigation shows that the .debug$T section of
		//  the MSCOFF (*.obj) file has type records and the .debug$S section has symbol records.
		//  More than that, in at least one instance, there has been a TypeServer2MsType type
		//  record that give the GUID, age, and name of the PDB file associated with the MSCOFF
		//  file.  At this point in time, these two sections of the MSCOFF are read (header and
		//  raw data), but we do not interpret these sections any further.  Suggest that we "might"
		//  want to parse some of these records at load time?  Maybe not.  We could, at analysis
		//  time, add the ability to process these two sections (as part of analysis (though we
		//  will not be aware of a PDB file yet), and upon discovery of a TypeServer2MsType (or
		//  perhaps other?), proceed to find the file (if possible) and also process that file.
		//  We posit that if a record indicates a separate PDB for the types (Note: MSFT indicates
		//  that only data types will be found in an MSCOFF PDB file), then that will likely be
		//  the only record in the .debug$T section.
		// TODO: If the MSCOFF file is located in a MSCOFF ARCHIVE (*.lib), there can be a PDB
		//  associated with the archive.  We currently do not pass on this association of the
		//  PDB archive to each underlying MSCOFF file.  Moreover, we believe that we are not
		//  currently discovering the associated MSCOFF ARCHIVE PDB file when processing the
		//  MSCOFF ARCHIVE.  Initial indication is that each MSCOFF within the archive will have
		//  the PDB file that it needs listed, even if redundant for each MSCOFF within the
		//  archive.
//		return executableFormat != null && (executableFormat.indexOf(PeLoader.PE_NAME) != -1 ||
//				executableFormat.indexOf(MSCoffLoader.MSCOFF_NAME) != -1);
	}

	@Override
	public void registerOptions(Options options, Program program) {

		symbolsRepositoryDir = PdbLocator.getDefaultPdbSymbolsDir();

		// PDB file location information
		if (developerMode) {
			options.registerOption(OPTION_NAME_DO_FORCELOAD, Boolean.FALSE, null,
				OPTION_DESCRIPTION_DO_FORCELOAD);
			options.registerOption(OPTION_NAME_FORCELOAD_FILE, OptionType.FILE_TYPE,
				DEFAULT_FORCE_LOAD_FILE, null, OPTION_DESCRIPTION_FORCELOAD_FILE);
		}
		options.registerOption(OPTION_NAME_SYMBOLPATH, OptionType.FILE_TYPE,
			symbolsRepositoryDir, null, OPTION_DESCRIPTION_SYMBOLPATH);
		options.registerOption(OPTION_NAME_INCLUDE_PE_PDB_PATH, includePeSpecifiedPdbPath, null,
			OPTION_DESCRIPTION_INCLUDE_PE_PDB_PATH);

		// PdbReaderOptions
		getPdbReaderOptions();
		options.registerOption(OPTION_NAME_PDB_READER_ANALYZER_LOGGING, pdbLogging, null,
			OPTION_DESCRIPTION_PDB_READER_ANALYZER_LOGGING);
		if (developerMode) {
			options.registerOption(OPTION_NAME_ONE_BYTE_CHARSET_NAME, oneByteCharsetName, null,
				OPTION_DESCRIPTION_ONE_BYTE_CHARSET_NAME);
			options.registerOption(OPTION_NAME_WCHAR_CHARSET_NAME, wideCharCharsetName, null,
				OPTION_DESCRIPTION_WCHAR_CHARSET_NAME);
		}

		// PdbApplicatorOptions
		getPdbApplicatorOptions();
		if (developerMode) {
			options.registerOption(OPTION_NAME_PROCESSING_RESTRICTIONS, restrictions, null,
				OPTION_DESCRIPTION_PROCESSING_RESTRICTIONS);
			options.registerOption(OPTION_NAME_APPLY_CODE_SCOPE_BLOCK_COMMENTS,
				applyCodeScopeBlockComments, null,
				OPTION_DESCRIPTION_APPLY_CODE_SCOPE_BLOCK_COMMENTS);
			// Mechanism to apply instruction labels is not yet implemented-> does nothing
			options.registerOption(OPTION_NAME_APPLY_INSTRUCTION_LABELS, applyInstructionLabels,
				null, OPTION_DESCRIPTION_APPLY_INSTRUCTION_LABELS);
			// The remap capability is not completely implemented... do not turn on.
			options.registerOption(OPTION_NAME_ADDRESS_REMAP,
				remapAddressUsingExistingPublicMangledSymbols, null,
				OPTION_DESCRIPTION_ADDRESS_REMAP);
			options.registerOption(OPTION_NAME_ALLOW_DEMOTE_MANGLED_PRIMARY,
				allowDemotePrimaryMangledSymbol, null,
				OPTION_DESCRIPTION_ALLOW_DEMOTE_MANGLED_PRIMARY);
			// Function params and local implementation is not complete... do not turn on.
			options.registerOption(OPTION_NAME_APPLY_FUNCTION_VARIABLES, applyFunctionVariables,
				null, OPTION_DESCRIPTION_APPLY_FUNCTION_VARIABLES);
			// Object-oriented composite layout is fairly far along, but its use will likely not
			// be forward compatible with future Ghidra work in this area; i.e., it might leave
			// the data type manager in a bad state for future revisions.  While the current
			// layout mechanism might work, I will likely change it to, instead, create a
			// syntactic intermediate representation before creating the final layout.  This will
			// aid portability between tool chains and versions and yield a standard way of
			// data-basing and presenting the information to a user.
			options.registerOption(OPTION_NAME_COMPOSITE_LAYOUT, compositeLayout, null,
				OPTION_DESCRIPTION_COMPOSITE_LAYOUT);
		}
	}

	@Override
	public void optionsChanged(Options options, Program program) {

		if (developerMode) {
			doForceLoad = options.getBoolean(OPTION_NAME_DO_FORCELOAD, doForceLoad);
			forceLoadFile = options.getFile(OPTION_NAME_FORCELOAD_FILE, forceLoadFile);
		}

		File symbolsDir = options.getFile(OPTION_NAME_SYMBOLPATH, symbolsRepositoryDir);
		if (!symbolsDir.equals(symbolsRepositoryDir)) {
			symbolsRepositoryDir = symbolsDir;
			PdbLocator.setDefaultPdbSymbolsDir(symbolsDir);
		}

		includePeSpecifiedPdbPath =
			options.getBoolean(OPTION_NAME_INCLUDE_PE_PDB_PATH, includePeSpecifiedPdbPath);

		// PdbReaderOptions
		pdbLogging = options.getBoolean(OPTION_NAME_PDB_READER_ANALYZER_LOGGING, pdbLogging);
		if (developerMode) {
			oneByteCharsetName =
				options.getString(OPTION_NAME_ONE_BYTE_CHARSET_NAME, oneByteCharsetName);
			wideCharCharsetName =
				options.getString(OPTION_NAME_WCHAR_CHARSET_NAME, wideCharCharsetName);
		}
		setPdbReaderOptions();

		// PdbApplicatorOptions
		if (developerMode) {
			restrictions = options.getEnum(OPTION_NAME_PROCESSING_RESTRICTIONS, restrictions);
			applyCodeScopeBlockComments = options.getBoolean(
				OPTION_NAME_APPLY_CODE_SCOPE_BLOCK_COMMENTS, applyCodeScopeBlockComments);
			// Mechanism to apply instruction labels is not yet implemented-> does nothing
			applyInstructionLabels =
				options.getBoolean(OPTION_NAME_APPLY_INSTRUCTION_LABELS, applyInstructionLabels);
			remapAddressUsingExistingPublicMangledSymbols = options.getBoolean(
				OPTION_NAME_ADDRESS_REMAP, remapAddressUsingExistingPublicMangledSymbols);
			allowDemotePrimaryMangledSymbol = options.getBoolean(
				OPTION_NAME_ALLOW_DEMOTE_MANGLED_PRIMARY, allowDemotePrimaryMangledSymbol);
			applyFunctionVariables =
				options.getBoolean(OPTION_NAME_APPLY_FUNCTION_VARIABLES, applyFunctionVariables);
			compositeLayout = options.getEnum(OPTION_NAME_COMPOSITE_LAYOUT, compositeLayout);
		}
		setPdbApplicatorOptions();
	}

	//==============================================================================================

	private boolean failMissingFilename(PdbProgramAttributes attributes, MessageLog log) {
		if (doForceLoad) {
			return false; // PDB File property not used for forced load
		}
		if (StringUtils.isEmpty(attributes.getPdbFile())) {
			logFailure("Missing 'PDB File' program property, unable to locate PDB", log);
			return true;
		}
		return false;
	}

	private void logFailure(String msg, MessageLog log) {
		log.appendMsg(getName(), msg);
		log.appendMsg(getName(), "Skipping PDB processing");
		log.setStatus(msg);
	}

	private boolean failMissingAttributes(PdbProgramAttributes attributes, MessageLog log) {
		if (doForceLoad) {
			return false; // Attributes not used for forced load
		}
		// RSDS version should only have GUID; non-RSDS version should only have Signature.
		String error;
		if ("RSDS".equals(attributes.getPdbVersion())) {
			if (!StringUtils.isEmpty(attributes.getPdbGuid())) {
				return false; // Don't fail.
			}
			error = "Missing 'PDB GUID' program property, unable to locate PDB.";
		}
		else {
			if (!StringUtils.isEmpty(attributes.getPdbSignature())) {
				return false; // Don't fail.
			}
			error = "Missing 'PDB Signature' program property, unable to locate PDB.";
		}
		logFailure(error, log);
		return true;
	}

	private void setPdbLogging(MessageLog log) {
		try {
			PdbLog.setEnabled(pdbLogging);
		}
		catch (IOException e) {
			// Probably could not open the file.
			if (log != null) {
				log.appendMsg(getName(), "IOException when trying to open PDB log file: ");
				log.appendException(e);
			}
		}
	}

	private void getPdbReaderOptions() {
		oneByteCharsetName = pdbReaderOptions.getOneByteCharsetName();
		wideCharCharsetName = pdbReaderOptions.getTwoByteCharsetName();
	}

	private void setPdbReaderOptions() {
		pdbReaderOptions.setOneByteCharsetForName(oneByteCharsetName);
		pdbReaderOptions.setWideCharCharsetForName(wideCharCharsetName);
	}

	private void getPdbApplicatorOptions() {
		applyCodeScopeBlockComments = PdbApplicatorOptions.DEFAULT_APPLY_CODE_SCOPE_BLOCK_COMMENTS;
		restrictions = PdbApplicatorOptions.DEFAULT_RESTRICTIONS;

		applyInstructionLabels = PdbApplicatorOptions.DEFAULT_APPLY_INSTRUCTION_LABELS;
		remapAddressUsingExistingPublicMangledSymbols =
			PdbApplicatorOptions.DEFAULT_REMAP_ADDRESSES_USING_EXISTING_SYMBOLS;
		allowDemotePrimaryMangledSymbol =
			PdbApplicatorOptions.DEFAULT_ALLOW_DEMOTE_PRIMARY_MANGLED_SYMBOLS;
		applyFunctionVariables = PdbApplicatorOptions.DEFAULT_APPLY_FUNCTION_VARIABLES;
		compositeLayout = PdbApplicatorOptions.DEFAULT_CLASS_LAYOUT;
	}

	private void setPdbApplicatorOptions() {
		pdbApplicatorOptions.setRestrictions(restrictions);

		pdbApplicatorOptions.setApplyCodeScopeBlockComments(applyCodeScopeBlockComments);
		pdbApplicatorOptions.setApplyInstructionLabels(applyInstructionLabels);
		pdbApplicatorOptions.setRemapAddressUsingExistingPublicSymbols(
			remapAddressUsingExistingPublicMangledSymbols);
		pdbApplicatorOptions.setAllowDemotePrimaryMangledSymbols(allowDemotePrimaryMangledSymbol);
		pdbApplicatorOptions.setApplyFunctionVariables(applyFunctionVariables);
		pdbApplicatorOptions.setClassLayout(compositeLayout);
	}

	private boolean confirmDirectory(File path) {
		return path.isDirectory();
	}

	private boolean confirmFile(File path) {
		return path.isFile();
	}

}
