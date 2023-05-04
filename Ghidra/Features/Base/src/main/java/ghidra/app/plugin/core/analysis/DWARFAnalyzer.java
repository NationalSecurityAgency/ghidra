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

import java.io.IOException;

import ghidra.app.services.*;
import ghidra.app.util.bin.format.dwarf4.DWARFException;
import ghidra.app.util.bin.format.dwarf4.DWARFPreconditionException;
import ghidra.app.util.bin.format.dwarf4.next.*;
import ghidra.app.util.bin.format.dwarf4.next.sectionprovider.DWARFSectionProvider;
import ghidra.app.util.bin.format.dwarf4.next.sectionprovider.DWARFSectionProviderFactory;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class DWARFAnalyzer extends AbstractAnalyzer {
	private static final String DWARF_LOADED_OPTION_NAME = "DWARF Loaded";

	private static final String OPTION_IMPORT_DATATYPES = "Import Data Types";
	private static final String OPTION_IMPORT_DATATYPES_DESC =
		"Import data types defined in the DWARF debug info.";

	private static final String OPTION_PRELOAD_ALL_DIES = "Preload All DIEs";
	private static final String OPTION_PRELOAD_ALL_DIES_DESC =
		"Preload all DIE records. Requires more memory, but necessary for some non-standard " +
			"layouts.";

	private static final String OPTION_IMPORT_FUNCS = "Import Functions";
	private static final String OPTION_IMPORT_FUNCS_DESC =
		"Import function information defined in the DWARF debug info\n" +
			"(implies 'Import Data Types' is selected).";

	private static final String OPTION_IMPORT_LIMIT_DIE_COUNT = "Debug Item Limit";
	private static final String OPTION_IMPORT_LIMIT_DIE_COUNT_DESC =
		"If the number of DWARF debug items are greater than this setting, DWARF analysis will " +
			"be skipped.";

	private static final String OPTION_OUTPUT_SOURCE_INFO = "Output Source Info";
	private static final String OPTION_OUTPUT_SOURCE_INFO_DESC =
		"Include source code location info (filename:linenumber) in comments attached to the " +
			"Ghidra datatype or function or variable created.";

	private static final String OPTION_OUTPUT_DWARF_DIE_INFO = "Output DWARF DIE Info";
	private static final String OPTION_OUTPUT_DWARF_DIE_INFO_DESC =
		"Include DWARF DIE offset info in comments attached to the Ghidra datatype or function " +
			"or variable created.";

	private static final String OPTION_NAME_LENGTH_CUTOFF = "Maximum Name Length";
	private static final String OPTION_NAME_LENGTH_CUTOFF_DESC =
		"Truncate symbol and type names longer than this limit.  Range 20..2000";

	private static final String OPTION_OUTPUT_LEXICAL_BLOCK_COMMENTS = "Add Lexical Block Comments";
	private static final String OPTION_OUTPUT_LEXICAL_BLOCK_COMMENTS_DESC =
		"Add comments to the start of lexical blocks";

	private static final String OPTION_OUTPUT_INLINE_FUNC_COMMENTS =
		"Add Inlined Functions Comments";
	private static final String OPTION_OUTPUT_INLINE_FUNC_COMMENTS_DESC =
		"Add comments to the start of inlined functions";

	private static final String OPTION_OUTPUT_FUNC_SIGS = "Create Function Signatures";
	private static final String OPTION_OUTPUT_FUNC_SIGS_DESC =
		"Create function signature data types for each function encountered in the DWARF debug " +
			"data.";

	private static final String OPTION_TRY_PACK_STRUCTS = "Try To Pack Structs";
	private static final String OPTION_TRY_PACK_STRUCTS_DESC =
		"Try to pack structure/union data types.";

	private static final String DWARF_ANALYZER_NAME = "DWARF";
	private static final String DWARF_ANALYZER_DESCRIPTION =
		"Automatically extracts DWARF info from an ELF file.";

//==================================================================================================
// Old Option Names - Should stick around for multiple major versions after 10.2
//==================================================================================================

	private static final String OPTION_IMPORT_DATATYPES_OLD = "Import data types";
	private static final String OPTION_PRELOAD_ALL_DIES_OLD = "Preload all DIEs";
	private static final String OPTION_IMPORT_FUNCS_OLD = "Import functions";
	private static final String OPTION_IMPORT_LIMIT_DIE_COUNT_OLD = "Debug item count limit";
	private static final String OPTION_OUTPUT_SOURCE_INFO_OLD = "Output Source info";
	private static final String OPTION_OUTPUT_DWARF_DIE_INFO_OLD = "Output DWARF DIE info";
	private static final String OPTION_NAME_LENGTH_CUTOFF_OLD = "Name length cutoff";
	private static final String OPTION_OUTPUT_LEXICAL_BLOCK_COMMENTS_OLD = "Lexical block comments";
	private static final String OPTION_OUTPUT_INLINE_FUNC_COMMENTS_OLD =
		"Inlined functions comments";
	private static final String OPTION_OUTPUT_FUNC_SIGS_OLD = "Output function signatures";

	private AnalysisOptionsUpdater optionsUpdater = new AnalysisOptionsUpdater();

//==================================================================================================
// End Old Option Names
//==================================================================================================	

	/**
	 * Returns true if DWARF has already been imported into the specified program.
	 * 
	 * @param program {@link Program} to check
	 * @return true if DWARF has already been imported, false if not yet
	 */
	public static boolean isAlreadyImported(Program program) {
		Options options = program.getOptions(Program.PROGRAM_INFO);
		return options.getBoolean(DWARF_LOADED_OPTION_NAME, false) ||
			oldCheckIfDWARFImported(program);
	}

	private DWARFImportOptions importOptions = new DWARFImportOptions();
	private long lastTxId = -1;

	public DWARFAnalyzer() {
		super(DWARF_ANALYZER_NAME, DWARF_ANALYZER_DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setDefaultEnablement(true);
		setPriority(AnalysisPriority.FORMAT_ANALYSIS.after());
		setSupportsOneTimeAnalysis();

		optionsUpdater.registerReplacement(OPTION_IMPORT_DATATYPES,
			OPTION_IMPORT_DATATYPES_OLD);
		optionsUpdater.registerReplacement(OPTION_PRELOAD_ALL_DIES,
			OPTION_PRELOAD_ALL_DIES_OLD);
		optionsUpdater.registerReplacement(OPTION_IMPORT_FUNCS,
			OPTION_IMPORT_FUNCS_OLD);
		optionsUpdater.registerReplacement(OPTION_IMPORT_LIMIT_DIE_COUNT,
			OPTION_IMPORT_LIMIT_DIE_COUNT_OLD);
		optionsUpdater.registerReplacement(OPTION_OUTPUT_SOURCE_INFO,
			OPTION_OUTPUT_SOURCE_INFO_OLD);
		optionsUpdater.registerReplacement(OPTION_OUTPUT_DWARF_DIE_INFO,
			OPTION_OUTPUT_DWARF_DIE_INFO_OLD);
		optionsUpdater.registerReplacement(OPTION_NAME_LENGTH_CUTOFF,
			OPTION_NAME_LENGTH_CUTOFF_OLD);
		optionsUpdater.registerReplacement(OPTION_OUTPUT_LEXICAL_BLOCK_COMMENTS,
			OPTION_OUTPUT_LEXICAL_BLOCK_COMMENTS_OLD);
		optionsUpdater.registerReplacement(OPTION_OUTPUT_INLINE_FUNC_COMMENTS,
			OPTION_OUTPUT_INLINE_FUNC_COMMENTS_OLD);
		optionsUpdater.registerReplacement(OPTION_OUTPUT_FUNC_SIGS, OPTION_OUTPUT_FUNC_SIGS_OLD);
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		// TODO: DWARF implementation needs improvements to handle Harvard Architectures properly
		// Currently unable to produce addresses which should refer to data space resulting in
		// improperly placed symbols, etc.
		Language language = program.getLanguage();
		return language.getDefaultSpace() == language.getDefaultDataSpace();
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		long txId = program.getCurrentTransactionInfo().getID();
		if (txId == lastTxId) {
			// Only run once per analysis session - as denoted by being in the same transaction
			return true;
		}
		lastTxId = txId;

		if (isAlreadyImported(program)) {
			Msg.info(this, "DWARF already imported, skipping.");
			return false;
		}

		DWARFSectionProvider dsp =
			DWARFSectionProviderFactory.createSectionProviderFor(program, monitor); // closed by DWARFProgram
		if (dsp == null) {
			Msg.info(this, "Unable to find DWARF information, skipping DWARF analysis");
			return false;
		}

		try {
			try (DWARFProgram prog = new DWARFProgram(program, importOptions, monitor, dsp)) {
				if (prog.getRegisterMappings() == null && importOptions.isImportFuncs()) {
					log.appendMsg(
						"No DWARF to Ghidra register mappings found for this program's language [" +
							program.getLanguageID().getIdAsString() +
							"], function information may be incorrect / incomplete.");
				}

				DWARFParser dp = new DWARFParser(prog, monitor);
				DWARFImportSummary parseResults = dp.parse();
				parseResults.logSummaryResults();
			}
			Options propList = program.getOptions(Program.PROGRAM_INFO);
			propList.setBoolean(DWARF_LOADED_OPTION_NAME, true);
			dsp.updateProgramInfo(program);
			return true;
		}
		catch (CancelledException ce) {
			throw ce;
		}
		catch (DWARFPreconditionException e) {
			log.appendMsg("Skipping DWARF import because a precondition was not met:");
			log.appendMsg(e.getMessage());
			log.appendMsg(
				"Manually re-run the DWARF analyzer after adjusting the options or start it via Dwarf_ExtractorScript");
		}
		catch (DWARFException | IOException e) {
			log.appendMsg("Error during DWARFAnalyzer import: " + e);
			Msg.error(this, "Error during DWARFAnalyzer import: ", e);
		}
		return false;
	}

	@Deprecated(forRemoval = true, since = "10.0")
	private static boolean oldCheckIfDWARFImported(Program prog) {
		// this was the old way of checking if the DWARF analyzer had already been run.  Keep
		// it around for a little bit so existing programs that have already imported DWARF data
		// don't get re-run.  Remove after a release or two. 
		return DWARFFunctionImporter.hasDWARFProgModule(prog, DWARFProgram.DWARF_ROOT_NAME);
	}

	@Override
	public boolean canAnalyze(Program program) {
		return DWARFProgram.isDWARF(program);
	}

	@Override
	public void registerOptions(Options options, Program program) {

		options.registerOption(OPTION_IMPORT_DATATYPES, importOptions.isImportDataTypes(), null,
			OPTION_IMPORT_DATATYPES_DESC);

		options.registerOption(OPTION_PRELOAD_ALL_DIES, importOptions.isPreloadAllDIEs(), null,
			OPTION_PRELOAD_ALL_DIES_DESC);

		options.registerOption(OPTION_IMPORT_FUNCS, importOptions.isImportFuncs(), null,
			OPTION_IMPORT_FUNCS_DESC);

		options.registerOption(OPTION_OUTPUT_DWARF_DIE_INFO, importOptions.isOutputDIEInfo(), null,
			OPTION_OUTPUT_DWARF_DIE_INFO_DESC);

		options.registerOption(OPTION_OUTPUT_LEXICAL_BLOCK_COMMENTS,
			importOptions.isOutputLexicalBlockComments(), null,
			OPTION_OUTPUT_LEXICAL_BLOCK_COMMENTS_DESC);

		options.registerOption(OPTION_OUTPUT_INLINE_FUNC_COMMENTS,
			importOptions.isOutputInlineFuncComments(), null,
			OPTION_OUTPUT_INLINE_FUNC_COMMENTS_DESC);

		options.registerOption(OPTION_OUTPUT_SOURCE_INFO,
			importOptions.isOutputSourceLocationInfo(), null, OPTION_OUTPUT_SOURCE_INFO_DESC);

		options.registerOption(OPTION_IMPORT_LIMIT_DIE_COUNT,
			importOptions.getImportLimitDIECount(), null, OPTION_IMPORT_LIMIT_DIE_COUNT_DESC);

		options.registerOption(OPTION_NAME_LENGTH_CUTOFF, importOptions.getNameLengthCutoff(), null,
			OPTION_NAME_LENGTH_CUTOFF_DESC);

		options.registerOption(OPTION_OUTPUT_FUNC_SIGS, importOptions.isCreateFuncSignatures(),
			null, OPTION_OUTPUT_FUNC_SIGS_DESC);

		options.registerOption(OPTION_TRY_PACK_STRUCTS, importOptions.isTryPackStructs(),
			null, OPTION_TRY_PACK_STRUCTS_DESC);
	}

	@Override
	public AnalysisOptionsUpdater getOptionsUpdater() {
		return optionsUpdater;
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		importOptions.setOutputDIEInfo(
			options.getBoolean(OPTION_OUTPUT_DWARF_DIE_INFO, importOptions.isOutputDIEInfo()));
		importOptions.setPreloadAllDIEs(
			options.getBoolean(OPTION_PRELOAD_ALL_DIES, importOptions.isPreloadAllDIEs()));
		importOptions.setOutputSourceLocationInfo(options.getBoolean(OPTION_OUTPUT_SOURCE_INFO,
			importOptions.isOutputSourceLocationInfo()));
		importOptions.setOutputLexicalBlockComments(options.getBoolean(
			OPTION_OUTPUT_LEXICAL_BLOCK_COMMENTS, importOptions.isOutputLexicalBlockComments()));
		importOptions.setOutputInlineFuncComments(options.getBoolean(
			OPTION_OUTPUT_INLINE_FUNC_COMMENTS, importOptions.isOutputInlineFuncComments()));
		importOptions.setImportDataTypes(
			options.getBoolean(OPTION_IMPORT_DATATYPES, importOptions.isImportDataTypes()));
		importOptions.setImportFuncs(
			options.getBoolean(OPTION_IMPORT_FUNCS, importOptions.isImportFuncs()));
		importOptions.setImportLimitDIECount(
			options.getInt(OPTION_IMPORT_LIMIT_DIE_COUNT, importOptions.getImportLimitDIECount()));
		importOptions.setNameLengthCutoff(
			options.getInt(OPTION_NAME_LENGTH_CUTOFF, importOptions.getNameLengthCutoff()));
		importOptions.setCreateFuncSignatures(
			options.getBoolean(OPTION_OUTPUT_FUNC_SIGS, importOptions.isCreateFuncSignatures()));
		importOptions.setTryPackDataTypes(
			options.getBoolean(OPTION_TRY_PACK_STRUCTS, importOptions.isTryPackStructs()));
	}

}
