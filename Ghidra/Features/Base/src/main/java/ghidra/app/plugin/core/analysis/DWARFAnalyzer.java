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
import ghidra.program.model.data.BuiltInDataTypeManager;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class DWARFAnalyzer extends AbstractAnalyzer {
	private static final String DWARF_LOADED_OPTION_NAME = "DWARF Loaded";

	private static final String OPTION_IMPORT_DATATYPES = "Import data types";
	private static final String OPTION_IMPORT_DATATYPES_DESC =
		"Import data types defined in the DWARF debug info.";

	private static final String OPTION_PRELOAD_ALL_DIES = "Preload all DIEs";
	private static final String OPTION_PRELOAD_ALL_DIES_DESC =
		"Preload all DIE records. Requires more memory, but necessary for some non-standard layouts.";

	private static final String OPTION_IMPORT_FUNCS = "Import functions";
	private static final String OPTION_IMPORT_FUNCS_DESC =
		"Import function information defined in the DWARF debug info.  (implies import data types)";

	private static final String OPTION_IMPORT_LIMIT_DIE_COUNT = "Debug item count limit";
	private static final String OPTION_IMPORT_LIMIT_DIE_COUNT_DESC =
		"If the number of DWARF debug items are greater than this setting, DWARF analysis will be skipped.";

	private static final String OPTION_OUTPUT_SOURCE_INFO = "Output Source info";
	private static final String OPTION_OUTPUT_SOURCE_INFO_DESC =
		"Include source code location info (filename:linenumber) in comments attached to the Ghidra datatype or function or variable created.";

	private static final String OPTION_OUTPUT_DWARF_DIE_INFO = "Output DWARF DIE info";
	private static final String OPTION_OUTPUT_DWARF_DIE_INFO_DESC =
		"Include DWARF DIE offset info in comments attached to the Ghidra datatype or function or variable created.";

	private static final String OPTION_NAME_LENGTH_CUTOFF = "Name length cutoff";
	private static final String OPTION_NAME_LENGTH_CUTOFF_DESC =
		"Truncate symbol and type names longer than this limit.  Range 20..2000";

	private static final String OPTION_OUTPUT_LEXICAL_BLOCK_COMMENTS = "Lexical block comments";
	private static final String OPTION_OUTPUT_LEXICAL_BLOCK_COMMENTS_DESC =
		"Add comments to the start of lexical blocks";

	private static final String OPTION_OUTPUT_INLINE_FUNC_COMMENTS = "Inlined functions comments";
	private static final String OPTION_OUTPUT_INLINE_FUNC_COMMENTS_DESC =
		"Add comments to the start of inlined functions";

	private static final String OPTION_COPY_ANON_TYPES =
		"Create local copy of anonymous types for struct fields";
	private static final String OPTION_COPY_ANON_TYPES_DESC =
		"Clones anonymous types used in a struct and creates a local copy using the name of the field.";

	private static final String OPTION_OUTPUT_FUNC_SIGS = "Output function signatures";
	private static final String OPTION_OUTPUT_FUNC_SIGS_DESC =
		"Create function signature data types for each function encountered in the DWARF debug data.";

	private static final String DWARF_ANALYZER_NAME = "DWARF";
	private static final String DWARF_ANALYZER_DESCRIPTION =
		"Automatically extracts DWARF info from an ELF file.";

	private DWARFImportOptions importOptions = new DWARFImportOptions();
	private long lastTxId = -1;

	public DWARFAnalyzer() {
		super(DWARF_ANALYZER_NAME, DWARF_ANALYZER_DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setDefaultEnablement(true);
		setPriority(AnalysisPriority.FORMAT_ANALYSIS.after());
		setSupportsOneTimeAnalysis();
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

		long txId = program.getCurrentTransaction().getID();
		if (txId == lastTxId) {
			// Only run once per analysis session - as denoted by being in the same transaction
			return true;
		}
		lastTxId = txId;

		Options propList = program.getOptions(Program.PROGRAM_INFO);
		boolean alreadyLoaded = propList.getBoolean(DWARF_LOADED_OPTION_NAME, false) ||
			oldCheckIfDWARFImported(program);
		if (alreadyLoaded) {
			Msg.info(this, "DWARF already imported, skipping.");
			return false;
		}

		DWARFSectionProvider dsp = DWARFSectionProviderFactory.createSectionProviderFor(program);
		if (dsp == null) {
			log.appendMsg("Unable to find DWARF information, skipping DWARF analysis");
			return false;
		}

		try {
			try (DWARFProgram prog = new DWARFProgram(program, importOptions, monitor, dsp)) {
				if (prog.getRegisterMappings() == null && importOptions.isImportFuncs()) {
					log.appendMsg(
						"No DWARF to Ghidra register mappings found for this program's language [" +
							program.getLanguageID().getIdAsString() +
							"], unable to import functions.");
					importOptions.setImportFuncs(false);
				}

				DWARFParser dp =
					new DWARFParser(prog, BuiltInDataTypeManager.getDataTypeManager(), monitor);
				DWARFImportSummary parseResults = dp.parse();
				parseResults.logSummaryResults();
			}
			propList.setBoolean(DWARF_LOADED_OPTION_NAME, true);
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
			log.appendMsg("Error during DWARFAnalyzer import");
			log.appendException(e);
		}
		return false;
	}

	private boolean oldCheckIfDWARFImported(Program prog) {
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

		options.registerOption(OPTION_COPY_ANON_TYPES, importOptions.isCopyRenameAnonTypes(), null,
			OPTION_COPY_ANON_TYPES_DESC);

		options.registerOption(OPTION_OUTPUT_FUNC_SIGS, importOptions.isCreateFuncSignatures(),
			null, OPTION_OUTPUT_FUNC_SIGS_DESC);
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
		importOptions.setCopyRenameAnonTypes(
			options.getBoolean(OPTION_COPY_ANON_TYPES, importOptions.isCopyRenameAnonTypes()));
		importOptions.setCreateFuncSignatures(
			options.getBoolean(OPTION_OUTPUT_FUNC_SIGS, importOptions.isCreateFuncSignatures()));
	}

}
