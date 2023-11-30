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
import ghidra.app.util.bin.format.golang.rtti.GoRttiMapper;
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
	private static final String DWARF_ANALYZER_NAME = "DWARF";
	private static final String DWARF_ANALYZER_DESCRIPTION =
		"Automatically extracts DWARF info from ELF/MachO/PE files.";


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

		if (GoRttiMapper.isGolangProgram(program)) {
			Msg.info(this, "DWARF: Enabling DIE preload for golang binary");
			importOptions.setPreloadAllDIEs(true);
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
		importOptions.registerOptions(options);
	}

	@Override
	public AnalysisOptionsUpdater getOptionsUpdater() {
		return importOptions.getOptionsUpdater();
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		importOptions.optionsChanged(options);
	}

}
