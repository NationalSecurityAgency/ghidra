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

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.bin.format.dwarf4.DWARFException;
import ghidra.app.util.bin.format.dwarf4.DWARFPreconditionException;
import ghidra.app.util.bin.format.dwarf4.next.DWARFDataTypeManager;
import ghidra.app.util.bin.format.dwarf4.next.DWARFFunctionImporter;
import ghidra.app.util.bin.format.dwarf4.next.DWARFImportOptions;
import ghidra.app.util.bin.format.dwarf4.next.DWARFImportSummary;
import ghidra.app.util.bin.format.dwarf4.next.DWARFParser;
import ghidra.app.util.bin.format.dwarf4.next.DWARFProgram;
import ghidra.app.util.bin.format.dwarf4.next.sectionprovider.DWARFSectionProvider;
import ghidra.app.util.bin.format.dwarf4.next.sectionprovider.DWARFSectionProviderFactory;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.BuiltInDataTypeManager;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.app.util.bin.format.dwarf4.next.DWARFLocalImporter;

public class DWARFLocalAnalyzer extends AbstractAnalyzer {

	public DWARFLocalAnalyzer() {
		super("Dwarf Locals", "adds dwarf locals late stage to use stack analysis", AnalyzerType.BYTE_ANALYZER);
		setPriority(AnalysisPriority.DATA_TYPE_PROPOGATION.after().after().after());
		setDefaultEnablement(true);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		try (DWARFSectionProvider dsp =
				DWARFSectionProviderFactory.createSectionProviderFor(program, monitor)) {
				if (dsp == null) {
					Msg.info(this, "Unable to find DWARF information, skipping DWARF analysis");
					return false;
				}

				DWARFImportOptions importOptions = new DWARFImportOptions();
				try (DWARFProgram prog = new DWARFProgram(program, importOptions, monitor, dsp)) {
					if (prog.getRegisterMappings() == null && importOptions.isImportFuncs()) {
						log.appendMsg(
							"No DWARF to Ghidra register mappings found for this program's language [" +
								program.getLanguageID().getIdAsString() +
								"], function information may be incorrect / incomplete.");
					}

					
					
					var builtInDTM = BuiltInDataTypeManager.getDataTypeManager();
					var importSummary = new DWARFImportSummary();
					var dwarf_dtm = new DWARFDataTypeManager(prog, prog.getGhidraProgram().getDataTypeManager(),
							builtInDTM, importSummary);
					
					DWARFLocalImporter dfi =
						new DWARFLocalImporter(prog, dwarf_dtm, monitor);
					dfi.process();
					importSummary.logSummaryResults();
				}
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
				log.appendMsg("Error during DWARFAnalyzer import: " + e.getMessage());
				Msg.error(this, "Error during DWARFAnalyzer import: " + e.getMessage(), e);
			}
			
		return false;
	}

	
}
