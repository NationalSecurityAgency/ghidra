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

import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.app.util.opinion.MachoLoader;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ExternalSymbolResolver;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * {@link Analyzer} to link unresolved symbols
 * 
 * @see ExternalSymbolResolver
 */
public class ExternalSymbolResolverAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "External Symbol Resolver";
	private static final String DESCRIPTION =
		"Links unresolved external symbols to the first symbol found in the program's required libraries list (found in program properties).";

	/**
	 * Creates a new {@link ExternalSymbolResolverAnalyzer} 
	 */
	public ExternalSymbolResolverAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();

		// Do it before demangling
		setPriority(AnalysisPriority.DATA_TYPE_PROPOGATION.before().before().before().before());
	}

	@Override
	public boolean canAnalyze(Program program) {
		// This analyzer needs to look around the project for imported libraries
		if (program.getDomainFile().getParent() == null) {
			return false;
		}

		Options options = program.getOptions(Program.PROGRAM_INFO);
		String format = options.getString("Executable Format", null);
		return ElfLoader.ELF_NAME.equals(format) || MachoLoader.MACH_O_NAME.equals(format);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		try (ExternalSymbolResolver esr = new ExternalSymbolResolver(
			program.getDomainFile().getParent().getProjectData(), monitor)) {
			esr.addProgramToFixup(program);
			esr.fixUnresolvedExternalSymbols();
			esr.logInfo(s -> Msg.info(this, s), false);
			if (esr.hasProblemLibraries()) {
				// causes a popup message at end of analysis session
				esr.logInfo(log::appendMsg, true);
			}
			return true;
		}
	}
}
