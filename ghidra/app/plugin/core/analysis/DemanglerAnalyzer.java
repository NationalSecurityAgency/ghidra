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

import ghidra.app.cmd.label.DemanglerCmd;
import ghidra.app.services.*;
import ghidra.app.util.demangler.DemanglerOptions;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class DemanglerAnalyzer extends AbstractAnalyzer {
	private static final String NAME = "Demangler";
	private static final String DESCRIPTION =
		"After a function is created, this analyzer will attempt to demangle " +
			"the name and apply datatypes to parameters.";

	private static final String OPTION_NAME_DEMANGLE_USE_KNOWN_PATTERNS =
		"Only Demangle Known Mangled Symbols";
	private static final String OPTION_DESCRIPTION_USE_KNOWN_PATTERNS =
		"Only demangle " + "symbols that follow known compiler mangling patterns. " +
			"Leaving this option off may cause non-mangled symbols to get demangled.";

	private final static String OPTION_NAME_COMMIT_SIGNATURE = "Commit Function Signatures";
	private static final String OPTION_DESCRIPTION_COMMIT_SIGNATURE =
		"Apply any recovered function signature, in addition to the function name";

	private boolean doSignatureEnabled = true;
	private boolean demangleAllSymbols = false;

	public DemanglerAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setPriority(AnalysisPriority.DATA_TYPE_PROPOGATION.before().before().before());
		setDefaultEnablement(true);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		SymbolTable symbolTable = program.getSymbolTable();

		int progress = 0;
		monitor.initialize(symbolTable.getNumSymbols());
		monitor.setShowProgressValue(false);

		SymbolIterator symiter = symbolTable.getPrimarySymbolIterator(set, true);
		while (symiter.hasNext()) {
			monitor.checkCanceled();

			Symbol symbol = symiter.next();
			Address address = symbol.getAddress();
			if (address.compareTo(set.getMaxAddress()) > 0) {
				break;
			}

			if (symbol.getSource() == SourceType.DEFAULT) {
				continue;
			}

			// Only demangle global memory symbols or external
			// symbols directly parented to a Library namespace
			Namespace parentNamespace = symbol.getParentNamespace();
			if (symbol.isExternal()) {
				if (!(parentNamespace instanceof Library)) {
					continue;
				}
			}
			else if (!parentNamespace.isGlobal()) {
				continue;
			}
			
			// Someone has already added arguments or return to the function
			//  signature.
			if (symbol.getSymbolType() == SymbolType.FUNCTION) {
				Function function = (Function) symbol.getObject();
				if (function.getSignatureSource() != SourceType.DEFAULT) {
					continue;
				}
			}

			// retrieve symbol count each time, as the number of symbols changes while we are working
			int count = symbolTable.getNumSymbols();
			monitor.setMaximum(count);
			monitor.setProgress((int) ((progress++ / (double) count) * count));

			DemanglerOptions options = new DemanglerOptions();
			options.setDoDisassembly(true);
			options.setApplySignature(doSignatureEnabled);
			options.setDemangleOnlyKnownPatterns(demangleAllSymbols);

			DemanglerCmd cmd = new DemanglerCmd(address, symbol.getName(), options);
			if (!cmd.applyTo(program)) {
				String message = cmd.getStatusMsg();
				if (message != null) {
					log.appendMsg(cmd.getName(), message);
					log.setStatus(message);
				}
			}
		}

		monitor.setShowProgressValue(true);
		return true;
	}

	@Override
	public void registerOptions(Options options, Program program) {
		options.registerOption(OPTION_NAME_COMMIT_SIGNATURE, doSignatureEnabled, null,
			OPTION_DESCRIPTION_COMMIT_SIGNATURE);

		options.registerOption(OPTION_NAME_DEMANGLE_USE_KNOWN_PATTERNS, false, null,
			OPTION_DESCRIPTION_USE_KNOWN_PATTERNS);
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		doSignatureEnabled = options.getBoolean(OPTION_NAME_COMMIT_SIGNATURE, doSignatureEnabled);
		demangleAllSymbols =
			options.getBoolean(OPTION_NAME_DEMANGLE_USE_KNOWN_PATTERNS, demangleAllSymbols);
	}
}
