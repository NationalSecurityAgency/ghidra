/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.plugin.core.function;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;

public class ExternalEntryFunctionAnalyzer extends AbstractAnalyzer {
	private static final String NAME = "External Entry References";
	private static final String DESCRIPTION =
		"Creates function definitions for external entry points where instructions already exist.";

	public ExternalEntryFunctionAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setPriority(AnalysisPriority.CODE_ANALYSIS.before().before());
		setDefaultEnablement(true);
	}

	/**
	 * Called when a function has been added.
	 * Looks at address for call reference
	 */
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) {

		Listing listing = program.getListing();

		AddressSet funcStarts = new AddressSet();

		monitor.setMessage("Finding External Entry Functions");
		//
		// add entry points
		//
		AddressIterator entryIter = program.getSymbolTable().getExternalEntryPointIterator();
		while (entryIter.hasNext() && !monitor.isCancelled()) {
			Address entry = entryIter.next();
			if (set.contains(entry) && listing.getInstructionAt(entry) != null) {
				funcStarts.addRange(entry, entry);
			}
		}

		// remove any addresses that are already functions
		SymbolIterator iter =
			program.getSymbolTable().getSymbols(funcStarts, SymbolType.FUNCTION, true);
		AddressSet alreadyFunctionSet = new AddressSet();
		while (iter.hasNext() && !monitor.isCancelled()) {
			Symbol element = iter.next();
			alreadyFunctionSet.addRange(element.getAddress(), element.getAddress());
		}
		funcStarts.delete(alreadyFunctionSet);

		if (monitor.isCancelled()) {
			return false;
		}
		AutoAnalysisManager amgr = AutoAnalysisManager.getAnalysisManager(program);
		amgr.createFunction(funcStarts, false);

		return true;
	}

}
