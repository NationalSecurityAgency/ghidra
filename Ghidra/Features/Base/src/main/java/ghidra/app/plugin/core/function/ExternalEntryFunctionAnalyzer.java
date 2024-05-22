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
package ghidra.app.plugin.core.function;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
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

		AddressSet funcStarts = new AddressSet();

		monitor.setMessage("Finding External Entry Functions");
		//
		// add entry points
		//
		AddressIterator entryIter = program.getSymbolTable().getExternalEntryPointIterator();
		while (entryIter.hasNext() && !monitor.isCancelled()) {
			Address entry = entryIter.next();
			if (!set.contains(entry)) {
				continue;
			}
			
			// check for any indicators this is a good start of a function
			// must have an instruction at the entry, and not be part of another function
			if (!isGoodFunctionStart(program, entry)) {
				continue;
			}
			
			funcStarts.addRange(entry, entry);
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
	
	/**
	 * Check if address is a good function start.
	 * Instruction exists at the location.
	 * No instruction falls through to this one.
	 * 
	 * @param program the program
	 * @param addr address to check if is a good function start
	 * @return true if would be a good function start, false otherwise
	 */
	public static boolean isGoodFunctionStart(Program program, Address addr) {
		// check location starts with an instruction
		if (program.getListing().getInstructionAt(addr) == null) {
			return false;
		}

		Address addrBefore = addr.previous();
		if (addrBefore == null) {
			return true;
		}
		
		// check if instruction before, falls into this one.
		// other code is responsible for creating functions from references
		Instruction instr = program.getListing().getInstructionContaining(addrBefore);
		if (instr != null && addr.equals(instr.getFallThrough())) {
			return false;
		}

		// didn't find anything that would indicate is a bad function start
		return true;
	}
}
