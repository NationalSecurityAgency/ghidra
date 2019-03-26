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

import ghidra.app.cmd.function.CreateThunkFunctionCmd;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;

public class FunctionAnalyzer extends AbstractAnalyzer {
	private static final String FIND_FUNCTION_STARTS_MSG = "Find Function Starts : ";
	private static final String NAME = "Subroutine References";
	private static final String DESCRIPTION =
		"Create Function definitions for code that is called.";

	private final static int NOTIFICATION_INTERVAL = 256;

	protected boolean createOnlyThunks = false;
	protected String analysisMessage = FIND_FUNCTION_STARTS_MSG;

	public FunctionAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		setPriority(AnalysisPriority.CODE_ANALYSIS.before());
		setDefaultEnablement(true);
	}

	/**
	 * Following the creation of instructions this analyzer searches for direct
	 * call references and creates functions at the called locations.
	 */
	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log) {

		ReferenceManager mgr = program.getReferenceManager();
		Listing listing = program.getListing();

		AddressSet funcStarts = new AddressSet();

		int count = 0;
		long initial_count = set.getNumAddresses();
		monitor.initialize(initial_count);
		AddressSet leftSet = new AddressSet(set);

		//
		// gather up all the locations that are referenced as calls
		//
		AddressIterator iter = mgr.getReferenceSourceIterator(set, true);
		while (!monitor.isCancelled() && iter.hasNext()) {
			Address addr = iter.next();

			count++;
			if (count > NOTIFICATION_INTERVAL) {
				leftSet.deleteRange(leftSet.getMinAddress(), addr);
				monitor.setProgress(initial_count - leftSet.getNumAddresses());
				monitor.setMessage(analysisMessage + addr);
				count = 0;
			}

			Instruction instr = listing.getInstructionAt(addr);
			if (instr == null) {
				continue;
			}
			if (!instr.getFlowType().isCall()) {
				continue;
			}
			Reference[] refs = mgr.getFlowReferencesFrom(addr);

			for (Reference ref : refs) {
				if (ref.getReferenceType().isCall()) {
					//
					// get the body
					//   if body has more than one entry point, don't create it
					//
					Address entryAddr = ref.getToAddress();

					// ignore calls to functions that occur immediately after the call
					//
					if (fallthroughCall(program, ref)) {
						continue;
					}

					funcStarts.addRange(entryAddr, entryAddr);
				}

			}
		}

		//
		//  Create functions at all the locations that are called
		//
		// remove any addresses that are already functions
		SymbolIterator symIter =
			program.getSymbolTable().getSymbols(funcStarts, SymbolType.FUNCTION, true);
		AddressSet funcEntryPoints = new AddressSet();
		while (symIter.hasNext()) {
			Symbol funcSymbol = symIter.next();
			if (isPlaceHolderFunctionThatShouldBeFixed(program, listing, funcSymbol)) {
				continue;
			}
			funcEntryPoints.addRange(funcSymbol.getAddress(), funcSymbol.getAddress());
		}
		funcStarts.delete(funcEntryPoints);

		// if only creating thunks
		if (createOnlyThunks && !funcStarts.isEmpty()) {
			// get rid of any functionStarts that aren't a thunk

			AddressSet thunkStarts = new AddressSet();
			AddressIterator iterator = funcStarts.getAddresses(true);
			while (iterator.hasNext()) {
				Address entry = iterator.next();
				Address thunkedAddr = CreateThunkFunctionCmd.getThunkedAddr(program, entry, true);
				if (thunkedAddr != null) {
					thunkStarts.add(entry);
				}
			}
			funcStarts = thunkStarts;
		}

		if (!funcStarts.isEmpty()) {
			AutoAnalysisManager amgr = AutoAnalysisManager.getAnalysisManager(program);
			amgr.createFunction(funcStarts, false);
		}

		return true;
	}

	/**
	 * check if the function body exists, and is a place holder single byte function that needs to be fixed.
	 * 
	 * @return true is this is a single address place holder function that needs fixing
	 */
	private boolean isPlaceHolderFunctionThatShouldBeFixed(Program program, Listing listing, Symbol funcSymbol) {
		Function func = program.getFunctionManager().getFunctionAt(funcSymbol.getAddress());

		if (func == null) {
			return false;
		}
		if (func.getBody().getNumAddresses() > 1) {
			return false;
		}
		Instruction instr = listing.getInstructionAt(func.getEntryPoint());
		if (instr == null) {
			return false;
		}
		// if instruction length longer than the body, or the instruction isn't terminal
		if (instr.getLength() > 1 || !instr.getFlowType().isTerminal()) {
			return true;
		}
		return false;
	}

	/**
	 * Check if this reference is from a call instruction that also
	 *    falls through to the called location.
	 * @param program
	 * @param ref
	 * @return true if the call also falls through to this instruction
	 */
	private boolean fallthroughCall(Program program, Reference ref) {
		// get the instruction that is calling here
		// if it falls through to here, then this is a fallthroughCall
		Address from = ref.getFromAddress();
		Instruction instr = program.getListing().getInstructionAt(from);
		if (instr == null) {
			return false;
		}
		if (instr.getFallThrough() == ref.getToAddress()) {
			return true;
		}
		return false;
	}
}
