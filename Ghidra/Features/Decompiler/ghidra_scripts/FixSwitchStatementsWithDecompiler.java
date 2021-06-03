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
// Fix any unknown switch instructions with the decompiler.
//
// Your mileage may vary!  This should only be run after existing code has been found.
// The results should be checked for validity.
//
// @category Analysis

import java.util.*;

import ghidra.app.cmd.function.DecompilerSwitchAnalysisCmd;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.parallel.DecompilerCallback;
import ghidra.app.decompiler.parallel.ParallelDecompiler;
import ghidra.app.plugin.core.analysis.SwitchAnalysisDecompileConfigurer;
import ghidra.app.plugin.core.bookmark.BookmarkEditCmd;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.Reference;
import ghidra.util.task.TaskMonitor;

public class FixSwitchStatementsWithDecompiler extends GhidraScript {

	@Override
	public void run() throws Exception {

		Map<Function, Instruction> instructionsByFunction = filterFunctions();

		DecompilerCallback<Void> callback = new DecompilerCallback<Void>(currentProgram,
			new SwitchAnalysisDecompileConfigurer(currentProgram)) {

			@Override
			public Void process(DecompileResults results, TaskMonitor m) throws Exception {

				Function func = results.getFunction();
				DecompilerSwitchAnalysisCmd cmd = new DecompilerSwitchAnalysisCmd(results);
				cmd.applyTo(currentProgram);
				Instruction instr = instructionsByFunction.get(func);
				BookmarkEditCmd bmcmd = new BookmarkEditCmd(instr.getMinAddress(),
					BookmarkType.INFO, "FixSwitchStatementsWithDecompiler", "Fixed switch stmt");
				bmcmd.applyTo(currentProgram);
				return null;
			}
		};

		Set<Function> functions = instructionsByFunction.keySet();
		try {
			ParallelDecompiler.decompileFunctions(callback, functions, monitor);
		}
		finally {
			callback.dispose();
		}
	}

	private Map<Function, Instruction> filterFunctions() {

		// search for all dynamic jump locations that have no target

		Map<Function, Instruction> results = new HashMap<>();
		Listing list = currentProgram.getListing();
		FunctionManager functionManager = currentProgram.getFunctionManager();
		InstructionIterator it = list.getInstructions(true);
		while (it.hasNext()) {

			if (monitor.isCancelled()) {
				return Collections.emptyMap();
			}

			Instruction instr = it.next();
			FlowType flowType = instr.getFlowType();
			if (!flowType.isJump() || !flowType.isComputed()) {
				continue;
			}

			Reference[] refsFrom = instr.getReferencesFrom();
			if (refsFrom.length == 0 || refsFrom.length > 2) {
				continue;
			}

			Function func = functionManager.getFunctionContaining(instr.getMinAddress());
			if (func == null) {
				println("No function at " + instr.getMinAddress());
				continue;
			}
			results.put(func, instr);
		}
		return results;
	}
}
