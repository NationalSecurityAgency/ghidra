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
package ghidra.app.cmd.function;

import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.Reference;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Command for analyzing the Stack; the command is run in the background.
 */
public class FunctionPurgeAnalysisCmd extends BackgroundCommand {
	private AddressSetView entryPoints;
	private Program program;

	/**
	 * Constructs a new command for analyzing the Stack.
	 * @param entries and address set indicating the entry points of functions that have 
	 * stacks to be analyzed.
	 * @param forceProcessing flag to force processing of stack references even if the stack
	 *           has already been defined.
	 */
	public FunctionPurgeAnalysisCmd(AddressSetView entries) {
		super("Compute Function Purge", true, true, false);
		entryPoints = entries;
	}

	/**
	 * 
	 * @see ghidra.framework.cmd.BackgroundCommand#applyTo(ghidra.framework.model.DomainObject, ghidra.util.task.TaskMonitor)
	 */
	@Override
	public boolean applyTo(DomainObject obj, TaskMonitor monitor) {
		program = (Program) obj;

		Processor processor = program.getLanguage().getProcessor();
		if (program.getLanguage().getDefaultSpace().getSize() > 32 ||
			!processor.equals(Processor.findOrPossiblyCreateProcessor("x86"))) {
			Msg.error(this,
				"Unsupported operation for language " + program.getLanguage().getLanguageID());
			return false;
		}

		AddressSetView set = entryPoints;

		long maxCount = set.getNumAddresses();

		monitor.setMaximum(maxCount);
		monitor.setProgress(0);

		for (Function function : program.getFunctionManager().getFunctions(entryPoints, true)) {
			if (monitor.isCancelled()) {
				break;
			}

			set = set.subtract(
				new AddressSet(program, entryPoints.getMinAddress(), function.getEntryPoint()));
			monitor.setProgress(maxCount - set.getNumAddresses());

			monitor.setMessage("Purge " + function.getName());

			try {
				analyzeFunction(function, monitor);
			}
			catch (CancelledException e) {
				// do nothing
			}
		}
		if (monitor.isCancelled()) {
			setStatusMsg("Function Purge analysis cancelled");
			return false;
		}
		return true;
	}

	/**
	 * Analyze a function to build a stack frame based on stack references.
	 * @param function function to be analyzed
	 * @param monitor the task monitor that is checked to see if the command has
	 * been cancelled.
	 * @throws CancelledException if the user canceled this command
	 */
	private void analyzeFunction(Function function, TaskMonitor monitor) throws CancelledException {

		int purge = -1;

		if (function != null) {
			purge = function.getStackPurgeSize();
		}
		if (purge == -1 || purge > 128 || purge < -128) {
			purge = locatePurgeReturn(program, function, monitor);
			// if couldn't find it, don't set it!
			if (purge != -1) {
				function.setStackPurgeSize(purge);
			}
		}
	}

	private int locatePurgeReturn(Program program, Function func, TaskMonitor monitor) {
		AddressSetView body = func.getBody();

		int returnPurge = findReturnPurge(program, body);
		if (returnPurge != -1) {
			return returnPurge;
		}

		// look harder, maybe something wrong with body, compute with flow.
		body = CreateFunctionCmd.getFunctionBody(program, func.getEntryPoint(), monitor);
		returnPurge = findReturnPurge(program, body);

		return returnPurge;
	}

	private int findReturnPurge(Program program, AddressSetView body) {
		int tempPurge;
		InstructionIterator iter = program.getListing().getInstructions(body, true);
		int count = 2048;
		while (iter.hasNext() && count > 0) {
			count--;
			Instruction instr = iter.next();

			FlowType ftype = instr.getFlowType();
			if (ftype.isTerminal()) {
				if (instr.getMnemonicString().compareToIgnoreCase("ret") == 0) {
					tempPurge = 0;
					Scalar scalar = instr.getScalar(0);
					if (scalar != null) {
						tempPurge = (int) scalar.getSignedValue();
						return tempPurge;
					}
					return 0;
				}
				else if (ftype.isCall()) {
					// is an override call-return, terminal/call
					// find a reference to a function, and take it's purge
					Reference[] referencesFrom = instr.getReferencesFrom();
					for (Reference reference : referencesFrom) {
						if (reference.getReferenceType().isFlow()) {
							Function functionAt = program.getFunctionManager().getFunctionAt(
								reference.getToAddress());
							// don't take the purge of a non-returning function
							if (functionAt != null && !functionAt.hasNoReturn()) {
								return functionAt.getStackPurgeSize();
							}
						}
					}
				}
			}
		}

		return -1;
	}

}
