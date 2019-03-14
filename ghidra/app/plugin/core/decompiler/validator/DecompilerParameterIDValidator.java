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
package ghidra.app.plugin.core.decompiler.validator;

import ghidra.app.plugin.core.analysis.validator.PostAnalysisValidator;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import docking.widgets.conditiontestpanel.ConditionResult;
import docking.widgets.conditiontestpanel.ConditionStatus;

public class DecompilerParameterIDValidator extends PostAnalysisValidator {
	private static final String NAME = "Decompiler Parameter ID Validator";

	public static final String MIN_NUM_FUNCS = "Minimum analysis threshold (% of funcs)";
	public static final int MIN_NUM_FUNCS_DEFAULT = 1;

	public DecompilerParameterIDValidator(Program program) {
		super(program);
	}

	@Override
	public ConditionResult doRun(TaskMonitor monitor) {
		int threshold = MIN_NUM_FUNCS_DEFAULT;
		ConditionStatus status = ConditionStatus.Passed;
		StringBuilder warnings = new StringBuilder();
		int number;
		number = checkNumberAnalyzed(program, monitor);
		if (number < threshold) {
			status = ConditionStatus.Warning;
			warnings.append(program.getDomainFile().getName() +
				" number of functions with signatures from the decompiler parameter id analyzer = " +
				number + "\n");
		}
		return new ConditionResult(status, warnings.toString());
	}

	private static int checkNumberAnalyzed(Program prog, TaskMonitor monitor) {
		FunctionIterator funcIter = prog.getFunctionManager().getFunctions(true);
		int numFuncsWithParameterID = 0;

		monitor.setIndeterminate(false);
		monitor.initialize(prog.getFunctionManager().getFunctionCount());
		while (funcIter.hasNext() && !monitor.isCancelled()) {
			monitor.incrementProgress(1);
			Function func = funcIter.next();
			Address address = func.getEntryPoint();
			Instruction inst = prog.getListing().getInstructionAt(address);

			if (inst != null) {
				final SourceType signatureSource = func.getSignatureSource();
				if (signatureSource == SourceType.ANALYSIS) {
					++numFuncsWithParameterID;
				}
			}
		}

		return numFuncsWithParameterID;
	}

	@Override
	public String getDescription() {
		return "Make sure at least " + MIN_NUM_FUNCS_DEFAULT +
			" function(s) have signatures from the decompiler parameter id analyzer";
	}

	@Override
	public String getName() {
		return NAME;
	}

	@Override
	public String toString() {
		return getName();
	}
}
