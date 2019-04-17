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
package ghidra.app.plugin.core.analysis.validator;

import docking.widgets.conditiontestpanel.ConditionResult;
import docking.widgets.conditiontestpanel.ConditionStatus;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class PercentAnalyzedValidator extends PostAnalysisValidator {
	private static final String NAME = "Percent Analyzed Validator";

	public static final String COVERAGE_THRESHOLD = "Minimum analysis coverage threshold";
	public static final float COVERAGE_THRESHOLD_DEFAULT = (float) 0.75;

	public PercentAnalyzedValidator(Program program) {
		super(program);
	}

	@Override
	public ConditionResult doRun(TaskMonitor monitor) {
		float threshold = COVERAGE_THRESHOLD_DEFAULT;
		ConditionStatus status = ConditionStatus.Passed;
		StringBuilder warnings = new StringBuilder();
		float percent;
		try {
			percent = checkPercentAnalyzed(program, monitor);
		}
		catch (MemoryAccessException e) {
			return new ConditionResult(ConditionStatus.Error, "Error accessing memory in " +
				program.getDomainFile().getName() + ": " + e.getMessage());
		}
		catch (CancelledException e) {
			return new ConditionResult(ConditionStatus.Cancelled);
		}
		if (percent < threshold) {
			status = ConditionStatus.Warning;
			warnings.append(program.getDomainFile().getName() +
				" percent disassembled/defined in executable memory = " + format(percent) + "\n");
		}
		return new ConditionResult(status, warnings.toString());
	}

	private static String format(float percent) {
		return String.format("%.1f%%", percent * 100.0);
	}

	private float checkPercentAnalyzed(Program prog, TaskMonitor monitor)
			throws MemoryAccessException, CancelledException {

		//make sure we only get executable memory that is initialized
		AddressSetView execMemSet = prog.getMemory().getExecuteSet();
		AddressSetView initMemSet = prog.getMemory().getLoadedAndInitializedAddressSet();
		AddressSetView execMemSetInitialized = execMemSet.intersect(initMemSet);
		monitor.setIndeterminate(false);

//		int myExecSetLen = 0;
//		MemoryBlock[] blocks = prog.getMemory().getBlocks();
//		for (int i = 0; i < blocks.length && !monitor.isCancelled(); i++) {
//			monitor.incrementProgress(1);
//			if (blocks[i].isExecute()) {
//				myExecSetLen += blocks[i].getSize();
//			}
//		}

		long numPossibleDefined = execMemSetInitialized.getNumAddresses();
		monitor.initialize(numPossibleDefined);

		InstructionIterator instIter =
			prog.getListing().getInstructions(execMemSetInitialized, true);
		int instCount = 0;
		while (!monitor.isCancelled() && instIter.hasNext()) {

			Instruction inst = instIter.next();
			int length = inst.getBytes().length;
			monitor.incrementProgress(length);
			instCount += length;
		}

		monitor.checkCanceled();

		DataIterator dataIter = prog.getListing().getData(execMemSetInitialized, true);
		int dataCount = 0;
		while (!monitor.isCancelled() && dataIter.hasNext()) {
			Data data = dataIter.next();
			int length = data.getLength();
			monitor.incrementProgress(length);
			if (data.isDefined()) {
				dataCount += length;
			}
		}

		monitor.setProgress(numPossibleDefined);

		int totalDefined = instCount + dataCount;
		float coverage = (float) totalDefined / (float) numPossibleDefined;
		//println("Executable Memory Length = " + numPossibleDefined);
		//println("MyExecSetLen = " + myExecSetLen);
		//println("Defined Instruction Bytes = " + instCount);
		//println("Defined Data Bytes = " + dataCount);

		//println("Total Defined Bytes = " + totalDefined);
		return coverage;
	}

	@Override
	public String getDescription() {
		return "Make sure program is at least " + format(COVERAGE_THRESHOLD_DEFAULT) +
			" disassembled/defined";
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
