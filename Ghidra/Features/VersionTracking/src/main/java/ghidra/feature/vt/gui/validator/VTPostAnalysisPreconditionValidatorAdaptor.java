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
package ghidra.feature.vt.gui.validator;

import ghidra.app.plugin.core.analysis.validator.PostAnalysisValidator;
import ghidra.feature.vt.api.main.VTSession;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorSplitter;
import docking.widgets.conditiontestpanel.ConditionResult;
import docking.widgets.conditiontestpanel.ConditionStatus;

public abstract class VTPostAnalysisPreconditionValidatorAdaptor extends VTPreconditionValidator {
	private final PostAnalysisValidator sourceValidator;
	private final PostAnalysisValidator destinationValidator;

	public VTPostAnalysisPreconditionValidatorAdaptor(Program sourceProgram,
			Program destinationProgram, VTSession existingResults) {
		super(sourceProgram, destinationProgram, existingResults);
		sourceValidator = createPostAnalysisPreconditionValidator(sourceProgram);
		destinationValidator = createPostAnalysisPreconditionValidator(destinationProgram);
	}

	protected abstract PostAnalysisValidator createPostAnalysisPreconditionValidator(Program program);

	@Override
	public String getDescription() {
		return sourceValidator.getDescription();
	}

	@Override
	public String getName() {
		return sourceValidator.getName();
	}

	@Override
	public String toString() {
		return getName();
	}

	@Override
	public ConditionResult doRun(TaskMonitor monitor) throws CancelledException {
		TaskMonitor[] subMonitors = TaskMonitorSplitter.splitTaskMonitor(monitor, 2);
		ConditionResult sourceResult = sourceValidator.run(subMonitors[0]);
		ConditionResult destinationResult = destinationValidator.run(subMonitors[1]);
		ConditionResult result = combine(sourceResult, destinationResult);
		return result;
	}

	private ConditionResult combine(ConditionResult sourceResult, ConditionResult destinationResult) {
		ConditionStatus sourceStatus = sourceResult.getStatus();
		ConditionStatus destinationStatus = destinationResult.getStatus();
		String sourceMessage = sourceResult.getMessage();
		String destinationMessage = destinationResult.getMessage();
		ConditionStatus status = ConditionStatus.Passed;
		if (sourceStatus == destinationStatus) {
			status = sourceStatus;
		}
		else if (sourceStatus == ConditionStatus.Error ||
			destinationStatus == ConditionStatus.Error) {
			status = ConditionStatus.Error;
		}
		else if (sourceStatus == ConditionStatus.Warning ||
			destinationStatus == ConditionStatus.Warning) {
			status = ConditionStatus.Warning;
		}
		else if (sourceStatus == ConditionStatus.Skipped ||
			destinationStatus == ConditionStatus.Skipped) {
			status = ConditionStatus.Skipped;
		}
		else if (sourceStatus == ConditionStatus.Cancelled ||
			destinationStatus == ConditionStatus.Cancelled) {
			status = ConditionStatus.Cancelled;
		}
		else if (sourceStatus == ConditionStatus.None || destinationStatus == ConditionStatus.None) {
			status = ConditionStatus.None;
		}
		return new ConditionResult(status, combine(sourceMessage, destinationMessage));
	}

	private String combine(String sourceMessage, String destinationMessage) {
		StringBuilder sb = new StringBuilder();
		sb.append(sourceValidator.getProgram().getName());
		sb.append(":\n");
		sb.append(sourceMessage);
		sb.append("\n");
		sb.append(destinationValidator.getProgram().getName());
		sb.append(":\n");
		sb.append(destinationMessage);
		return sb.toString();
	}
}
