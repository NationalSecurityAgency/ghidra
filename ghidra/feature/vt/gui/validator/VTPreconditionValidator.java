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

import ghidra.feature.vt.api.main.VTSession;
import ghidra.program.model.listing.Program;
import ghidra.util.classfinder.ExtensionPoint;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import docking.widgets.conditiontestpanel.*;

/**
 * Validator objects looks for specific preconditions that should exist in order to get optimal
 * results when applying a program correlator.
 *
 */
public abstract class VTPreconditionValidator implements ConditionTester, ExtensionPoint {
	protected final Program sourceProgram;
	protected final Program destinationProgram;
	protected final VTSession existingResults;

	public VTPreconditionValidator(Program sourceProgram, Program destinationProgram,
			VTSession existingResults) {
		this.sourceProgram = sourceProgram;
		this.destinationProgram = destinationProgram;
		this.existingResults = existingResults;
	}

	@Override
	public String toString() {
		return getName();
	}

	public final ConditionResult run(TaskMonitor monitor) throws CancelledException {

		// make sure the program isn't closed while we are working
		if (!sourceProgram.addConsumer(this)) {
			return new ConditionResult(ConditionStatus.Cancelled);
		}

		if (!destinationProgram.addConsumer(this)) {
			sourceProgram.release(this);
			return new ConditionResult(ConditionStatus.Cancelled);
		}

		try {
			return doRun(monitor);
		}
		finally {
			sourceProgram.release(this);
			destinationProgram.release(this);
		}
	}

	public abstract ConditionResult doRun(TaskMonitor monitor) throws CancelledException;
}
