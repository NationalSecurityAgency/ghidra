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
package ghidra.app.plugin.core.analysis.validator;

import ghidra.program.model.listing.Program;
import ghidra.util.classfinder.ExtensionPoint;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import docking.widgets.conditiontestpanel.*;

public abstract class PostAnalysisValidator implements ConditionTester, ExtensionPoint {
	protected final Program program;

	public PostAnalysisValidator(Program program) {
		this.program = program;
	}

	public Program getProgram() {
		return program;
	}

	public final ConditionResult run(TaskMonitor monitor) throws CancelledException {

		if (!program.addConsumer(this)) {
			return new ConditionResult(ConditionStatus.Cancelled);
		}

		try {

			return doRun(monitor);
		}
		finally {
			program.release(this);
		}
	}

	public abstract ConditionResult doRun(TaskMonitor monitor) throws CancelledException;
}
