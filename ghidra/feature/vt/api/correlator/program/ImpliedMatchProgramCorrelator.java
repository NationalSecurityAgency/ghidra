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
package ghidra.feature.vt.api.correlator.program;

import ghidra.feature.vt.api.main.VTMatchSet;
import ghidra.feature.vt.api.main.VTScore;
import ghidra.feature.vt.api.util.VTAbstractProgramCorrelator;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class ImpliedMatchProgramCorrelator extends VTAbstractProgramCorrelator {

	public static final VTScore MANUAL_SCORE = new VTScore(1.0);
	public static final String NAME = "Implied Match";

	public ImpliedMatchProgramCorrelator(Program sourceProgram, Program destinationProgram) {
		super(null, sourceProgram, sourceProgram.getMemory(), destinationProgram,
			destinationProgram.getMemory(), new ToolOptions(NAME));
	}

	@Override
	protected void doCorrelate(VTMatchSet matchSet, TaskMonitor monitor) throws CancelledException {
		// Do Nothing
	}

	public String getName() {
		return NAME;
	}
}
