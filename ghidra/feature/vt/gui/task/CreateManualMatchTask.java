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
package ghidra.feature.vt.gui.task;

import ghidra.feature.vt.api.main.*;
import ghidra.program.model.listing.Function;
import ghidra.util.task.TaskMonitor;

public class CreateManualMatchTask extends VtTask {

	private final Function sourceFunction;
	private final Function destinationFunction;
	private double PERFECT_SCORE = 1.0;

	protected VTMatch newlyCreatedMatch;

	public CreateManualMatchTask(VTSession session, Function sourceFunction,
			Function destinationFunction) {
		this("Create Manual Match", session, sourceFunction, destinationFunction);
	}

	public CreateManualMatchTask(String name, VTSession session, Function sourceFunction,
			Function destinationFunction) {
		super(name, session);
		this.sourceFunction = sourceFunction;
		this.destinationFunction = destinationFunction;
	}

	@Override
	protected boolean doWork(TaskMonitor monitor) throws Exception {

		VTMatchSet manualMatchSet = session.getManualMatchSet();
		VTMatchInfo manualMatchInfo = createMatch(manualMatchSet);
		newlyCreatedMatch = manualMatchSet.addMatch(manualMatchInfo);
		boolean result = runFollowOnTasks(monitor);

		return result;
	}

	// to be overridden by subclasses to do work in the same transaction
	protected boolean runFollowOnTasks(TaskMonitor monitor) throws Exception {
		return true;
	}

	public VTMatch getNewMatch() {
		return newlyCreatedMatch;
	}

	private VTMatchInfo createMatch(VTMatchSet manualMatchSet) {
		VTMatchInfo matchInfo = new VTMatchInfo(manualMatchSet);
		matchInfo.setSourceAddress(sourceFunction.getEntryPoint());
		matchInfo.setDestinationAddress(destinationFunction.getEntryPoint());
		matchInfo.setSourceLength((int) sourceFunction.getBody().getNumAddresses());
		matchInfo.setDestinationLength((int) destinationFunction.getBody().getNumAddresses());
		matchInfo.setSimilarityScore(new VTScore(PERFECT_SCORE));
		matchInfo.setConfidenceScore(new VTScore(PERFECT_SCORE));
		matchInfo.setAssociationType(VTAssociationType.FUNCTION);
		matchInfo.setTag(null);
		return matchInfo;
	}

	@Override
	protected String getErrorHeader() {
		return "Unexpected exceptions creating a manual match from " + sourceFunction + " to " +
			destinationFunction;
	}
}
