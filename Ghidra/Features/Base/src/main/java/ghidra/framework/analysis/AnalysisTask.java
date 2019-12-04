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
package ghidra.framework.analysis;

import ghidra.app.services.Analyzer;
import ghidra.framework.model.UndoableDomainObject;
import ghidra.framework.task.GTask;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class AnalysisTask implements GTask {

	private AnalyzerScheduler analyzerScheduler;
	private AnalysisPhase executionPhase;
	private AnalysisManager analysisManager;

	public AnalysisTask(AnalysisPhase executionPhase, AnalyzerScheduler analyzerScheduler) {
		this.executionPhase = executionPhase;
		this.analyzerScheduler = analyzerScheduler;
		analysisManager = analyzerScheduler.getAnalysisManager();
	}

	@Override
	public String getName() {
		return analyzerScheduler.getAnalyzer().getName();
	}

	@Override
	public void run(UndoableDomainObject domainObject, TaskMonitor monitor)
			throws CancelledException {
		Program program = (Program) domainObject;
		Analyzer analyzer = analyzerScheduler.getAnalyzer();
		AddressSetView addressSet = analyzerScheduler.getAddressSet();

		analyzer.added(program, addressSet, monitor, analysisManager.getMessageLog());
	}

	public int getPriority() {
		return analyzerScheduler.getPriority();
	}

	public AnalysisPhase getPhase() {
		return executionPhase;
	}

	@Override
	public String toString() {
		return getName();
	}
}
