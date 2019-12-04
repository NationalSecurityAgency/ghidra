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
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;

public class AnalyzerScheduler {

	private final AnalysisManager analysisManager;
	private final Analyzer analyzer;
	private int rank;
	private boolean enabled;
	private AddressSet addressSet = new AddressSet();

	/**
	 * The phase to execute this scheduler's analyzer - may be current phase or a future phase
	 *  if current status is delayed.
	 */
	private AnalysisPhase executionPhase;

	public AnalyzerScheduler(AnalysisManager analysisMgr, Analyzer analyzer, int rank) {
		this.analysisManager = analysisMgr;
		this.rank = rank;
		this.analyzer = analyzer;
	}

	synchronized void setPhase(AnalysisPhase phase) {
		executionPhase = phase.getExecutionPhase(analyzer);
		enabled = executionPhase != null;
	}

	synchronized void added(AddressSetView set) {
		if (!enabled) {
			return;
		}
		boolean alreadyScheduled = !addressSet.isEmpty();
		addressSet.add(set);

		if (!alreadyScheduled) {
			analysisManager.scheduleAnalysisTask(new AnalysisTask(executionPhase, this));
		}
	}

	public Analyzer getAnalyzer() {
		return analyzer;
	}

	public int getPriority() {
		return rank;
	}

	public AnalysisManager getAnalysisManager() {
		return analysisManager;
	}

	public synchronized AddressSetView getAddressSet() {
		AddressSetView set = addressSet;
		addressSet = new AddressSet();
		return set;
	}

	@Override
	public String toString() {
		return analyzer.getName();
	}
}
