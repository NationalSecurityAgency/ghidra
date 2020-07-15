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

import java.util.*;

import org.apache.commons.collections4.map.HashedMap;

import ghidra.app.services.Analyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.model.UndoableDomainObject;
import ghidra.framework.task.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class AnalysisManager {

	private AnalysisRecipe recipe;
	private Map<AnalyzerType, List<AnalyzerScheduler>> triggerMap;
	private List<AnalyzerScheduler> schedulers = new ArrayList<AnalyzerScheduler>();
	private GTaskManager taskManager;
	private AnalysisPhase currentPhase;
	private MessageLog messageLog = new MessageLog();

	public AnalysisManager(Program program) {
		this(program, AnalysisRecipeBuilder.getRecipe(program));
	}

	public AnalysisManager(Program program, AnalysisRecipe recipe) {
		this.recipe = recipe;
		taskManager = GTaskManagerFactory.getTaskManager(program);
		triggerMap = new HashedMap<AnalyzerType, List<AnalyzerScheduler>>();
		initialize();
	}

	private void initialize() {
		List<Analyzer> analyzerList = recipe.getAnalyzers();
		for (int rank = 0; rank < analyzerList.size(); rank++) {
			Analyzer analyzer = analyzerList.get(rank);
			AnalyzerScheduler scheduler = new AnalyzerScheduler(this, analyzer, rank);
			AnalyzerType analyzerType = analyzer.getAnalysisType();
			addScheduler(analyzerType, scheduler);
		}
		setPhase(recipe.getLastPhase());
	}

	private void setPhase(AnalysisPhase phase) {
		currentPhase = phase;
		for (AnalyzerScheduler scheduler : schedulers) {
			scheduler.setPhase(phase);
		}
	}

	private void addScheduler(AnalyzerType analysisType, AnalyzerScheduler analyzerScheduler) {
		schedulers.add(analyzerScheduler);
		List<AnalyzerScheduler> list = triggerMap.get(analysisType);
		if (list == null) {
			list = new ArrayList<AnalyzerScheduler>();
			triggerMap.put(analysisType, list);
		}
		list.add(analyzerScheduler);
	}

	public void runAnalysis(AddressSet addressSet) {
		if (!currentPhase.equals(recipe.getLastPhase())) {
			Msg.showWarn(this, null, "Analysis Already Running!",
				"Please wait for the current analysis to complete before running analysis again.");
			return;
		}
		List<AnalysisPhase> analysisPhases = recipe.getAnalysisPhases();
		boolean isFirstPhase = true;
		taskManager.setSuspended(true);
		for (AnalysisPhase analysisPhase : analysisPhases) {
			taskManager.scheduleTask(new StartPhaseTask(analysisPhase), 0, analysisPhase.getName());
			if (isFirstPhase) {
				isFirstPhase = false;
				taskManager.scheduleTask(new KickStartAnalyzersTask(addressSet), 1,
					analysisPhase.getName());
			}
		}
		taskManager.setSuspended(false);

	}

	public void addTaskListener(GTaskListener listener) {
		taskManager.addTaskListener(listener);
	}

	public void removeTaskListener(GTaskListener listener) {
		taskManager.removeTaskListener(listener);
	}

	public void waitForAnalysis(long timeoutMillis) {
		taskManager.waitWhileBusy(timeoutMillis);
	}

	void scheduleAnalysisTask(AnalysisTask task) {
		taskManager.scheduleTask(task, 1000 + task.getPriority() * 10, task.getPhase().getName());
	}

	public List<AnalysisPhase> getPhases() {
		return recipe.getAnalysisPhases();
	}

	void triggerAnalysis(AnalyzerType analyzerType, AddressSetView addressSet) {
		List<AnalyzerScheduler> list = triggerMap.get(analyzerType);
		if (list == null) {
			return;
		}
		for (AnalyzerScheduler analyzerScheduler : list) {
			analyzerScheduler.added(addressSet);
		}
	}

	private class StartPhaseTask implements GTask {

		private AnalysisPhase phase;

		public StartPhaseTask(AnalysisPhase phase) {
			this.phase = phase;
		}

		@Override
		public String getName() {
			return phase.getName();
		}

		@Override
		public void run(UndoableDomainObject domainObject, TaskMonitor monitor)
				throws CancelledException {
			Msg.debug(this, "Starting phase " + phase);
			setPhase(phase);
		}
	}

	private class KickStartAnalyzersTask implements GTask {

		private AddressSetView restrictSet;

		public KickStartAnalyzersTask(AddressSet addressSet) {
			this.restrictSet = addressSet;
		}

		@Override
		public String getName() {
			return "Analysis Address Set Primer Task";
		}

		@Override
		public void run(UndoableDomainObject domainObject, TaskMonitor monitor)
				throws CancelledException {

			Program program = (Program) domainObject;
			if (restrictSet == null || restrictSet.isEmpty()) {
				analyzeExternalSpace(program);
				restrictSet = program.getMemory(); // process entire program
			}

			triggerAnalysis(AnalyzerType.BYTE_ANALYZER, restrictSet);

			if (program.getListing().getNumInstructions() != 0) {
				triggerAnalysis(AnalyzerType.INSTRUCTION_ANALYZER, restrictSet);
			}

			if (program.getListing().getNumDefinedData() != 0) {
				triggerAnalysis(AnalyzerType.DATA_ANALYZER, restrictSet);
			}

			if (program.getFunctionManager().getFunctions(true).hasNext()) {
				triggerAnalysis(AnalyzerType.FUNCTION_ANALYZER, restrictSet);
				triggerAnalysis(AnalyzerType.FUNCTION_SIGNATURES_ANALYZER, restrictSet);
			}
		}

		private void analyzeExternalSpace(Program program) {
			triggerAnalysis(AnalyzerType.BYTE_ANALYZER,
				new AddressSet(AddressSpace.EXTERNAL_SPACE.getMinAddress(),
					AddressSpace.EXTERNAL_SPACE.getMaxAddress()));
		}

		@Override
		public String toString() {
			return getName() + ": " + restrictSet;
		}
	}

	public MessageLog getMessageLog() {
		return messageLog;
	}

}
