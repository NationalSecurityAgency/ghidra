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

import static org.junit.Assert.assertEquals;

import java.util.ArrayList;
import java.util.List;

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.app.services.*;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.listing.Program;

public class AnalyzerSchedulerTest extends AbstractGenericTest {

	private static final int HIGHEST_RANK = 0;

	private AnalyzerScheduler scheduler;
	private ProgramDB program;
	private AnalysisManagerSpy analysisMgrSpy;
	private List<Analyzer> analyzers = new ArrayList<Analyzer>();
	private Analyzer1 scheduledAnalyzer;

	private AnalysisRecipe recipe;

	public AnalyzerSchedulerTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {
		ProgramBuilder programBuilder = new ProgramBuilder();
		programBuilder.createMemory("AAA", "0x100", 0x1000);
		program = programBuilder.getProgram();
		analysisMgrSpy = new AnalysisManagerSpy(program);
		scheduledAnalyzer = new Analyzer1();
		analyzers.add(scheduledAnalyzer);
		recipe = new AnalysisRecipe("Test", analyzers, program);
		scheduler = new AnalyzerScheduler(analysisMgrSpy, scheduledAnalyzer, HIGHEST_RANK);
	}

	@Test
    public void testDisabledState() {
		recipe.setAnalyzerEnablement(scheduledAnalyzer, false);
		scheduler.setPhase(recipe.getLastPhase());
		scheduler.added(program.getMemory());
		assertEquals(0, analysisMgrSpy.getScheduledTaskCount());
	}

	@Test
    public void testDelayedState() {
		AnalysisPhase phase = recipe.createPhase();
		scheduler.setPhase(phase);
		scheduler.added(program.getMemory());
		assertEquals(1, analysisMgrSpy.getScheduledTaskCount());
		assertEquals(recipe.getLastPhase(), analysisMgrSpy.getTask().getPhase());

	}

	@Test
    public void testEnabledState() {
		AnalysisPhase phase = recipe.createPhase();
		recipe.setAnalyzerStartPhase(scheduledAnalyzer, phase);
		scheduler.setPhase(phase);
		scheduler.added(program.getMemory());
		assertEquals(1, analysisMgrSpy.getScheduledTaskCount());
		assertEquals(phase, analysisMgrSpy.getTask().getPhase());
	}

//	private AnalysisPhase createPhase(AnalyzerStatus status) {
//		AnalysisPhase phase = recipe.createPhaseBefore(recipe.getLastPhase(), "Phase 1");
//		recipe.setAnalyzerStatus(scheduledAnalyzer, phase, status);
//		return phase;
//	}

	private class AnalysisManagerSpy extends AnalysisManager {
		private List<AnalysisTask> tasks = new ArrayList<AnalysisTask>();

		public AnalysisManagerSpy(Program program) {
			super(program);
		}

		AnalysisTask getTask() {
			return tasks.get(0);
		}

		@Override
		void scheduleAnalysisTask(AnalysisTask task) {
			tasks.add(task);
		}

		int getScheduledTaskCount() {
			return tasks.size();
		}
	}

	public static class Analyzer1 extends AnalyzerTestStub {

		Analyzer1() {
			super("Analyzer1", AnalyzerType.BYTE_ANALYZER, true, new AnalysisPriority("1", 1));
		}
	}
}
