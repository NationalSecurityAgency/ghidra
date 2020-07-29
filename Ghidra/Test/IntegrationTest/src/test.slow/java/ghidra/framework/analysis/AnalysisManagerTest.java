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

import static org.junit.Assert.*;

import java.io.*;
import java.util.ArrayList;

import org.junit.*;

import generic.jar.ResourceFile;
import ghidra.app.plugin.core.osgi.BundleHost;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.app.services.*;
import ghidra.framework.task.GScheduledTask;
import ghidra.framework.task.GTaskListener;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.symbol.Symbol;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import mockit.*;

public class AnalysisManagerTest extends AbstractGhidraHeadlessIntegrationTest {
	@Mocked
	GTaskListener listener;

	private ProgramBuilder programBuilder;
	private ProgramDB program;
	private AnalysisManager analysisManager;
	private ArrayList<Analyzer> analyzers;

	class TaskTypeDelegate implements Delegate<GScheduledTask> {
		private String name;

		TaskTypeDelegate(String name) {
			this.name = name;
		}

		void validate(GScheduledTask scheduledTask) {

			String clazz = scheduledTask.getTask().getClass().getSimpleName();
			if (!clazz.equals(name)) {
				assertEquals("Found unexpected class.  Found task with name '" +
					scheduledTask.getTask().getName() + "'", name, clazz);
			}
		}
	}

	class TaskNameDelegate implements Delegate<GScheduledTask> {
		private String name;

		TaskNameDelegate(String name) {
			this.name = name;
		}

		void validate(GScheduledTask scheduledTask) {
			Assert.assertEquals(name, scheduledTask.getTask().getName());
		}
	}

	@Before
	public void setUp() throws Exception {
		programBuilder = new ProgramBuilder();
		programBuilder.createMemory("AAA", "0x100", 0x1000);
		program = programBuilder.getProgram();
		analyzers = new ArrayList<>();

		// make sure the user scripts subdirectory exists for createScriptFile
		File userScriptsDir = new File(GhidraScriptUtil.USER_SCRIPTS_DIR);
		userScriptsDir.mkdirs();
		
		GhidraScriptUtil.initialize(new BundleHost(), null);
	}

	@After
	public void cleanup() {
		GhidraScriptUtil.dispose();
	}

	@Test
	public void testTwoAnalyzersWithOnePhases() {

		analyzers.add(new Analyzer1());
		analyzers.add(new Analyzer2());
		AnalysisRecipe recipe = new AnalysisRecipe("Test Recipe", analyzers, program);
		analysisManager = new AnalysisManager(program, recipe);
		analysisManager.addTaskListener(listener);

		analysisManager.runAnalysis(null);
		analysisManager.waitForAnalysis(1000);

		new VerificationsInOrder() {
			{
				listener.initialize();
				listener.taskStarted(with(new TaskTypeDelegate("StartPhaseTask")));
				listener.taskCompleted(with(new TaskTypeDelegate("StartPhaseTask")), null);
				listener.taskStarted(with(new TaskTypeDelegate("KickStartAnalyzersTask")));
				listener.taskCompleted(with(new TaskTypeDelegate("KickStartAnalyzersTask")), null);
				listener.taskStarted(with(new TaskNameDelegate("Analyzer1")));
				listener.taskCompleted(with(new TaskNameDelegate("Analyzer1")), null);
				listener.taskStarted(with(new TaskNameDelegate("Analyzer2")));
				listener.taskCompleted(with(new TaskNameDelegate("Analyzer2")), null);
			}
		};

	}

	@Test
	public void testTwoAnalyzersWithTwoPhases() {
		analyzers.add(new Analyzer1());
		analyzers.add(new Analyzer2());
		AnalysisRecipe recipe = new AnalysisRecipe("Test Recipe", analyzers, program);
		AnalysisPhase firstPhase = recipe.createPhase();
		recipe.setAnalyzerStartPhase(analyzers.get(0), firstPhase);

		analysisManager = new AnalysisManager(program, recipe);
		analysisManager.addTaskListener(listener);

		analysisManager.runAnalysis(null);
		analysisManager.waitForAnalysis(1000);

		new VerificationsInOrder() {
			{
				listener.initialize();
				listener.taskStarted(with(new TaskTypeDelegate("StartPhaseTask")));
				listener.taskCompleted(with(new TaskTypeDelegate("StartPhaseTask")), null);
				listener.taskStarted(with(new TaskTypeDelegate("KickStartAnalyzersTask")));
				listener.taskCompleted(with(new TaskTypeDelegate("KickStartAnalyzersTask")), null);
				listener.taskStarted(with(new TaskNameDelegate("Analyzer1")));
				listener.taskCompleted(with(new TaskNameDelegate("Analyzer1")), null);
				listener.taskStarted(with(new TaskTypeDelegate("StartPhaseTask")));
				listener.taskCompleted(with(new TaskTypeDelegate("StartPhaseTask")), null);
				listener.taskStarted(with(new TaskNameDelegate("Analyzer2")));
				listener.taskCompleted(with(new TaskNameDelegate("Analyzer2")), null);
			}
		};
	}

	@Test
	public void testTwoAnalyzersWithTwoPhasesAnalyzerInSecondPhaseOff() {
		analyzers.add(new Analyzer1());
		analyzers.add(new Analyzer2());
		AnalysisRecipe recipe = new AnalysisRecipe("Test Recipe", analyzers, program);
		AnalysisPhase firstPhase = recipe.createPhase();
		recipe.setAnalyzerStartPhase(analyzers.get(0), firstPhase);
		recipe.setAnalyzerEnablement(analyzers.get(1), false);

		analysisManager = new AnalysisManager(program, recipe);
		analysisManager.addTaskListener(listener);

		analysisManager.runAnalysis(null);
		analysisManager.waitForAnalysis(1000);

		new VerificationsInOrder() {
			{
				listener.initialize();
				listener.taskStarted(with(new TaskTypeDelegate("StartPhaseTask")));
				listener.taskCompleted(with(new TaskTypeDelegate("StartPhaseTask")), null);
				listener.taskStarted(with(new TaskTypeDelegate("KickStartAnalyzersTask")));
				listener.taskCompleted(with(new TaskTypeDelegate("KickStartAnalyzersTask")), null);
				listener.taskStarted(with(new TaskNameDelegate("Analyzer1")));
				listener.taskCompleted(with(new TaskNameDelegate("Analyzer1")), null);
				listener.taskStarted(with(new TaskTypeDelegate("StartPhaseTask")));
				listener.taskCompleted(with(new TaskTypeDelegate("StartPhaseTask")), null);
				listener.taskStarted((GScheduledTask) any);
				times = 0; // make sure no more taskStarted calls are mode
			}
		};

	}

	@Test
	public void testSciptAnalyzer() throws Exception {
		final ResourceFile scriptFile = createScriptFile();
		analyzers.add(new Analyzer1());
		GhidraScriptAnalyzerAdapter analyzer =
			new GhidraScriptAnalyzerAdapter(scriptFile, AnalyzerType.BYTE_ANALYZER, 10000);
		analyzers.add(analyzer);
		AnalysisRecipe recipe = new AnalysisRecipe("Test Recipe", analyzers, program);
		analysisManager = new AnalysisManager(program, recipe);
		analysisManager.addTaskListener(listener);

		analysisManager.runAnalysis(null);
		analysisManager.waitForAnalysis(10000);

		// verify that the script ran
		Symbol symbol = getUniqueSymbol(program, "TEST_SYMBOL");
		assertNotNull(symbol);

		new VerificationsInOrder() {
			{
				listener.initialize();
				listener.taskStarted(with(new TaskTypeDelegate("StartPhaseTask")));
				listener.taskCompleted(with(new TaskTypeDelegate("StartPhaseTask")), null);
				listener.taskStarted(with(new TaskTypeDelegate("KickStartAnalyzersTask")));
				listener.taskCompleted(with(new TaskTypeDelegate("KickStartAnalyzersTask")), null);
				listener.taskStarted(with(new TaskNameDelegate("Analyzer1")));
				listener.taskCompleted(with(new TaskNameDelegate("Analyzer1")), null);
				listener.taskStarted(with(new TaskNameDelegate("Script: " + scriptFile.getName())));
				listener.taskCompleted(
					with(new TaskNameDelegate("Script: " + scriptFile.getName())), null);
				listener.taskStarted((GScheduledTask) any);
				times = 0; // make sure no more taskStarted calls are mode
			}
		};

	}

	private ResourceFile createScriptFile() throws Exception {
		ResourceFile newScriptFile = createTempScriptFile("TestAnalyzerScript");
		String filename = newScriptFile.getName();
		String className = filename.replaceAll("\\.java", "");

		//@formatter:off
		String newScript =
			"import ghidra.app.script.GhidraScript;\n\n"+
			"import ghidra.program.model.address.Address;\n"+
			"import ghidra.program.model.symbol.SourceType;\n"+
			"public class "+className+" extends GhidraScript {\n\n"+
			"	@Override\n"+
			"	protected void run() throws Exception {\n"+
			"		Address minAddress = currentProgram.getMinAddress();\n"+
			"		currentProgram.getSymbolTable().createLabel(minAddress, \"TEST_SYMBOL\",\n"+
			"			SourceType.USER_DEFINED);\n"+
			"	}\n\n"+
			"}\n";
		//@formatter:on

		writeStringToFile(newScriptFile, newScript);

		return newScriptFile;
	}

	private void writeStringToFile(ResourceFile file, String string) throws IOException {
		BufferedWriter writer = new BufferedWriter(new FileWriter(file.getFile(false)));
		writer.write(string);
		writer.close();
	}

	private ResourceFile createTempScriptFile(String name) throws IOException {
		File userScriptsDir = new File(GhidraScriptUtil.USER_SCRIPTS_DIR);
		if (name.length() > 50) {
			// too long and the script manager complains
			name = name.substring(name.length() - 50);
		}
		File tempFile = File.createTempFile(name, ".java", userScriptsDir);
		tempFile.deleteOnExit();
		return new ResourceFile(tempFile);
	}

	public static class Analyzer1 extends AnalyzerTestStub {

		Analyzer1() {
			super("Analyzer1", AnalyzerType.BYTE_ANALYZER, true, new AnalysisPriority("1", 1));
		}
	}

	public static class Analyzer2 extends AnalyzerTestStub {

		Analyzer2() {
			super("Analyzer2", AnalyzerType.BYTE_ANALYZER, true, new AnalysisPriority("2", 2));
		}
	}
}
