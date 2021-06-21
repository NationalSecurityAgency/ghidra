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
package ghidra.app.plugin.core.analysis;

import static org.junit.Assert.*;

import java.util.*;

import javax.swing.JComponent;
import javax.swing.table.TableModel;

import org.junit.*;

import docking.widgets.OptionDialog;
import ghidra.GhidraOptions;
import ghidra.framework.model.Project;
import ghidra.framework.options.Options;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginClassManager;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;

public class AnalyzeAllOpenProgramsTaskTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private PluginToolStub tool;
	private List<Program> openPrograms = new ArrayList<>();

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = new PluginToolStub(env.getProject());
	}

	private Program buildProgram(String name, String languageID) throws Exception {
		ProgramBuilder builder = new ProgramBuilder(name, languageID);
		builder.createMemory("test1", "0x1000", 0x2000);
		return builder.getProgram();
	}

	@After
	public void tearDown() throws Exception {
		for (Program program : openPrograms) {
			env.release(program);
		}
		tool.close();
		env.dispose();
	}

	@Test
	public void testAnalyzeAllPrograms_TwoSameArchitecture() throws Exception {

		// show the dialog, or the options get ignored by the task
		tool.setShowAnalysisOptions(true);

		openPrograms.add(buildProgram("notepad", ProgramBuilder._TOY));
		openPrograms.add(buildProgram("winhello", ProgramBuilder._TOY));

		AnalyzeProgramStrategySpy spy = new AnalyzeProgramStrategySpy();
		AnalyzeAllOpenProgramsTask task = new AnalyzeAllOpenProgramsTask(tool, openPrograms.get(0),
			openPrograms.toArray(new Program[openPrograms.size()]), spy);
		runTask(task);

		String optionName = "Stack";
		enableOption(optionName, false);

		waitForTasks();

		Collection<Program> expectedAnalyzed = Collections.unmodifiableCollection(openPrograms);
		assertProgramsAnalyzed(spy, expectedAnalyzed);

		verifyOptions(optionName, expectedAnalyzed);
	}

	@Test
	public void testAnalyzeAllPrograms_TwoDifferentArchitectures() throws Exception {

		// show the dialog, or the options get ignored by the task
		tool.setShowAnalysisOptions(true);

		Program notepad = buildProgram("notepad", ProgramBuilder._TOY);
		Program winhello = buildProgram("winhello", ProgramBuilder._TOY64_BE);

		openPrograms.add(notepad);
		openPrograms.add(winhello);

		AnalyzeProgramStrategySpy spy = new AnalyzeProgramStrategySpy();
		AnalyzeAllOpenProgramsTask task = new AnalyzeAllOpenProgramsTask(tool, openPrograms.get(0),
			openPrograms.toArray(new Program[openPrograms.size()]), spy);
		runTask(task);

		String optionName = "Stack";
		enableOption(optionName, true);

		waitForTasks();

		Collection<Program> expectedAnalyzed = Arrays.asList(notepad);
		Collection<Program> expectedIgnored = Arrays.asList(winhello);

		assertProgramsAnalyzed(spy, expectedAnalyzed);
		assertProgramsIgnored(spy, expectedIgnored);

		verifyOptions(optionName, expectedAnalyzed);
		verifyDefaultOptions(expectedIgnored);
	}

	@Test
	public void testCancelAnalysisOptionsDialog() throws Exception {
		// show the dialog, or the options get ignored by the task
		tool.setShowAnalysisOptions(true);

		Program notepad = buildProgram("notepad", ProgramBuilder._TOY);
		openPrograms.add(notepad);

		AnalyzeProgramStrategySpy spy = new AnalyzeProgramStrategySpy();
		AnalyzeAllOpenProgramsTask task = new AnalyzeAllOpenProgramsTask(tool, openPrograms.get(0),
			openPrograms.toArray(new Program[openPrograms.size()]), spy);
		runTask(task);

		cancelAnalysisDialog();

		waitForTasks();

		assertTrue(spy.analyzed.isEmpty());
	}

	@Test
	public void testAnalyzeAllPrograms_NoOptionsDialog_TwoDifferentArchitectures()
			throws Exception {
		//
		// Test that, if we do not show the dialog, then all programs are analyzed using their
		// current options.
		//
		tool.setShowAnalysisOptions(false);

		openPrograms.add(buildProgram("notepad", ProgramBuilder._TOY));
		openPrograms.add(buildProgram("winhello", ProgramBuilder._TOY64_BE));

		AnalyzeProgramStrategySpy spy = new AnalyzeProgramStrategySpy();
		AnalyzeAllOpenProgramsTask task = new AnalyzeAllOpenProgramsTask(tool, openPrograms.get(0),
			openPrograms.toArray(new Program[openPrograms.size()]), spy);
		runTask(task);

		waitForTasks();

		Collection<Program> expectedAnalyzed = Collections.unmodifiableCollection(openPrograms);
		assertProgramsAnalyzed(spy, expectedAnalyzed);

		verifyDefaultOptions(expectedAnalyzed);
	}

	@Test
	public void testAnalyzeAllPrograms_TwoDifferentArchitectures_InterspersedOrdering()
			throws Exception {
		//
		// Makes sure that the program whose options are set via the dialog is analyzed, as well
		// as any other programs with matching architecture, even if they are encountered after
		// a program with a differing architecture.
		//

		// show the dialog, or the options get ignored by the task
		tool.setShowAnalysisOptions(true);

		Program notepad = buildProgram("notepad", ProgramBuilder._TOY);
		Program p6502 = buildProgram("winhello", ProgramBuilder._TOY64_BE);
		Program winhello = buildProgram("winhello", ProgramBuilder._TOY);

		openPrograms.add(notepad);
		openPrograms.add(p6502);
		openPrograms.add(winhello);

		AnalyzeProgramStrategySpy spy = new AnalyzeProgramStrategySpy();
		AnalyzeAllOpenProgramsTask task = new AnalyzeAllOpenProgramsTask(tool, openPrograms.get(0),
			openPrograms.toArray(new Program[openPrograms.size()]), spy);
		runTask(task);

		String optionName = "Stack";
		enableOption(optionName, true);

		waitForTasks();

		Collection<Program> expectedAnalyzed = Arrays.asList(notepad, winhello);
		Collection<Program> expectedIgnored = Arrays.asList(p6502);

		assertProgramsAnalyzed(spy, expectedAnalyzed);
		assertProgramsIgnored(spy, expectedIgnored);

		verifyOptions(optionName, expectedAnalyzed);
		verifyDefaultOptions(expectedIgnored);
	}

	@Test
	public void testAnalyzeAllPrograms_TwoDifferentArchitectures_CancelWarningDialog()
			throws Exception {

		// show the dialog, or the options get ignored by the task
		tool.setShowAnalysisOptions(true);

		Program notepad = buildProgram("notepad", ProgramBuilder._TOY);
		Program p6502 = buildProgram("winhello", ProgramBuilder._TOY64_BE);
		Program winhello = buildProgram("winhello", ProgramBuilder._TOY);

		openPrograms.add(notepad);
		openPrograms.add(p6502);
		openPrograms.add(winhello);

		AnalyzeProgramStrategySpy spy = new AnalyzeProgramStrategySpy();
		AnalyzeAllOpenProgramsTask task = new AnalyzeAllOpenProgramsTask(tool, openPrograms.get(0),
			openPrograms.toArray(new Program[openPrograms.size()]), spy);
		runTask(task);

		OptionDialog warningDialog = waitForDialogComponent(OptionDialog.class);
		pressButtonByText(warningDialog, "Cancel");

		waitForTasks();

		Collection<Program> expectedIgnored = Arrays.asList(notepad, winhello, p6502);
		assertProgramsIgnored(spy, expectedIgnored);
	}

	/**
	 * Verifies that changing the analyzers to be run affects the task list for 
	 * all open programs.
	 * <p>
	 * For this test we'll verify that a specific analyzer is enabled, then turn off all
	 * analyzers and check again to verify that the analyzer is no longer enabled.
	 * 
	 * @throws Exception if there is a problem building the test programs
	 */
	@Test
	public void testMultiplePrograms_OptionsChange() throws Exception {

		// show the dialog, or the options get ignored by the task
		tool.setShowAnalysisOptions(true);

		Program notepad = buildProgram("notepad", ProgramBuilder._TOY);
		Program winhello = buildProgram("winhello", ProgramBuilder._TOY);

		openPrograms.add(notepad);
		openPrograms.add(winhello);

		// Verify that "Stack" is in the list of analyzers to run (it should be turned on
		// by default)
		assertTrue(isAnalyzerEnabled("Stack", notepad));
		assertTrue(isAnalyzerEnabled("Stack", winhello));

		// Remove all analyzers
		disableAllAnalyzers();

		// Verify that "Stack" is not in the list of analyzers to run (we could check any
		// analyzer since all were removed)
		assertFalse(isAnalyzerEnabled("Stack", notepad));
		assertFalse(isAnalyzerEnabled("Stack", winhello));
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	/**
	 * Returns true if the given analyzer is enabled.
	 * 
	 * @param name the name of the analyzer
	 * @param program the program to check
	 * @return true if the analyzer is enabled; false otherwise
	 */
	private boolean isAnalyzerEnabled(String name, Program program) {
		Options options = program.getOptions(Program.ANALYSIS_PROPERTIES);
		return options.getBoolean(name, true);
	}

	private void disableAllAnalyzers() {
		AnalyzeProgramStrategySpy spy = new AnalyzeProgramStrategySpy();
		AnalyzeAllOpenProgramsTask task = new AnalyzeAllOpenProgramsTask(tool, openPrograms.get(0),
			openPrograms.toArray(new Program[openPrograms.size()]), spy);
		runTask(task);

		AnalysisOptionsDialog optionsDialog = waitForDialogComponent(AnalysisOptionsDialog.class);
		AnalysisPanel panel =
			findComponent(optionsDialog.getComponent(), AnalysisPanel.class, false);

		runSwing(() -> invokeInstanceMethod("deselectAll", panel));
		runSwing(() -> panel.applyChanges());

		close(optionsDialog);
	}

	private void enableOption(String optionName, boolean expectWarning) {

		if (expectWarning) {
			OptionDialog warningDialog = waitForDialogComponent(OptionDialog.class);
			pressButtonByText(warningDialog, "Continue");
		}

		AnalysisOptionsDialog optionsDialog =
			waitForDialogComponent(AnalysisOptionsDialog.class);

		// select some options
		JComponent root = optionsDialog.getComponent();
		pressButtonByText(root, "Deselect All");

		// just enable a specific option, so we can verify that all programs share that option
		selectAnalyzer(optionsDialog, optionName);

		// press Apply
		pressButtonByText(optionsDialog, "Analyze");
	}

	private void cancelAnalysisDialog() {
		AnalysisOptionsDialog optionsDialog =
			waitForDialogComponent(AnalysisOptionsDialog.class);

		// press Apply
		pressButtonByText(optionsDialog, "Cancel");
	}

	private void verifyOptions(String optionName, Collection<Program> programs) {
		for (Program program : programs) {
			Options options = program.getOptions(Program.ANALYSIS_PROPERTIES);
			assertTrue("Program did not share a changed option: " + program,
				options.getBoolean(optionName, false));
		}
	}

	private void verifyDefaultOptions(Collection<Program> programs) {
		for (Program program : programs) {
			Options options = program.getOptions(Program.ANALYSIS_PROPERTIES);
			for (String name : options.getOptionNames()) {
				assertTrue("Program options are unexpectedly changed: " + program,
					options.isDefaultValue(name));
			}
		}
	}

	private void selectAnalyzer(AnalysisOptionsDialog dialog, String name) {
		//
		// The analysis dialog uses a table to display the enablement and name of each
		// analyzer
		//

		AnalysisPanel panel = (AnalysisPanel) getInstanceField("panel", dialog);
		final TableModel model = (TableModel) getInstanceField("model", panel);
		int rowCount = model.getRowCount();
		int row = 0;
		for (row = 0; row < rowCount; row++) {
			String rowName = (String) model.getValueAt(row, 1);
			if (name.equals(rowName)) {
				break;// found it
			}
		}

		if (row == rowCount) {
			Assert.fail("Couldn't find analyzer named " + name);
		}

		final int analyzerRow = row;
		runSwing(() -> model.setValueAt(Boolean.TRUE, analyzerRow, 0));
	}

	private void runTask(final AnalyzeAllOpenProgramsTask task) {
		TaskLauncher.launch(task);
	}

	private void assertProgramsAnalyzed(AnalyzeProgramStrategySpy spy,
			Collection<Program> toAnalyze) {
		//@formatter:off
		Set<Program> analyzed = spy.analyzed;
		assertArraysEqualUnordered(
			"Some open programs that share the same architecture were not analyzed ",
			toAnalyze.toArray(new Program[toAnalyze.size()]),
			analyzed.toArray(new Program[analyzed.size()]));
		//@formatter:on
	}

	private void assertProgramsIgnored(AnalyzeProgramStrategySpy spy,
			Collection<Program> expectedIgnored) {
		for (Program program : expectedIgnored) {
			assertFalse("A program with an architecture differing from that of the program whose " +
				"options were changed has been analyzed", spy.analyzed.contains(program));
		}
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class PluginToolStub extends PluginTool {

		private ToolOptions options = new ToolOptions(GhidraOptions.CATEGORY_AUTO_ANALYSIS);

		public PluginToolStub(Project project) {
			super(project, "Fake Test Tool", false, false, false);
		}

		void setShowAnalysisOptions(boolean show) {
			options.setBoolean("Show Analysis Options", show);
		}

		@Override
		public PluginClassManager getPluginClassManager() {
			return null;
		}

		@Override
		public ToolOptions getOptions(String categoryName) {
			if (GhidraOptions.CATEGORY_AUTO_ANALYSIS.equals(categoryName)) {
				return options;
			}
			return super.getOptions(categoryName);
		}

		@Override
		public void close() {
			runSwing(super::close);
		}
	}

	private class AnalyzeProgramStrategySpy extends AnalyzeProgramStrategy {

		private Set<Program> analyzed = new HashSet<>();

		@Override
		protected void analyzeProgram(Program program, AutoAnalysisManager manager,
				TaskMonitor monitor) {
			// don't analyze--be fast!
			if (analyzed.contains(program)) {
				Assert.fail("Somehow analyzed the same program twice: " + program);
			}
			analyzed.add(program);
		}

		boolean isDone(Collection<Program> toAnalyze) {
			return analyzed.containsAll(toAnalyze);
		}
	}
}
