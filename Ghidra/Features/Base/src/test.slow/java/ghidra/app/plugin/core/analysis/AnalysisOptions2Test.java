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

import java.awt.Color;
import java.awt.Component;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JPanel;
import javax.swing.table.TableModel;

import org.junit.*;

import docking.ActionContext;
import docking.action.DockingActionIf;
import docking.options.editor.DefaultOptionComponent;
import docking.widgets.table.GTable;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.codebrowser.CodeViewerProvider;
import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * This class test the ability to replace analysis options using an {@link AnalysisOptionsUpdater}.
 */
public class AnalysisOptions2Test extends AbstractGhidraHeadedIntegrationTest {

	private static final String UNCHANGING_OPTION_NAME = "Unchanging Name";
	private static final String NEW_OPTION_NAME = "New Option";
	private static final String OLD_OPTION_NAME = "Old Option";
	private static final String NEW_OPTION_DEFAULT_VALUE = "New Default Value";
	private static final String OLD_OPTION_DEFAULT_VALUE = "Old Default Value";
	private static final String UNCHANGING_OPTION_DEFAULT_VALUE = "Unchanging Default Value";

	private static final Color NEW_OPTION_DEFAULT_VALUE_AS_COLOR = Color.GREEN;

	private TestEnv env;
	private PluginTool tool;
	private Program program;
	private AnalysisOptionsDialog optionsDialog;

	@Before
	public void setUp() throws Exception {

		env = new TestEnv();
		tool = env.getTool();
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		addPlugin(tool, AutoAnalysisPlugin.class);
		showTool(tool);

		program = buildProgram("test", ProgramBuilder._TOY);
	}

	private Program buildProgram(String name, String languageID) throws Exception {
		ProgramBuilder builder = new ProgramBuilder(name, languageID);
		builder.createMemory("test1", "0x1000", 0x2000);
		return builder.getProgram();
	}

	@After
	public void tearDown() throws Exception {
		close(optionsDialog);
		env.dispose();
	}

	@Test
	public void testOptionReplacing_DefaultNewValue_DefaultOldValue() throws Exception {

		//
		// The old option's default value should not be applied to the new option
		//

		installAnalyzer(NotReplacingTestAnalyzerStub.class);

		// install old options; the default value will not be used in the new option
		installOldOptions(OLD_OPTION_DEFAULT_VALUE);

		openProgram();

		optionsDialog = invokeAnalysisDialog();

		// check options displayed in the dialog
		assertOnlyNewOptionsInUi();
		assertOptionValue(NEW_OPTION_NAME, NEW_OPTION_DEFAULT_VALUE);
		assertOptionValue(UNCHANGING_OPTION_NAME, UNCHANGING_OPTION_DEFAULT_VALUE);
		assertOldValueRemoved();
	}

	@Test
	public void testOptionReplacing_NonDefaultNewValue_DefaultOldValue() throws Exception {

		//
		// The old option's default value should not be applied to the new option
		//

		installAnalyzer(NotReplacingTestAnalyzerStub.class);

		// install old options; the default value will not be used in the new option
		installOldOptions(OLD_OPTION_DEFAULT_VALUE);

		// put new options in the analyzer's options
		String newValue = "Some New Value";
		changeNewOption(newValue);

		openProgram();

		optionsDialog = invokeAnalysisDialog();

		// check options displayed in the dialog
		assertOnlyNewOptionsInUi();
		assertOptionValue(NEW_OPTION_NAME, newValue);
		assertOptionValue(UNCHANGING_OPTION_NAME, UNCHANGING_OPTION_DEFAULT_VALUE);
		assertOldValueRemoved();
	}

	@Test
	public void testOptionReplacing_DefaultNewValue_NonDefaultOldValue() throws Exception {

		//
		// The old option's non-default value should be applied to the new option
		//

		installAnalyzer(UseOldValueTestAnalyzerStub.class);

		// install old options; the default value will not be used in the new option
		installOldOptions(OLD_OPTION_DEFAULT_VALUE);
		String newValue = "Old Option Non-default Value";
		changeOldOption(newValue);

		openProgram();

		optionsDialog = invokeAnalysisDialog();

		// check options displayed in the dialog
		assertOnlyNewOptionsInUi();
		assertOptionValue(NEW_OPTION_NAME, newValue);
		assertOptionValue(UNCHANGING_OPTION_NAME, UNCHANGING_OPTION_DEFAULT_VALUE);
		assertOldValueRemoved();
	}

	@Test
	public void testOptionReplacing_NonDefaultNewValue_NonDefaultOldValue() throws Exception {

		//
		// The old option's non-default value should not be applied to the new option, since the
		// new option has a non-default
		//

		installAnalyzer(UseOldValueTestAnalyzerStub.class);

		// install old options; the default value will not be used in the new option
		installOldOptions(OLD_OPTION_DEFAULT_VALUE);
		String oldOptionNewValue = "Old Option Non-default Value";
		changeOldOption(oldOptionNewValue);

		String newOptionNewValue = "Some New Value";
		changeNewOption(newOptionNewValue);

		openProgram();

		optionsDialog = invokeAnalysisDialog();

		// check options displayed in the dialog
		assertOnlyNewOptionsInUi();
		assertOptionValue(NEW_OPTION_NAME, newOptionNewValue);
		assertOptionValue(UNCHANGING_OPTION_NAME, UNCHANGING_OPTION_DEFAULT_VALUE);
		assertOldValueRemoved();
	}

	@Test
	public void testOptionReplacing_DefaultNewValue_NonDefaultOldValue_DifferentValueTypes()
			throws Exception {

		//
		// The old option's non-default value should be applied to the new option.  The new option 
		// has a different object type than the old option.
		//

		installAnalyzer(ConvertValueTypeTestAnalyzerStub.class);

		// install old options; the default value will not be used in the new option
		installOldOptions(OLD_OPTION_DEFAULT_VALUE);
		String newValue = "255,175,175"; // pink
		changeOldOption(newValue);

		openProgram();

		optionsDialog = invokeAnalysisDialog();

		// check options displayed in the dialog
		assertOnlyNewOptionsInUi();
		assertOptionValue(NEW_OPTION_NAME, toColor(newValue));
		assertOptionValue(UNCHANGING_OPTION_NAME, UNCHANGING_OPTION_DEFAULT_VALUE);
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private void openProgram() {
		ProgramManager pm = tool.getService(ProgramManager.class);
		pm.openProgram(program.getDomainFile());
	}

	private void installOldOptions(Object value) {
		Options programAnalysisOptions = program.getOptions(Program.ANALYSIS_PROPERTIES);
		Options options = programAnalysisOptions.getOptions(AbstractTestAnalyzerStub.NAME);
		AbstractOptions abstractOptions = (AbstractOptions) getInstanceField("options", options);

		// this call creates an 'unregistered option'
		String fullOptionName =
			"Analyzers." + AbstractTestAnalyzerStub.NAME + '.' + OLD_OPTION_NAME;
		Option option = abstractOptions.getOption(fullOptionName, OptionType.getOptionType(value),
			OLD_OPTION_DEFAULT_VALUE);

		// during testing 'value' may or may not match the default value
		tx(program, () -> {
			option.setCurrentValue(value);
			setInstanceField("isRegistered", option, false);
		});
	}

	private void installAnalyzer(Class<? extends Analyzer> analyzer) {

		@SuppressWarnings("unchecked")
		List<Class<?>> extensions =
			(List<Class<?>>) getInstanceField("extensionPoints", ClassSearcher.class);

		// remove any traces of previous test runs
		extensions.removeIf(c -> c.getSimpleName().contains("TestAnalyzerStub"));

		extensions.add(analyzer);
	}

	private AnalysisOptionsDialog invokeAnalysisDialog() {

		CodeBrowserPlugin cbp = env.getPlugin(CodeBrowserPlugin.class);
		CodeViewerProvider provider = cbp.getProvider();
		DockingActionIf action = getAction(tool, "Auto Analyze");
		ActionContext context = runSwing(() -> provider.getActionContext(null));
		performAction(action, context, false);

		// TODO temp debug to catch issue seen when running parallel tests
		try {
			return waitForDialogComponent(AnalysisOptionsDialog.class);
		}
		catch (Throwable t) {

			printOpenWindows();

			failWithException("Unable to find analysis dialog", t);
			return null; // can't get here
		}
	}

	private void changeNewOption(String newValue) {
		Options options = program.getOptions(Program.ANALYSIS_PROPERTIES);
		Options analyzerOptions = options.getOptions(AbstractTestAnalyzerStub.NAME);

		tx(program, () -> analyzerOptions.putObject(NEW_OPTION_NAME, newValue));
	}

	private void changeOldOption(String newValue) {
		Options programAnalysisOptions = program.getOptions(Program.ANALYSIS_PROPERTIES);
		Options options = programAnalysisOptions.getOptions(AbstractTestAnalyzerStub.NAME);
		AbstractOptions abstractOptions = (AbstractOptions) getInstanceField("options", options);

		// this call creates an 'unregistered option'
		String fullOptionName =
			"Analyzers." + AbstractTestAnalyzerStub.NAME + '.' + OLD_OPTION_NAME;
		Option option = abstractOptions.getOption(fullOptionName,
			OptionType.getOptionType(OLD_OPTION_DEFAULT_VALUE), OLD_OPTION_DEFAULT_VALUE);

		// during testing 'value' may or may not match the default value
		tx(program, () -> {
			option.setCurrentValue(newValue);
			setInstanceField("isRegistered", option, false);
		});
	}

	private void assertOldValueRemoved() {
		Options options = program.getOptions(Program.ANALYSIS_PROPERTIES);
		Options analyzerOptions = options.getOptions(AbstractTestAnalyzerStub.NAME);
		assertFalse("Old option not removed", analyzerOptions.contains(OLD_OPTION_NAME));
	}

	private void assertOnlyNewOptionsInUi() {

		// click our analyzer in the list of options
		selectAnalyzer(AbstractTestAnalyzerStub.NAME);

		// get the panel of options
		JPanel panel =
			(JPanel) findComponentByName(optionsDialog, AnalysisPanel.ANALYZER_OPTIONS_PANEL_NAME);

		// get the option labels
		List<String> uiOptionNames = new ArrayList<>();
		Component[] components = panel.getComponents();
		for (Component component : components) {

			DefaultOptionComponent doc = (DefaultOptionComponent) component;
			String text = doc.getLabelText();
			uiOptionNames.add(text);
		}

		// check against our new options
		assertEquals(2, uiOptionNames.size());
		assertTrue(uiOptionNames.contains(UNCHANGING_OPTION_NAME));
		assertTrue(uiOptionNames.contains(NEW_OPTION_NAME));
	}

	private void assertOptionValue(String optionName, Object defaultValue) {
		Options options = program.getOptions(Program.ANALYSIS_PROPERTIES);
		Options analyzerOptions = options.getOptions(AbstractTestAnalyzerStub.NAME);
		Object value = analyzerOptions.getObject(optionName, null);
		assertEquals("Option value is not as expected for '" + optionName + "'", defaultValue,
			value);
	}

	private static Color toColor(String rgbString) {
		String[] parts = rgbString.split(",");
		int r = Integer.parseInt(parts[0]);
		int g = Integer.parseInt(parts[1]);
		int b = Integer.parseInt(parts[2]);
		return new Color(r, g, b);
	}

	private void selectAnalyzer(String name) {
		GTable table = getAnalyzerTable();
		int analyzerRow = getRowForAnalyzer(name, table.getModel());
		runSwing(() -> table.selectRow(analyzerRow));
	}

	private GTable getAnalyzerTable() {
		// The analysis dialog uses a table to display the enablement and name of each analyzer
		AnalysisPanel panel = (AnalysisPanel) getInstanceField("panel", optionsDialog);
		return (GTable) getInstanceField("table", panel);
	}

	private int getRowForAnalyzer(String name, TableModel model) {
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
		int analyzerRow = row;
		return analyzerRow;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	public static abstract class AbstractTestAnalyzerStub implements Analyzer {

		protected AnalysisOptionsUpdater updater = new AnalysisOptionsUpdater();

		private static final String NAME = "Test Analyzer";

		@Override
		public String getName() {
			return NAME;
		}

		@Override
		public AnalyzerType getAnalysisType() {
			return AnalyzerType.FUNCTION_ANALYZER;
		}

		@Override
		public boolean getDefaultEnablement(Program p) {
			return true;
		}

		@Override
		public boolean supportsOneTimeAnalysis() {
			return false;
		}

		@Override
		public String getDescription() {
			return "Test analyzer...";
		}

		@Override
		public AnalysisPriority getPriority() {
			return AnalysisPriority.FUNCTION_ANALYSIS;
		}

		@Override
		public boolean canAnalyze(Program p) {
			return true;
		}

		@Override
		public boolean added(Program p, AddressSetView set, TaskMonitor monitor,
				MessageLog log) throws CancelledException {
			return false;
		}

		@Override
		public boolean removed(Program p, AddressSetView set, TaskMonitor monitor,
				MessageLog log) throws CancelledException {
			return false;
		}

		@Override
		public void registerOptions(Options options, Program p) {

			options.registerOption(UNCHANGING_OPTION_NAME, UNCHANGING_OPTION_DEFAULT_VALUE, null,
				"Unchanging option description");

			// replaces "Old Name"
			options.registerOption(NEW_OPTION_NAME, NEW_OPTION_DEFAULT_VALUE, null,
				"New option description");
		}

		@Override
		public AnalysisOptionsUpdater getOptionsUpdater() {
			return updater;
		}

		@Override
		public void optionsChanged(Options options, Program p) {
			// stub
		}

		@Override
		public void analysisEnded(Program p) {
			// stub
		}

		@Override
		public boolean isPrototype() {
			return false;
		}
	}

	public static class NotReplacingTestAnalyzerStub extends AbstractTestAnalyzerStub {

		public NotReplacingTestAnalyzerStub() {
			super();

			updater.registerReplacement(NEW_OPTION_NAME, OLD_OPTION_NAME, oldValue -> {
				throw new AssertException(
					"Replace function unexpectedly called for new/old options: '" +
						NEW_OPTION_NAME + "' / '" + OLD_OPTION_NAME + "'");
			});
		}
	}

	public static class UseOldValueTestAnalyzerStub extends AbstractTestAnalyzerStub {

		public UseOldValueTestAnalyzerStub() {
			super();

			updater.registerReplacement(NEW_OPTION_NAME, OLD_OPTION_NAME, oldValue -> {
				return oldValue;
			});
		}
	}

	public static class ConvertValueTypeTestAnalyzerStub extends AbstractTestAnalyzerStub {

		public ConvertValueTypeTestAnalyzerStub() {
			super();

			updater.registerReplacement(NEW_OPTION_NAME, OLD_OPTION_NAME, oldValue -> {
				// Assumption: 'oldValue' is an RGB string; the new value expects a Color
				return toColor((String) oldValue);
			});
		}

		@Override
		public void registerOptions(Options options, Program p) {

			options.registerOption(UNCHANGING_OPTION_NAME, UNCHANGING_OPTION_DEFAULT_VALUE, null,
				"Unchanging option description");

			// replaces "Old Name"
			options.registerOption(NEW_OPTION_NAME, NEW_OPTION_DEFAULT_VALUE_AS_COLOR, null,
				"New option description");

		}
	}
}
