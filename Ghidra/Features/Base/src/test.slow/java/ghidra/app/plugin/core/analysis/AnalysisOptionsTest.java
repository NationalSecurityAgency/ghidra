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

import java.io.File;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.swing.ComboBoxModel;
import javax.swing.table.TableModel;

import org.junit.*;

import docking.ActionContext;
import docking.action.DockingActionIf;
import docking.widgets.OptionDialog;
import docking.widgets.combobox.GhidraComboBox;
import docking.widgets.dialogs.InputWithChoicesDialog;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.codebrowser.CodeViewerProvider;
import ghidra.app.services.ProgramManager;
import ghidra.framework.Application;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.preferences.Preferences;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import utilities.util.FileUtilities;

public class AnalysisOptionsTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private PluginTool tool;
	private Program program;
	private AnalysisOptionsDialog optionsDialog;

	@Before
	public void setUp() throws Exception {
		cleanUpStoredPreferences();
		env = new TestEnv();
		tool = env.getTool();
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		addPlugin(tool, AutoAnalysisPlugin.class);
		showTool(tool);
		program = buildProgram("test", ProgramBuilder._TOY);
		ProgramManager pm = tool.getService(ProgramManager.class);
		pm.openProgram(program.getDomainFile());
		optionsDialog = invokeAnalysisDialog();
	}

	private Program buildProgram(String name, String languageID) throws Exception {
		ProgramBuilder builder = new ProgramBuilder(name, languageID);
		builder.createMemory("test1", "0x1000", 0x2000);
		return builder.getProgram();
	}

	@After
	public void tearDown() throws Exception {
		env.release(program);
		env.dispose();
		cleanUpStoredPreferences();
	}

	private static void cleanUpStoredPreferences() {
		Preferences.clear();
		Preferences.store();

		File userSettingsDirectory = Application.getUserSettingsDirectory();
		File optionsDir = new File(userSettingsDirectory, AnalysisPanel.ANALYZER_OPTIONS_SAVE_DIR);
		FileUtilities.deleteDir(optionsDir);
	}

	@Test
	public void testSelectAll() throws Exception {

		setAnalyzerEnabled("Stack", false);
		setAnalyzerEnabled("Reference", false);
		setAnalyzerEnabled("ASCII Strings", false);

		assertFalse(isAnalyzerEnabled("Stack"));
		assertFalse(isAnalyzerEnabled("Reference"));
		assertFalse(isAnalyzerEnabled("ASCII Strings"));

		pressButtonByText(optionsDialog, "Select All");

		assertTrue(isAnalyzerEnabled("Stack"));
		assertTrue(isAnalyzerEnabled("Reference"));
		assertTrue(isAnalyzerEnabled("ASCII Strings"));

		close(optionsDialog);
	}

	@Test
	public void testDeselectAll() throws Exception {

		setAnalyzerEnabled("Stack", true);
		setAnalyzerEnabled("Reference", true);
		setAnalyzerEnabled("ASCII Strings", true);

		assertTrue(isAnalyzerEnabled("Stack"));
		assertTrue(isAnalyzerEnabled("Reference"));
		assertTrue(isAnalyzerEnabled("ASCII Strings"));

		pressButtonByText(optionsDialog, "Deselect All");

		assertFalse(isAnalyzerEnabled("Stack"));
		assertFalse(isAnalyzerEnabled("Reference"));
		assertFalse(isAnalyzerEnabled("ASCII Strings"));

		close(optionsDialog);
	}

	@Test
	public void testReset() throws Exception {
		assertTrue(isAnalyzerEnabled("Stack"));
		assertTrue(isAnalyzerEnabled("Reference"));
		assertTrue(isAnalyzerEnabled("ASCII Strings"));

		setAnalyzerEnabled("Stack", false);
		setAnalyzerEnabled("Reference", false);
		setAnalyzerEnabled("ASCII Strings", false);

		assertFalse(isAnalyzerEnabled("Stack"));
		assertFalse(isAnalyzerEnabled("Reference"));
		assertFalse(isAnalyzerEnabled("ASCII Strings"));

		pressButtonByText(optionsDialog, "Reset");

		assertTrue(isAnalyzerEnabled("Stack"));
		assertTrue(isAnalyzerEnabled("Reference"));
		assertTrue(isAnalyzerEnabled("ASCII Strings"));

		close(optionsDialog);
	}

	@Test
	public void testSaveConfiguration() {
		assertComboboxEquals("Current Program Options");
		setAnalyzerEnabled("Stack", false);
		setAnalyzerEnabled("Reference", false);
		setAnalyzerEnabled("ASCII Strings", false);

		pressButtonByText(optionsDialog, "Save...", false);
		saveConfig("foo");

		assertComboboxEquals("foo");

		close(optionsDialog);
	}

	@Test
	public void testDeleteConfiguration() {
		assertComboboxEquals("Current Program Options");
		createConfig("foo", false, false, false);
		assertComboboxEquals("foo");

		pressButtonByText(optionsDialog, "Delete", false);
		confirmDelete();

		assertComboboxEquals("Current Program Options");

		close(optionsDialog);
	}

	@Test
	public void testSwitchCombo() {
		createConfig("a", false, false, false);
		createConfig("b", false, true, false);
		createConfig("c", true, false, true);

		assertComboboxEquals("c");

		assertTrue(isAnalyzerEnabled("Stack"));
		assertFalse(isAnalyzerEnabled("Reference"));
		assertTrue(isAnalyzerEnabled("ASCII Strings"));

		setCombobox("a");
		assertFalse(isAnalyzerEnabled("Stack"));
		assertFalse(isAnalyzerEnabled("Reference"));
		assertFalse(isAnalyzerEnabled("ASCII Strings"));

		setCombobox("b");
		assertFalse(isAnalyzerEnabled("Stack"));
		assertTrue(isAnalyzerEnabled("Reference"));
		assertFalse(isAnalyzerEnabled("ASCII Strings"));

		close(optionsDialog);
	}

	@Test
	public void testCancelDialogDoesntSaveChanges() {
		assertComboboxEquals("Current Program Options");

		assertTrue(isAnalyzerEnabledInProgramOptions("Stack"));
		assertTrue(isAnalyzerEnabledInProgramOptions("Reference"));
		assertTrue(isAnalyzerEnabled("Stack"));
		assertTrue(isAnalyzerEnabled("Reference"));

		setAnalyzerEnabled("Stack", false);
		setAnalyzerEnabled("Reference", false);

		assertTrue(isAnalyzerEnabledInProgramOptions("Stack"));
		assertTrue(isAnalyzerEnabledInProgramOptions("Reference"));
		assertFalse(isAnalyzerEnabled("Stack"));
		assertFalse(isAnalyzerEnabled("Reference"));

		pressButtonByText(optionsDialog, "Cancel", false);
		OptionDialog yesNoDialog = waitForDialogComponent(OptionDialog.class);
		pressButtonByText(yesNoDialog.getComponent(), "No");
		waitForSwing();

		assertTrue(isAnalyzerEnabledInProgramOptions("Stack"));
		assertTrue(isAnalyzerEnabledInProgramOptions("Reference"));
	}

	@Test
	public void testAnalyzeSavesChangesToProgram() {
		assertComboboxEquals("Current Program Options");

		assertTrue(isAnalyzerEnabledInProgramOptions("Stack"));
		assertTrue(isAnalyzerEnabledInProgramOptions("Reference"));
		assertTrue(isAnalyzerEnabled("Stack"));
		assertTrue(isAnalyzerEnabled("Reference"));

		setAnalyzerEnabled("Stack", false);
		setAnalyzerEnabled("Reference", false);

		assertTrue(isAnalyzerEnabledInProgramOptions("Stack"));
		assertTrue(isAnalyzerEnabledInProgramOptions("Reference"));
		assertFalse(isAnalyzerEnabled("Stack"));
		assertFalse(isAnalyzerEnabled("Reference"));

		pressButtonByText(optionsDialog, "Analyze");

		waitForBusyTool(tool);

		assertFalse(isAnalyzerEnabledInProgramOptions("Stack"));
		assertFalse(isAnalyzerEnabledInProgramOptions("Reference"));

	}

//==================================================================================================
// Private Methods
//==================================================================================================
	private void createConfig(String name, boolean stackOn, boolean refOn, boolean stringOn) {
		setAnalyzerEnabled("Stack", stackOn);
		setAnalyzerEnabled("Reference", refOn);
		setAnalyzerEnabled("ASCII Strings", stringOn);

		pressButtonByText(optionsDialog, "Save...", false);
		saveConfig(name);

	}

	private void assertComboboxEquals(String name) {
		AnalysisPanel panel = (AnalysisPanel) getInstanceField("panel", optionsDialog);
		@SuppressWarnings("unchecked")
		GhidraComboBox<Options> combo =
			(GhidraComboBox<Options>) getInstanceField("optionsComboBox", panel);
		assertEquals(name, ((Options) combo.getSelectedItem()).getName());
	}

	private void setCombobox(String name) {
		runSwing(() -> {
			AnalysisPanel panel = (AnalysisPanel) getInstanceField("panel", optionsDialog);
			@SuppressWarnings("unchecked")
			GhidraComboBox<Options> combo =
				(GhidraComboBox<Options>) getInstanceField("optionsComboBox", panel);
			ComboBoxModel<Options> model = combo.getModel();
			for (int i = 0; i < model.getSize(); i++) {
				Options elementAt = model.getElementAt(i);
				if (elementAt.getName().equals(name)) {
					combo.setSelectedItem(elementAt);
					return;
				}
			}
			fail("Couldn't find combobox item: " + name);
		});
	}

	private void saveConfig(String name) {
		InputWithChoicesDialog dialog = waitForDialogComponent(InputWithChoicesDialog.class);
		runSwing(() -> dialog.setValue(name));
		pressButtonByText(dialog, "OK");
		waitForSwing();

	}

	private void confirmDelete() {
		OptionDialog dialog = waitForDialogComponent(OptionDialog.class);
		pressButtonByText(dialog, "Yes");
		waitForSwing();
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

	private boolean isAnalyzerEnabledInProgramOptions(String analyzerName) {
		Options options = program.getOptions(Program.ANALYSIS_PROPERTIES);
		return options.getBoolean(analyzerName, false);
	}

	private void setAnalyzerEnabled(String name, boolean enabled) {
		TableModel model = getAnalyzerTableModel();
		int analyzerRow = getRowForAnalyzer(name, model);
		runSwing(() -> model.setValueAt(enabled, analyzerRow, 0));
	}

	private boolean isAnalyzerEnabled(String name) {
		TableModel model = getAnalyzerTableModel();
		int analyzerRow = getRowForAnalyzer(name, model);
		AtomicBoolean result = new AtomicBoolean();
		runSwing(() -> result.set((Boolean) model.getValueAt(analyzerRow, 0)));
		return result.get();
	}

	private TableModel getAnalyzerTableModel() {
		// The analysis dialog uses a table to display the enablement and name of each
		// analyzer
		AnalysisPanel panel = (AnalysisPanel) getInstanceField("panel", optionsDialog);
		return (TableModel) getInstanceField("model", panel);
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

}
