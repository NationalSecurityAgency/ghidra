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
package ghidra.framework.plugintool.dialog;

import static org.junit.Assert.*;

import java.util.List;

import javax.swing.*;
import javax.swing.table.TableModel;

import org.junit.*;

import docking.action.DockingActionIf;
import docking.tool.ToolConstants;
import docking.widgets.table.GTableFilterPanel;
import docking.widgets.table.threaded.ThreadedTableModel;
import ghidra.app.DeveloperPluginPackage;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.data.DataPlugin;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.plugin.core.equate.EquateTablePlugin;
import ghidra.app.plugin.core.function.FunctionPlugin;
import ghidra.app.plugin.core.gotoquery.GoToServicePlugin;
import ghidra.app.plugin.core.help.AboutProgramPlugin;
import ghidra.app.plugin.core.memory.MemoryMapPlugin;
import ghidra.app.plugin.core.navigation.GoToAddressLabelPlugin;
import ghidra.app.plugin.core.navigation.NavigationHistoryPlugin;
import ghidra.app.plugin.core.programtree.ProgramTreePlugin;
import ghidra.app.plugin.debug.DbViewerPlugin;
import ghidra.app.plugin.debug.EventDisplayPlugin;
import ghidra.app.plugin.prototype.debug.ScreenshotPlugin;
import ghidra.framework.model.ToolChest;
import ghidra.framework.plugintool.PluginConfigurationModel;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginDescription;
import ghidra.framework.plugintool.util.PluginPackage;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;

/**
 * Tests for the configuring a tool.
 *
 *
 */
public class ManagePluginsTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private PluginTool tool;
	private ManagePluginsDialog provider;
	private PluginConfigurationModel pluginModel;
	private String descrText;
	private PluginManagerComponent pluginManagerComponent;

	private PluginInstallerDialog installerProvider;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.getTool();
		tool.addPlugin(NavigationHistoryPlugin.class.getName());
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		tool.addPlugin(MemoryMapPlugin.class.getName());
		tool.addPlugin(GoToAddressLabelPlugin.class.getName());
		tool.addPlugin(DataTypeManagerPlugin.class.getName());
		tool.addPlugin(DataPlugin.class.getName());
		tool.addPlugin(FunctionPlugin.class.getName());
		tool.addPlugin(EquateTablePlugin.class.getName());
		tool.addPlugin(ProgramTreePlugin.class.getName());

		env.showTool();

		showProvider();
	}

	@After
	public void tearDown() throws Exception {
		tool.setConfigChanged(false);
		ToolChest tc = tool.getProject().getLocalToolChest();
		tc.remove("MyTestTool");
		runSwing(() -> provider.close());
		closeAllWindowsAndFrames();
		env.dispose();
	}

	@Test
	public void testActionEnablement() {
		performAction(provider.getSaveAction(), true);

		assertTrue(!provider.getSaveAction().isEnabled());
		assertTrue(provider.getSaveAsAction().isEnabled());
	}

	@Test
	public void testAddRemovePackage() {
		final PluginPackage pluginPackage =
			PluginPackage.getPluginPackage(DeveloperPluginPackage.NAME);
		PluginDescription dBViewer = PluginDescription.getPluginDescription(DbViewerPlugin.class);
		PluginDescription screenshot =
			PluginDescription.getPluginDescription(ScreenshotPlugin.class);
		PluginDescription eventDisplay =
			PluginDescription.getPluginDescription(EventDisplayPlugin.class);

		assertTrue(!pluginModel.isLoaded(dBViewer));
		assertTrue(!pluginModel.isLoaded(screenshot));
		assertTrue(!pluginModel.isLoaded(eventDisplay));

		executeOnSwingWithoutBlocking(() -> pluginModel.addAllPlugins(pluginPackage));

		assertTrue(pluginModel.isLoaded(dBViewer));
		assertTrue(pluginModel.isLoaded(screenshot));
		assertTrue(pluginModel.isLoaded(eventDisplay));

		executeOnSwingWithoutBlocking(() -> pluginModel.removeAllPlugins(pluginPackage));

		assertTrue(!pluginModel.isLoaded(dBViewer));
		assertTrue(!pluginModel.isLoaded(screenshot));
		assertTrue(!pluginModel.isLoaded(eventDisplay));

	}

	@Test
	public void testAddPlugin() throws Exception {
		tool.setConfigChanged(false);

		JTable table = findComponent(installerProvider, JTable.class);
		TableModel model = table.getModel();

		String pluginName = (String) model.getValueAt(0, PluginInstallerTableModel.NAME_COL);
		assertEquals("AboutProgramPlugin", pluginName);

		clickTableCell(table, 0, PluginInstallerTableModel.INSTALLED_COL, 1);

		waitForTasks();

		assertTrue(tool.hasConfigChanged());
		assertTrue(provider.getSaveAction().isEnabled());
		assertTrue(
			pluginModel.isLoaded(PluginDescription.getPluginDescription(AboutProgramPlugin.class)));
	}

	@Test
	public void testRemovePlugin() throws Exception {
		tool.setConfigChanged(false);
		SwingUtilities.invokeLater(() -> pluginManagerComponent.manageAllPlugins());
		pluginModel.removePlugin(PluginDescription.getPluginDescription(EquateTablePlugin.class));
		assertTrue(tool.hasConfigChanged());
		assertTrue(provider.getSaveAction().isEnabled());
		assertTrue(!pluginModel.isLoaded(
			PluginDescription.getPluginDescription(AboutProgramPlugin.class)));

	}

	@Test
	public void testRemovePluginWithDependencies() throws Exception {
		// verify that all plugins that depend on the one being removed are
		// also removed from the tool

		assertNotNull(getPlugin(tool, ProgramTreePlugin.class));

		// remove the ViewManager plugin
		final PluginDescription pluginDescription =
			PluginDescription.getPluginDescription(GoToServicePlugin.class);

		List<PluginDescription> dependentNames = pluginModel.getDependencies(pluginDescription);

		assertEquals(4, dependentNames.size());

		executeOnSwingWithoutBlocking(() -> pluginModel.removePlugin(pluginDescription));

		dependentNames = pluginModel.getDependencies(pluginDescription);
		assertNull(getPlugin(tool, ProgramTreePlugin.class));

		assertTrue(dependentNames.size() == 0);
	}

	@Test
	public void testDescriptionPanel() throws Exception {
		executeOnSwingWithoutBlocking(() -> pluginManagerComponent.manageAllPlugins());

		PluginInstallerDialog dialog = waitForDialogComponent(PluginInstallerDialog.class);

		JTable table = findComponent(dialog, JTable.class);
		clickTableCell(table, 0, PluginInstallerTableModel.NAME_COL, 1);

		PluginDetailsPanel detailsPanel = dialog.getDetailsPanel();
		final JLabel textLabel = (JLabel) getInstanceField("textLabel", detailsPanel);

		SwingUtilities.invokeAndWait(() -> descrText = textLabel.getText());

		assertTrue(descrText.contains("Name:"));
		assertTrue(descrText.contains("Description:"));
		assertTrue(descrText.contains("Package:"));
		assertTrue(descrText.contains("Category:"));
		assertTrue(descrText.contains("Plugin Class:"));
		assertTrue(descrText.contains("Class Location:"));
		assertTrue(descrText.contains("Used By:"));
		assertTrue(descrText.contains("Services Required:"));
	}

	@Test
	public void testSearchFilter() throws Exception {
		executeOnSwingWithoutBlocking(() -> pluginManagerComponent.manageAllPlugins());

		PluginInstallerDialog dialog = waitForDialogComponent(PluginInstallerDialog.class);

		JTable table = findComponent(dialog, JTable.class);

		GTableFilterPanel<PluginDescription> filterPanel = dialog.getFilterPanel();
		JTextField tf = findComponent(filterPanel, JTextField.class);
		assertNotNull(tf);

		ThreadedTableModel<?, ?> model = (ThreadedTableModel<?, ?>) table.getModel();
		int unfilteredCount = model.getRowCount();

		runSwing(() -> filterPanel.setFilterText("data"));
		waitForTableModel(model);
		waitForTasks();

		assertTrue("Adding filter text did not reduce the number of components in the table.",
			unfilteredCount > model.getRowCount());
	}

	@Test
	public void testSaveChanges() throws Exception {
		tool.setConfigChanged(true);
		assertTrue(tool.hasConfigChanged());
		performAction(provider.getSaveAction(), true);
		assertTrue(!tool.hasConfigChanged());
	}

	@Test
	public void testSaveAs() throws Exception {
		// verify the Save tool config dialog is displayed.
		performAction(provider.getSaveAsAction(), false);
		waitForSwing();
		SaveToolConfigDialog d = waitForDialogComponent(SaveToolConfigDialog.class);
		assertNotNull(d);
		pressButtonByText(d, "Cancel");

		waitForCondition(() -> !d.isVisible());
	}

	private void showProvider() {

		DockingActionIf action = getAction(tool, ToolConstants.TOOL_OWNER, "Configure Tool");
		performAction(action, true);
		waitForSwing();
		provider = tool.getManagePluginsDialog();
		pluginManagerComponent = (PluginManagerComponent) getInstanceField("comp", provider);

		executeOnSwingWithoutBlocking(() -> pluginManagerComponent.manageAllPlugins());
		installerProvider = waitForDialogComponent(PluginInstallerDialog.class);

		pluginModel = installerProvider.getModel();
	}
}
