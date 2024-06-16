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

import org.junit.*;

import docking.action.DockingActionIf;
import ghidra.app.plugin.core.archive.ArchivePlugin;
import ghidra.framework.main.*;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginConfigurationModel;
import ghidra.framework.plugintool.util.PluginDescription;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.classfinder.ClassSearcher;

/**
 * Test configure the Front End tool
 */
public class ManageFrontEndToolTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private FrontEndTool tool;
	private FrontEndPlugin plugin;
	private ManagePluginsDialog managePluginsDialog;
	private PluginConfigurationModel pluginModel;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.getFrontEndTool();
		plugin = getPlugin(tool, FrontEndPlugin.class);

		env.showFrontEndTool();
		showProvider();
	}

	@After
	public void tearDown() throws Exception {

		runSwing(() -> {
			tool.setConfigChanged(false);
			managePluginsDialog.close();
		});
		env.dispose();
	}

	@Test
	public void testOnlyFrontendablePluginsAreAvailable() {
		int count = 0;
		List<PluginDescription> allPluginDescriptions = pluginModel.getAllPluginDescriptions();
		for (PluginDescription pluginDescription : allPluginDescriptions) {
			assertTrue(ApplicationLevelPlugin.class.isAssignableFrom(pluginDescription.getPluginClass()));
			count++;
		}

		List<Class<? extends ApplicationLevelPlugin>> classes = ClassSearcher.getClasses(ApplicationLevelPlugin.class);
		assertEquals(count, classes.size());
	}

	@Test
	public void testSaveCloseProject() throws Exception {

		final Plugin p = getPlugin(tool, ArchivePlugin.class);
		assertNotNull(p);
		runSwing(() -> {
			managePluginsDialog.close();
			tool.removePlugins(new Plugin[] { p });
		});

		showProvider();

		DockingActionIf action = getAction(tool, plugin.getName(), "Save Project");
		performAction(action, true);

		action = getAction(tool, plugin.getName(), "Close Project");
		performAction(action, true);
		assertFalse(managePluginsDialog.isVisible());
	}

	private void showProvider() throws Exception {

		DockingActionIf action = getAction(tool, "Project Window", "Configure Tool");
		performAction(action, true);
		waitForSwing();
		runSwing(() -> tool.showConfig(false, false));

		managePluginsDialog = tool.getManagePluginsDialog();
		pluginModel = managePluginsDialog.getPluginConfigurationModel();
	}
}
