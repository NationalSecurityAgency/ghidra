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
package ghidra.framework.main;

import static org.junit.Assert.*;

import java.awt.Rectangle;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.*;

import org.junit.*;

import docking.ActionContext;
import docking.action.DockingActionIf;
import docking.test.AbstractDockingTest;
import ghidra.app.plugin.core.byteviewer.ByteViewerPlugin;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginException;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;

// The ByteViewer is in its own plugin; the CodeBrowser is in Base, this we need 
// the ModuleClassLoaderDependent interface
public class ByteViewerToolConnectionTest extends AbstractGhidraHeadedIntegrationTest {

	private FrontEndTool frontEndTool;
	private TestEnv env;
	private ToolConnectionDialog dialog;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		env.resetDefaultTools();
		frontEndTool = env.getFrontEndTool();
		env.showFrontEndTool();
		setErrorGUIEnabled(false);
	}

	@After
	public void tearDown() throws Exception {
		if (dialog != null) {
			pressButtonByText(dialog, "OK");
		}

		closeAllWindows();
		env.dispose();
	}

	@Test
	public void testConnectToolsDialog() throws Exception {
		PluginTool cbTool = runTool("CodeBrowser");
		PluginTool cbTool2 = runTool("CodeBrowser");

		DockingActionIf connectAction = getAction("Connect Tools");
		performAction(connectAction, true);
		dialog = waitForDialogComponent(ToolConnectionDialog.class);
		JList<?> producerList = (JList<?>) findComponentByName(dialog, "Producers");
		JList<?> consumerList = (JList<?>) findComponentByName(dialog, "Consumers");
		JList<?> eventList = (JList<?>) findComponentByName(dialog, "Events");

		assertNotNull(producerList);
		assertNotNull(consumerList);
		assertNotNull(eventList);

		producerList.setSelectedIndex(0);
		consumerList.setSelectedIndex(1);
		clickRow(eventList, 1);

		Program p = buildProgram();

		ProgramManager pm = cbTool.getService(ProgramManager.class);
		SwingUtilities.invokeAndWait(() -> pm.openProgram(p.getDomainFile()));

		ProgramManager pm2 = cbTool2.getService(ProgramManager.class);
		assertEquals(p, pm2.getCurrentProgram());

		env.release(p);
	}

	private void clickRow(JList<?> list, int row) {

		AtomicReference<Rectangle> ref = new AtomicReference<>();
		runSwing(() -> {
			Rectangle rect = list.getCellBounds(row, row);
			ref.set(rect);
		});
		clickMouse(list, 1, ref.get().x + 5, ref.get().y + 5, 1, 0);
	}

	private Program buildProgram() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("sample", ProgramBuilder._TOY);
		builder.createMemory("test2", "0x1001000", 0x2000);
		Program p = builder.getProgram();
		p.clearUndo();
		return p;
	}

	@Test
	public void testPluginsRemoved() throws Exception {
		PluginTool cbTool = runTool("CodeBrowser");
		PluginTool cbTool2 = runTool("CodeBrowser");
		DockingActionIf connectAction = getAction("Connect Tools");
		performAction(connectAction);
		dialog = waitForDialogComponent(ToolConnectionDialog.class);
		JList<?> producerList = (JList<?>) findComponentByName(dialog, "Producers");
		JList<?> consumerList = (JList<?>) findComponentByName(dialog, "Consumers");
		JList<?> eventList = (JList<?>) findComponentByName(dialog, "Events");

		selectListItem(producerList, 0);
		selectListItem(consumerList, 1);

		JCheckBox cb = (JCheckBox) eventList.getModel().getElementAt(0);
		assertTrue(cb.getText().equals("ByteBlockChange"));
		close(dialog);

		Plugin p1 = getPlugin(cbTool, ByteViewerPlugin.class);
		removePlugin(cbTool, p1);

		Plugin p2 = getPlugin(cbTool2, ByteViewerPlugin.class);
		removePlugin(cbTool2, p2);

		performAction(connectAction);
		dialog = waitForDialogComponent(ToolConnectionDialog.class);

		producerList = (JList<?>) findComponentByName(dialog, "Producers");
		consumerList = (JList<?>) findComponentByName(dialog, "Consumers");
		eventList = (JList<?>) findComponentByName(dialog, "Events");

		selectListItem(producerList, 0);
		selectListItem(consumerList, 1);

		cb = (JCheckBox) eventList.getModel().getElementAt(0);
		assertTrue(!cb.getText().equals("ByteBlockChange"));
	}

	@Test
	public void testPluginsAdded() throws Exception {
		PluginTool cbTool = runTool("CodeBrowser");
		PluginTool cbTool2 = runTool("CodeBrowser");
		DockingActionIf connectAction = getAction("Connect Tools");
		performAction(connectAction, true);
		dialog = waitForDialogComponent(ToolConnectionDialog.class);
		JList<?> producerList = (JList<?>) findComponentByName(dialog, "Producers");
		JList<?> consumerList = (JList<?>) findComponentByName(dialog, "Consumers");
		JList<?> eventList = (JList<?>) findComponentByName(dialog, "Events");

		selectListItem(producerList, 0);
		selectListItem(consumerList, 1);

		JCheckBox cb = (JCheckBox) eventList.getModel().getElementAt(0);
		assertTrue(cb.getText().equals("ByteBlockChange"));
		close(dialog);

		Plugin p1 = getPlugin(cbTool, ByteViewerPlugin.class);
		removePlugin(cbTool, p1);

		Plugin p2 = getPlugin(cbTool2, ByteViewerPlugin.class);
		removePlugin(cbTool2, p2);

		performAction(connectAction, true);
		dialog = waitForDialogComponent(ToolConnectionDialog.class);

		producerList = (JList<?>) findComponentByName(dialog, "Producers");
		consumerList = (JList<?>) findComponentByName(dialog, "Consumers");
		eventList = (JList<?>) findComponentByName(dialog, "Events");

		selectListItem(producerList, 0);
		selectListItem(consumerList, 1);

		cb = (JCheckBox) eventList.getModel().getElementAt(0);
		assertTrue(!cb.getText().equals("ByteBlockChange"));
		close(dialog);

		// add ByteViewer back in 
		addPlugin(cbTool, ByteViewerPlugin.class.getName());
		addPlugin(cbTool2, ByteViewerPlugin.class.getName());
		performAction(connectAction, true);
		dialog = waitForDialogComponent(ToolConnectionDialog.class);

		producerList = (JList<?>) findComponentByName(dialog, "Producers");
		consumerList = (JList<?>) findComponentByName(dialog, "Consumers");
		eventList = (JList<?>) findComponentByName(dialog, "Events");

		selectListItem(producerList, 0);
		selectListItem(consumerList, 1);

		cb = (JCheckBox) eventList.getModel().getElementAt(0);
		assertTrue(cb.getText().equals("ByteBlockChange"));
		close(dialog);
		if (!dialog.isVisible()) {
			dialog = null;
		}
	}

//==================================================================================================
// Private Methods
//==================================================================================================	

	private void selectListItem(final JList<?> list, final int index) throws Exception {
		SwingUtilities.invokeAndWait(() -> list.setSelectedIndex(index));

	}

	private void addPlugin(final PluginTool tool, final String className) throws Exception {
		SwingUtilities.invokeAndWait(() -> {
			try {
				tool.addPlugin(className);
			}
			catch (PluginException e) {
				e.printStackTrace();
			}
			tool.getProject().getToolManager().toolChanged(tool);
		});
	}

	private void removePlugin(final PluginTool tool, final Plugin plugin) throws Exception {
		SwingUtilities.invokeAndWait(() -> {
			tool.removePlugins(new Plugin[] { plugin });
			tool.getProject().getToolManager().toolChanged(tool);
		});
	}

	private DockingActionIf getAction(String actionName) {
		DockingActionIf action =
			AbstractDockingTest.getAction(frontEndTool, "FrontEndPlugin", actionName);
		return action;
	}

	private DockingActionIf getAction(String toolName, String action) {

		Set<DockingActionIf> actions =
			getActionsByOwnerAndName(frontEndTool, "FrontEndPlugin", toolName);
		for (DockingActionIf a : actions) {
			String[] menuPath = a.getMenuBarData().getMenuPath();
			if (menuPath.length > 2) {
				if (menuPath[1].indexOf(action) >= 0) {
					return a;
				}
			}
		}
		return null;
	}

	private PluginTool runTool(String toolName) throws Exception {
		DockingActionIf runAction = getAction(toolName, "Run Tool");
		assertNotNull(runAction);// if action is null, the name of the tool changed
		performAction(runAction, toolName, true);
		PluginTool[] tools = frontEndTool.getToolServices().getRunningTools();
		return tools[tools.length - 1];
	}

	private void performAction(final DockingActionIf action, String name, boolean doWait)
			throws Exception {

		final JMenuItem item = new JMenuItem(name);
		Runnable r = () -> action.actionPerformed(new ActionContext(null, null, item));
		if (doWait) {
			SwingUtilities.invokeAndWait(r);
		}
		else {
			SwingUtilities.invokeLater(r);
		}
		waitForPostedSwingRunnables();
	}

}
