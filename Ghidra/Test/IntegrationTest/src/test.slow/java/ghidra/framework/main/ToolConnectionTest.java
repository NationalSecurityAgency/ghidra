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
import ghidra.app.plugin.core.byteviewer.ByteViewerPlugin;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginException;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;

public class ToolConnectionTest extends AbstractGhidraHeadedIntegrationTest {

	private FrontEndTool frontEndTool;
	private TestEnv env;
	private ToolConnectionDialog dialog;
	private JList<?> producerList;
	private JList<?> consumerList;
	private JList<?> eventList;

	private PluginTool tool1;
	private PluginTool tool2;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		env.resetDefaultTools();
		frontEndTool = env.getFrontEndTool();
		env.showFrontEndTool();
		setErrorGUIEnabled(false);

		tool1 = runTool("CodeBrowser");
		tool2 = runTool("CodeBrowser");
	}

	private Program buildNotepad() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("notepad", ProgramBuilder._TOY);
		builder.createMemory("test2", "0x1001000", 0x2000);
		Program p = builder.getProgram();
		p.clearUndo();
		return p;
	}

	@After
	public void tearDown() throws Exception {
		if (dialog != null) {
			close(dialog);
		}

		closeAllWindows();

		env.dispose();
	}

	@Test
	public void testConnectToolsDialog() throws Exception {

		connectTools();

		clickListRow(eventList, 1);
		pressButtonByText(dialog, "OK");

		Program p = buildNotepad();

		ProgramManager pm = tool1.getService(ProgramManager.class);
		ProgramManager pm2 = tool2.getService(ProgramManager.class);
		runSwing(() -> pm.openProgram(p.getDomainFile()));

		waitForCondition(() -> pm2.getCurrentProgram() != null,
			"Tool 2 did not open a proagram when one was opened in tool1");

		assertEquals(p, pm2.getCurrentProgram());

		env.release(p);
	}

	@Test
	public void testPluginsRemoved() throws Exception {

		connectTools();

		JCheckBox cb = (JCheckBox) eventList.getModel().getElementAt(0);
		assertTrue(cb.getText().equals("ByteBlockChange"));
		close(dialog);

		Plugin p1 = getPlugin(tool1, ByteViewerPlugin.class);
		removePlugin(tool1, p1);

		Plugin p2 = getPlugin(tool2, ByteViewerPlugin.class);
		removePlugin(tool2, p2);

		connectTools();

		cb = (JCheckBox) eventList.getModel().getElementAt(0);
		assertTrue(!cb.getText().equals("ByteBlockChange"));
	}

	@Test
	public void testPluginsAdded() throws Exception {

		connectTools();

		JCheckBox cb = (JCheckBox) eventList.getModel().getElementAt(0);
		assertTrue(cb.getText().equals("ByteBlockChange"));
		close(dialog);

		Plugin p1 = getPlugin(tool1, ByteViewerPlugin.class);
		removePlugin(tool1, p1);

		Plugin p2 = getPlugin(tool2, ByteViewerPlugin.class);
		removePlugin(tool2, p2);

		connectTools();

		cb = (JCheckBox) eventList.getModel().getElementAt(0);
		assertTrue(!cb.getText().equals("ByteBlockChange"));
		close(dialog);

		// add ByteViewer back in 
		addPlugin(tool1, ByteViewerPlugin.class.getName());
		addPlugin(tool2, ByteViewerPlugin.class.getName());

		connectTools();

		cb = (JCheckBox) eventList.getModel().getElementAt(0);
		assertTrue(cb.getText().equals("ByteBlockChange"));
		close(dialog);
	}

//==================================================================================================
// Private Methods
//==================================================================================================	

	private void clickListRow(JList<?> list, int row) {

		AtomicReference<Rectangle> ref = new AtomicReference<>();
		runSwing(() -> ref.set(list.getCellBounds(row, row)));

		Rectangle rect = ref.get();
		clickMouse(list, 1, rect.x + 5, rect.y + 5, 1, 0);
	}

	private void connectTools() throws Exception {
		DockingActionIf connectAction = getAction("Connect Tools");
		performAction(connectAction, true);
		dialog = waitForDialogComponent(ToolConnectionDialog.class);
		producerList = (JList<?>) findComponentByName(dialog, "Producers");
		consumerList = (JList<?>) findComponentByName(dialog, "Consumers");
		eventList = (JList<?>) findComponentByName(dialog, "Events");

		assertNotNull(producerList);
		assertNotNull(consumerList);
		assertNotNull(eventList);

		selectListItem(producerList, 0);
		selectListItem(consumerList, 1);
	}

	private void selectListItem(JList<?> list, final int index) throws Exception {
		runSwing(() -> list.setSelectedIndex(index));
	}

	private void addPlugin(final PluginTool tool, final String className) throws Exception {
		runSwing(() -> {
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
		runSwing(() -> {
			tool.removePlugins(new Plugin[] { plugin });
			tool.getProject().getToolManager().toolChanged(tool);
		});
	}

	private DockingActionIf getAction(String actionName) {
		DockingActionIf action = getAction(frontEndTool, "FrontEndPlugin", actionName);
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

		JMenuItem item = new JMenuItem(name);
		Runnable r = () -> action.actionPerformed(new ActionContext(null, null, item));
		runSwing(r, doWait);
		waitForSwing();
	}

}
