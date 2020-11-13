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

import java.awt.*;
import java.awt.event.MouseEvent;
import java.io.File;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.*;

import org.junit.*;

import docking.ActionContext;
import docking.action.DockingActionIf;
import docking.test.AbstractDockingTest;
import docking.tool.ToolConstants;
import docking.widgets.OptionDialog;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.table.GTable;
import docking.widgets.tree.GTreeNode;
import docking.wizard.WizardManager;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.framework.GenericRunInfo;
import ghidra.framework.ToolUtils;
import ghidra.framework.data.ContentHandler;
import ghidra.framework.main.datatree.DataTree;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.dialog.SaveToolConfigDialog;
import ghidra.framework.plugintool.util.PluginException;
import ghidra.framework.preferences.Preferences;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.task.TaskMonitor;
import resources.ResourceManager;

/**
 * Tests for tool actions on the front end (Ghidra project window)
 */
public class ToolActionManagerTest extends AbstractGhidraHeadedIntegrationTest {

	private FrontEndTool frontEndTool;
	private TestEnv env;
	private File exportFile = new File(GenericRunInfo.getProjectsDirPath(), "untitled.tool");

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		env.resetDefaultTools();

		frontEndTool = env.getFrontEndTool();
		env.showFrontEndTool();

		exportFile.delete();
	}

	@After
	public void tearDown() throws Exception {
		closeAllWindows();
		env.dispose();
	}

	@Test
	public void testDeleteTool() throws Exception {
		// delete a tool from the tool chest
		// verify delete menu is updated
		// verify "open with" menu is updated
		createTool();
		DockingActionIf action = getAction("Untitled", "Delete Tool");
		assertNotNull(action);
		performAction(action, "Untitled", false);
		OptionDialog d = waitForDialogComponent(OptionDialog.class);
		assertNotNull(d);
		assertEquals("Confirm Delete", d.getTitle());
		pressButtonByText(d.getComponent(), "Delete");
		waitForSwing();

		assertNull(getAction("Untitled", "Delete Tool"));
		assertNull(getAction("Untitled", "Run Tool"));
		assertNull(getAction("Untitled", "Export Tool"));
	}

	@Test
	public void testDeleteToolFromIcon() throws Exception {
		createTool();

		DockingActionIf deleteAction = getAction("Delete Tool");
		performToolButtonAction(deleteAction, "Untitled", false, true);

		OptionDialog d = waitForDialogComponent(OptionDialog.class);
		assertNotNull(d);
		assertEquals("Confirm Delete", d.getTitle());
		pressButtonByText(d.getComponent(), "Delete");
		waitForSwing();

		assertNull(getAction("Untitled", "Delete Tool"));
		assertNull(getAction("Untitled", "Run Tool"));
		assertNull(getAction("Untitled", "Export Tool"));
	}

	@Test
	public void testCloseRunningToolIcon() throws Exception {
		// close tool from the icon in the running tools
		createTool();

		DockingActionIf closeAction = getAction("Close Tool");
		performToolButtonAction(closeAction, "Untitled", true, true);

		PluginTool[] tools = frontEndTool.getProject().getToolServices().getRunningTools();
		assertEquals(0, tools.length);
	}

	@Test
	public void testRunTool() throws Exception {
		// action for run tool
		createTool();

		DockingActionIf runAction = getAction("Untitled", "Run Tool");
		performAction(runAction, "Untitled", true);
		PluginTool[] tools = frontEndTool.getProject().getToolServices().getRunningTools();
		assertEquals(2, tools.length);
	}

	@Test
	public void testRunToolFromIcon() throws Exception {
		createTool();

		// verify there is a tool button for each config in the tool chest
		ToolTemplate[] configs = frontEndTool.getToolServices().getToolChest().getToolTemplates();
		for (ToolTemplate config : configs) {
			ToolButton b = findToolButton(frontEndTool.getToolFrame(), config.getName(), false);
			assertNotNull(b);
		}

		final ToolButton cbButton = findToolButton(frontEndTool.getToolFrame(), "Untitled", false);
		runSwing(() -> cbButton.doClick());

		// the button click triggers an animation, and then launches the tool, so we must wait 
		// for the window to appear
		Window window = waitForWindow("Untitled(2)");
		assertNotNull(window);

		waitForCondition(() -> {
			PluginTool[] tools = frontEndTool.getToolServices().getRunningTools();
			return tools.length == 2;
		});

		ToolButton tb = findToolButton(frontEndTool.getToolFrame(), "Untitled", true);
		assertNotNull(tb);
	}

	@Test
	public void testImportTool() throws Exception {
		// action for import a tool
		final ToolChest tc = frontEndTool.getToolServices().getToolChest();
		int count = tc.getToolCount();

		String toolNamePrefix = "TestCodeBrowser";
		final File cbFile = ResourceManager.getResourceFile(
			"defaultTools/" + toolNamePrefix + ToolUtils.TOOL_EXTENSION);
		assertNotNull(cbFile);

		DockingActionIf importAction = getAction("Import Tool");
		performAction(importAction, false);

		GhidraFileChooser chooser = waitForDialogComponent(GhidraFileChooser.class);

		setSelectedFile(chooser, cbFile);

		pressButtonByText(chooser, "Import");
		waitForSwing();
		assertEquals(count + 1, tc.getToolCount());

		ToolTemplate[] configs = tc.getToolTemplates();
		final ArrayList<String> list = new ArrayList<>();
		for (ToolTemplate config : configs) {
			if (config.getName().startsWith(toolNamePrefix + "_")) {
				list.add(config.getName());
			}
		}
		assertTrue(list.size() > 0);
		Collections.sort(list);
		runSwing(() -> tc.remove(list.get(list.size() - 1)));
	}

	@Test
	public void testSetToolAssociation() throws Exception {

		//
		// verify the default tool is the 'CodeBrowser'
		// verify that the VT tool is not in the tool chest (has not been imported)
		//
		removePreferences();
		initializeToolChestToJustCodeBrowser();

		//
		// verify that double-clicking a program launches its default tool (the CodeBrowser)
		//
		Project project = frontEndTool.getProject();
		DataTree tree = findComponent(frontEndTool.getToolFrame(), DataTree.class);

// TODO: move to method		
		DomainFolder rootFolder = project.getProjectData().getRootFolder();
		Program p = buildProgram("notepad");
		rootFolder.createFile("notepad", p, TaskMonitor.DUMMY);
		env.release(p);

		GTreeNode rootNode = tree.getViewRoot();
		waitForTree(tree);
		waitForSwing();

		GTreeNode node = rootNode.getChild("notepad");
		Rectangle bounds = tree.getPathBounds(node.getTreePath());

		tree.setSelectedNode(node);
		waitForTree(tree);

		JTree jTree = (JTree) invokeInstanceMethod("getJTree", tree);
		clickMouse(jTree, MouseEvent.BUTTON1, bounds.x + 5, bounds.y + 5, 2, 0);
		waitForSwing();

		PluginTool tool = waitForTool("CodeBrowser", project);

		// close the CodeBrowser tool
		close(tool);
		waitForSwing();

		//
		// edit the association
		//
		DockingActionIf setAssociationsAction = getAction("Set Tool Associations");
		performAction(setAssociationsAction, false);

		SetToolAssociationsDialog associationDialog =
			waitForDialogComponent(SetToolAssociationsDialog.class);

		//
		// edit the association
		//
		// find the 'Program' entry
		GTable associationTable = findComponent(associationDialog.getComponent(), GTable.class);
		int rowCount = associationTable.getRowCount();
		int programRow = -1;
		for (int i = 0; i < rowCount; i++) {
			ContentHandler handler = (ContentHandler) associationTable.getValueAt(i, 0);
			if ("Program".equals(handler.getContentType())) {
				programRow = i;
				break;
			}
		}
		assertTrue("Unable to find the 'Program' entry in the associations table",
			programRow != -1);

		// select the program entry in the table
		final int finalProgramRow = programRow;
		runSwing(() -> associationTable.selectRow(finalProgramRow));

		// click the edit button
		JButton editButton = findButtonByText(associationDialog, "Edit");
		pressButton(editButton, false);

		// grab the new dialog
		PickToolDialog pickToolDialog = waitForDialogComponent(PickToolDialog.class);

		// select the VT tool
		String VTToolName = "Version Tracking";
		final GTable pickTable = findComponent(pickToolDialog.getComponent(), GTable.class);
		rowCount = pickTable.getRowCount();
		int toolRow = -1;
		for (int i = 0; i < rowCount; i++) {
			ToolTemplate template = (ToolTemplate) pickTable.getValueAt(i, 0);
			if (VTToolName.equals(template.getName())) {
				toolRow = i;
				break;
			}
		}
		assertTrue("Unable to find the 'Version Tracking' entry in the pick tool table",
			toolRow != -1);

		final int finalToolRow = toolRow;
		runSwing(() -> pickTable.selectRow(finalToolRow));

		// press OK
		JButton okButton = findButtonByText(pickToolDialog.getComponent(), "OK");
		pressButton(okButton);
		waitForSwing();

		// verify the new association is the VT tool
		ToolTemplate template = (ToolTemplate) associationTable.getValueAt(finalProgramRow, 1);
		assertEquals(VTToolName + " tool not made the association for Program", VTToolName,
			template.getName());

		// close the dialog
		final JButton associationDialogOKButton =
			findButtonByText(associationDialog.getComponent(), "OK");
		pressButton(associationDialogOKButton);

		//
		// Verify the new association
		//

		// verify the VT tool is now in the tool chest (has been imported as a result of the user
		// choice)
		ToolServices toolServices = frontEndTool.getToolServices();
		ToolChest toolChest = toolServices.getToolChest();
		ToolTemplate toolTemplate = toolChest.getToolTemplate(VTToolName);
		assertNotNull("Default tool not imported when chosen as the associated tool", toolTemplate);

		// double-click a program in the Front End
		clickMouse(jTree, MouseEvent.BUTTON1, bounds.x + 5, bounds.y + 5, 2, 0);
		waitForSwing();

		// make sure the VT tool is launched
		tool = waitForTool(VTToolName, project);

		// close the VT tool
		// we first have to close the wizard...
		final WizardManager wizard = waitForDialogComponent(WizardManager.class);
		runSwing(() -> wizard.close());

		// ...then the tool
		close(tool);
		waitForSwing();

		//
		// edit the association
		//
		// find the 'Program' entry		
		rowCount = associationTable.getRowCount();
		programRow = -1;
		for (int i = 0; i < rowCount; i++) {
			ContentHandler handler = (ContentHandler) associationTable.getValueAt(i, 0);
			if ("Program".equals(handler.getContentType())) {
				programRow = i;
				break;
			}
		}
		assertTrue("Unable to find the 'Program' entry in the associations table",
			programRow != -1);

		// select the program entry in the table
		final int newFinalProgramRow = programRow;
		runSwing(() -> associationTable.selectRow(newFinalProgramRow));

		// click the restore button
		JButton restoreButton =
			findButtonByText(associationDialog.getComponent(), "Restore Default");
		pressButton(restoreButton);

		// press OK
		JButton associationDialogOKButton2 =
			findButtonByText(associationDialog.getComponent(), "OK");
		pressButton(associationDialogOKButton2);

		//
		// Verify the new association
		//
		// double-click a program in the Front End
		clickMouse(jTree, MouseEvent.BUTTON1, bounds.x + 5, bounds.y + 5, 2, 0);
		waitForSwing();

		// make sure the 'CodeBrowser' tool is launched
		tool = waitForTool("CodeBrowser", project);

		// close the 'CodeBrowser' tool
		close(tool);
		waitForSwing();
	}

	@Test
	public void testImportDefaultTools() throws Exception {
		final ToolChest tc = frontEndTool.getToolServices().getToolChest();
		int count = tc.getToolCount();
		ToolTemplate[] origConfigs = tc.getToolTemplates();

		Set<String> defaultTools = ResourceManager.getResourceNames("defaultTools", ".tool");
		Set<String> extraToolsList = ResourceManager.getResourceNames("extraTools", ".tool");

		DockingActionIf importAction = getAction("Import Ghidra Tools");
		performAction(importAction, false);
		waitForSwing();
		ImportGhidraToolsDialog d = waitForDialogComponent(ImportGhidraToolsDialog.class);
		assertNotNull(d);

		JList<?> defList = findComponent(d, JList.class);
		assertNotNull(defList);

		@SuppressWarnings("rawtypes")
		ListCellRenderer renderer = defList.getCellRenderer();
		for (int i = 0; i < defaultTools.size(); i++) {
			@SuppressWarnings("unchecked")
			JCheckBox cb =
				(JCheckBox) renderer.getListCellRendererComponent(defList, null, i, false, false);
			assertTrue(!cb.isSelected());
		}

		final JButton selectAllButton = (JButton) getInstanceField("selectAllButton", d);
		runSwing(() -> selectAllButton.doClick());

		pressButtonByText(d, "OK");
		waitForSwing();
		assertEquals(count + defaultTools.size() + extraToolsList.size(), tc.getToolCount());

		ToolTemplate[] configs = tc.getToolTemplates();

		// remove default tools that were just added
		ArrayList<String> origList = new ArrayList<>();
		for (ToolTemplate origConfig : origConfigs) {
			origList.add(origConfig.getName());
		}
		final ArrayList<String> newList = new ArrayList<>();
		for (ToolTemplate config : configs) {
			newList.add(config.getName());
		}
		newList.removeAll(origList);
		runSwing(() -> {
			for (int i = 0; i < newList.size(); i++) {
				tc.remove(newList.get(i));
			}
		});
		assertEquals(origList.size(), tc.getToolCount());
	}

	@Test
	public void testImportSomeDefaultTools() throws Exception {
		final ToolChest tc = frontEndTool.getToolServices().getToolChest();
		final ToolTemplate[] origConfigs = tc.getToolTemplates();
		runSwing(() -> {
			for (ToolTemplate origConfig : origConfigs) {
				tc.remove(origConfig.getName());
			}
		});

		DockingActionIf importAction = getAction("Import Ghidra Tools");
		performAction(importAction, false);
		waitForSwing();
		ImportGhidraToolsDialog d = waitForDialogComponent(ImportGhidraToolsDialog.class);
		assertNotNull(d);

		pressButtonByText(d, "Select None");
		@SuppressWarnings("unchecked")
		JList<Object> defList = findComponent(d, JList.class);
		assertNotNull(defList);

		ListCellRenderer<Object> renderer = defList.getCellRenderer();
		JCheckBox cb =
			(JCheckBox) renderer.getListCellRendererComponent(defList, null, 0, false, false);
		Rectangle rect = defList.getCellBounds(0, 0);
		clickMouse(defList, 1, rect.x + 10, rect.y + 10, 1, 0);
		assertTrue(cb.isSelected());

		pressButtonByText(d, "OK");
		waitForSwing();

		ToolTemplate[] configs = tc.getToolTemplates();
		assertEquals(1, configs.length);
	}

	@Test
	public void testExportTool() throws Exception {

		// export using the menu action
		createTool();

		DockingActionIf exportAction = getAction("Untitled", "Export Tool");
		performAction(exportAction, "Untitled", false);
		GhidraFileChooser chooser = waitForDialogComponent(GhidraFileChooser.class);

		setSelectedFile(chooser, exportFile);

		pressButtonByText(chooser, "Export");
		waitForSwing();
		assertTrue(exportFile.exists());
	}

	@Test
	public void testExportToolOverwrite() throws Exception {
		// export using the menu action
		createTool();

		DockingActionIf exportAction = getAction("Untitled", "Export Tool");
		performAction(exportAction, "Untitled", false);
		GhidraFileChooser chooser = waitForDialogComponent(GhidraFileChooser.class);

		setSelectedFile(chooser, exportFile);
		pressButtonByText(chooser, "Export");
		waitForSwing();

		performAction(exportAction, "Untitled", false);
		chooser = waitForDialogComponent(GhidraFileChooser.class);

		setSelectedFile(chooser, exportFile);
		JButton b = findButtonByText(chooser, "Export");
		pressButton(b, false);
		OptionDialog optD = waitForDialogComponent(OptionDialog.class);
		assertNotNull(optD);
		assertEquals("Overwrite?", optD.getTitle());

		pressButtonByText(optD.getComponent(), "Overwrite");
		waitForSwing();
		assertTrue(exportFile.exists());
	}

	@Test
	public void testExportToolOverwriteNo() throws Exception {
		// export using the menu action
		createTool();

		DockingActionIf exportAction = getAction("Untitled", "Export Tool");
		performAction(exportAction, "Untitled", false);
		GhidraFileChooser chooser = waitForDialogComponent(GhidraFileChooser.class);

		setSelectedFile(chooser, exportFile);
		pressButtonByText(chooser, "Export");
		waitForSwing();

		performAction(exportAction, "Untitled", false);

		chooser = waitForDialogComponent(GhidraFileChooser.class);
		setSelectedFile(chooser, exportFile);

		JButton b = findButtonByText(chooser, "Export");
		pressButton(b, false);
		waitForSwing();

		OptionDialog optD = waitForDialogComponent(OptionDialog.class);
		assertNotNull(optD);
		assertEquals("Overwrite?", optD.getTitle());

		pressButtonByText(optD.getComponent(), "Cancel");
		chooser = waitForDialogComponent(GhidraFileChooser.class);
		pressButtonByText(chooser, "Cancel");
	}

	@Test
	public void testExportToolOverwriteCancel() throws Exception {
		// export using the menu action
		createTool();

		DockingActionIf exportAction = getAction("Untitled", "Export Tool");
		performAction(exportAction, "Untitled", false);
		GhidraFileChooser chooser = waitForDialogComponent(GhidraFileChooser.class);

		setSelectedFile(chooser, exportFile);
		pressButtonByText(chooser, "Export");
		waitForSwing();

		performAction(exportAction, "Untitled", false);

		chooser = waitForDialogComponent(GhidraFileChooser.class);
		setSelectedFile(chooser, exportFile);

		JButton b = findButtonByText(chooser, "Export");
		pressButton(b, false);
		OptionDialog optD = waitForDialogComponent(OptionDialog.class);
		assertNotNull(optD);
		assertEquals("Overwrite?", optD.getTitle());

		pressButtonByText(optD.getComponent(), "Cancel");
	}

	@Test
	public void testExportToolFromIcon() throws Exception {
		createTool();

		DockingActionIf exportAction = getAction("Export Tool");
		performToolButtonAction(exportAction, "Untitled", false, false);
		GhidraFileChooser chooser = waitForDialogComponent(GhidraFileChooser.class);
		setSelectedFile(chooser, exportFile);

		pressButtonByText(chooser, "Export");
		waitForSwing();
		assertTrue(exportFile.exists());
	}

	@Test
	public void testCloseTool() throws Exception {
		// action on tool button for running tool
		createTool();

		DockingActionIf closeAction = getAction("Close Tool");
		performToolButtonAction(closeAction, "Untitled", false, true);

		assertEquals(0, frontEndTool.getToolServices().getRunningTools().length);
	}

	private Program buildProgram(String programName) throws Exception {
		ProgramBuilder builder = new ProgramBuilder(programName, ProgramBuilder._TOY);
		builder.createMemory("test1", Long.toHexString(0x1001000), 0x2000);
		return builder.getProgram();
	}

	private void close(final PluginTool tool) {
		runSwing(() -> tool.close());
	}

	private void removePreferences() {
		Preferences.clear();
	}

	private PluginTool waitForTool(String toolName, Project project) {
		PluginTool tool = null;
		int sleepTime = 100;
		int waitCount = 0;
		while (tool == null && waitCount < 300) {
			waitForSwing();
			sleep(sleepTime);
			ToolManager toolManager = project.getToolManager();
			PluginTool[] runningTools = toolManager.getRunningTools();
			if (runningTools != null && runningTools.length > 0) {
				tool = runningTools[0];
			}
		}

		assertNotNull("Did not find a single running " + toolName + " tool", tool);
		assertEquals("Running tool is not " + toolName, toolName, tool.getName());

		return tool;
	}

	private void initializeToolChestToJustCodeBrowser() {
		final ToolServices toolServices = frontEndTool.getToolServices();
		final ToolChest toolChest = toolServices.getToolChest();

		final AtomicReference<String> failedTool = new AtomicReference<>();
		runSwing(() -> {
			ToolTemplate[] toolTemplates = toolChest.getToolTemplates();
			for (ToolTemplate toolTemplate : toolTemplates) {
				String name = toolTemplate.getName();
				if (!name.equals("CodeBrowser")) {
					if (!toolChest.remove(name)) {
						failedTool.set(name);
						return;
					}
				}
			}

		});

		String toolName = failedTool.get();
		assertNull("Failed to remove tool: " + toolName, toolName);
		assertEquals("Did not remove tools as expected", 1, toolChest.getToolCount());
	}

	private void setSelectedFile(GhidraFileChooser chooser, File f) throws Exception {
		runSwing(() -> chooser.setSelectedFile(f));
		waitForUpdateOnChooser(chooser);
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

	private DockingActionIf getAction(String actionName) {
		DockingActionIf action =
			AbstractDockingTest.getAction(frontEndTool, "FrontEndPlugin", actionName);
		return action;
	}

	private PluginTool createTool() throws Exception {
		DockingActionIf createAction = getAction("Create Tool");
		performAction(createAction, true);
		PluginTool[] tools = frontEndTool.getProject().getToolManager().getRunningTools();
		final PluginTool tool = tools[0];
		runSwing(() -> {
			try {
				tool.addPlugin(CodeBrowserPlugin.class.getName());
			}
			catch (PluginException e) {
				e.printStackTrace();
			}
		});

		DockingActionIf action = getAction(tool, ToolConstants.TOOL_OWNER, "Save Tool As");
		performAction(action, false);

		waitForSwing();
		SaveToolConfigDialog saveDialog = waitForDialogComponent(SaveToolConfigDialog.class);
		pressButtonByText(saveDialog, "Save");
		waitForSwing();
		return tool;
	}

	private void performToolButtonAction(final DockingActionIf action, String name, boolean doWait,
			boolean runningTool) throws Exception {
		final ToolButton tb = findToolButton(frontEndTool.getToolFrame(), name, runningTool);
		Runnable r = () -> action.actionPerformed(new ActionContext(null, tb, tb));
		if (doWait) {
			runSwing(r);
		}
		else {
			runSwing(r, false);
		}
		waitForSwing();
	}

	private ToolButton findToolButton(Container parent, String toolName, boolean runningTool) {
		Component[] comps = parent.getComponents();
		for (Component comp : comps) {
			if (comp instanceof ToolButton) {
				ToolButton tb = (ToolButton) comp;
				if (tb.getToolTemplate().getName().equals(toolName) &&
					(tb.isRunningTool() == runningTool)) {
					return tb;
				}
			}
			else if (comp instanceof Container) {
				ToolButton tb = findToolButton((Container) comp, toolName, runningTool);
				if (tb != null) {
					return tb;
				}
			}
		}
		return null;
	}

	private void performAction(final DockingActionIf action, String name, boolean doWait)
			throws Exception {

		runSwing(() -> {
			JMenuItem item = new JMenuItem(name);
			action.actionPerformed(new ActionContext(null, null, item));
		}, doWait);

		waitForSwing();
	}

}
