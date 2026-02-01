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
package ghidra.app.plugin.core.programtree;

import static org.junit.Assert.*;

import java.awt.Component;
import java.awt.Container;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.*;

import org.junit.*;

import docking.DefaultActionContext;
import docking.action.DockingActionIf;
import docking.widgets.dialogs.InputDialog;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.services.ProgramManager;
import ghidra.app.services.ViewManagerService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSetView;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;

/**
 * Test the view manager plugin that controls the view in the browser and the
 * program tree.
 */
public class ViewManagerPluginTest extends AbstractGhidraHeadedIntegrationTest {

	private static final String DEFAULT_TREE_NAME = "Program Tree";

	private TestEnv env;
	private PluginTool tool;
	private ProgramDB program;
	private ProgramTreePlugin plugin;
	private ViewManagerComponentProvider provider;
	private ProgramManager programMgr;
	private ViewPanel viewPanel;
	private JTabbedPane tabbedPane;
	private CodeBrowserPlugin cb;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.getTool();
		tool.addPlugin(ProgramTreePlugin.class.getName());
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		cb = env.getPlugin(CodeBrowserPlugin.class);

		ProgramBuilder builder = new ProgramBuilder("notepad", ProgramBuilder._TOY);
		program = builder.getProgram();

		builder.createMemory("test1", "0x1001000", 0x2000);

		//Main Tree
		builder.createProgramTree("Main Tree");
		builder.createFragment("Main Tree", "", ".text", "0x1001000", "0x10011ff");

		builder.createProgramTree("Tree One");
		builder.createFragment("Tree One", "", ".text", "0x1001000", "0x10011ff");

		builder.createProgramTree("Tree Two");
		builder.createFragment("Tree Two", "", ".text", "0x1001000", "0x10011ff");

		//Tree Three
		builder.createProgramTree("Tree Three");
		builder.createFragment("Tree Three", "", ".text", "0x1001000", "0x10011ff");

		programMgr = tool.getService(ProgramManager.class);
		programMgr.openProgram(program.getDomainFile());

		ViewManagerService vms = tool.getService(ViewManagerService.class);
		provider = (ViewManagerComponentProvider) vms;
		tool.showComponentProvider(provider, true);

		plugin = getPlugin(tool, ProgramTreePlugin.class);
		viewPanel = (ViewPanel) provider.getComponent();
		findTabbedPane();
	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

	@Test
	public void testDefaultTreeView() {

		ViewProviderService vps = provider.getCurrentViewProvider();
		assertNotNull(vps);
		assertEquals(DEFAULT_TREE_NAME, vps.getViewName());
		int index = tabbedPane.getSelectedIndex();
		assertEquals(DEFAULT_TREE_NAME, tabbedPane.getTitleAt(index));
	}

	@Test
	public void testCloseProgram() {
		programMgr.closeProgram();
		ViewProviderService vps = provider.getCurrentViewProvider();
		assertNotNull(vps);
		assertEquals(DEFAULT_TREE_NAME, vps.getViewName());
		int index = tabbedPane.getSelectedIndex();
		assertEquals(DEFAULT_TREE_NAME, tabbedPane.getTitleAt(index));
		assertTrue(provider.getCurrentView().isEmpty());
	}

	@Test
	public void testCreateDefaultView() throws Exception {
		ProgramTreePlugin treePlugin = env.getPlugin(ProgramTreePlugin.class);
		final DockingActionIf createTreeAction = getAction(treePlugin, "Create Default Tree View");
		SwingUtilities
				.invokeAndWait(() -> createTreeAction.actionPerformed(new DefaultActionContext()));
		program.flushEvents();

		ViewProviderService vps = provider.getCurrentViewProvider();

		String[] treeNames = program.getListing().getTreeNames();

		assertEquals(treeNames.length, tabbedPane.getTabCount());
		assertEquals(DEFAULT_TREE_NAME + "(1)", vps.getViewName());
		assertEquals(tabbedPane.getSelectedComponent(), vps.getViewComponent());
		performAction(createTreeAction);
		program.flushEvents();
		vps = provider.getCurrentViewProvider();
		treeNames = program.getListing().getTreeNames();

		assertEquals(treeNames.length, tabbedPane.getTabCount());
		assertEquals(DEFAULT_TREE_NAME + "(2)", vps.getViewName());
		assertEquals(tabbedPane.getSelectedComponent(), vps.getViewComponent());

	}

	@Test
	public void testUndoRedo() throws Exception {
		ProgramTreePlugin treePlugin = env.getPlugin(ProgramTreePlugin.class);
		final DockingActionIf createTreeAction = getAction(treePlugin, "Create Default Tree View");
		performAction(createTreeAction);
		program.flushEvents();
		env.showTool();
		ViewProviderService vps = provider.getCurrentViewProvider();

		String[] treeNames = program.getListing().getTreeNames();

		assertEquals(treeNames.length, tabbedPane.getTabCount());
		assertEquals(DEFAULT_TREE_NAME + "(1)", vps.getViewName());
		assertEquals(tabbedPane.getSelectedComponent(), vps.getViewComponent());
		performAction(createTreeAction);
		program.flushEvents();
		vps = provider.getCurrentViewProvider();
		treeNames = program.getListing().getTreeNames();

		assertEquals(treeNames.length, tabbedPane.getTabCount());
		assertEquals(DEFAULT_TREE_NAME + "(2)", vps.getViewName());
		assertEquals(tabbedPane.getSelectedComponent(), vps.getViewComponent());

		undo(program);
		// tree 2 should be removed
		vps = provider.getCurrentViewProvider();
		treeNames = program.getListing().getTreeNames();

		assertEquals(treeNames.length, tabbedPane.getTabCount());
		assertEquals(DEFAULT_TREE_NAME + "(1)", vps.getViewName());
		assertEquals(tabbedPane.getSelectedComponent(), vps.getViewComponent());

		redo(program);
		// tree 2 should be back    
		vps = provider.getCurrentViewProvider();
		treeNames = program.getListing().getTreeNames();

		assertEquals(treeNames.length, tabbedPane.getTabCount());
		assertEquals(DEFAULT_TREE_NAME + "(2)", vps.getViewName());
		assertEquals(tabbedPane.getSelectedComponent(), vps.getViewComponent());

		undo(program);
		undo(program);
		// program 1 and 2 should be removed
		vps = provider.getCurrentViewProvider();
		treeNames = program.getListing().getTreeNames();

		assertEquals(treeNames.length, tabbedPane.getTabCount());
		assertEquals(DEFAULT_TREE_NAME, vps.getViewName());
		assertEquals(tabbedPane.getSelectedComponent(), vps.getViewComponent());

		redo(program);
		// tree 1 should be back
		vps = provider.getCurrentViewProvider();
		treeNames = program.getListing().getTreeNames();

		assertEquals(treeNames.length, tabbedPane.getTabCount());
		assertEquals(DEFAULT_TREE_NAME + "(1)", vps.getViewName());
		assertEquals(tabbedPane.getSelectedComponent(), vps.getViewComponent());

		redo(program);
		// tree 2 should be back    
		vps = provider.getCurrentViewProvider();
		treeNames = program.getListing().getTreeNames();

		assertEquals(treeNames.length, tabbedPane.getTabCount());
		assertEquals(DEFAULT_TREE_NAME + "(2)", vps.getViewName());
		assertEquals(tabbedPane.getSelectedComponent(), vps.getViewComponent());
	}

	@Test
	public void testSelectView() {

		// make "Main Tree" the current view
		setCurrentViewProvider("Main Tree");

		ViewProviderService vps = provider.getCurrentViewProvider();
		assertEquals("Main Tree", vps.getViewName());
		assertEquals(tabbedPane.getSelectedComponent(), vps.getViewComponent());
		assertTrue(provider.getCurrentView().hasSameAddresses(cb.getView()));
		assertTrue(provider.getCurrentView().hasSameAddresses(vps.getCurrentView()));
	}

	@Test
	public void testCloseView() throws Exception {
		// close "Program Tree"
		final DockingActionIf closeAction = getAction(plugin, "Close Tree View");
		performAction(closeAction);

		waitForBusyTool(tool);

		String[] treeNames = program.getListing().getTreeNames();
		assertEquals(treeNames.length - 1, tabbedPane.getTabCount());
		ViewProviderService vps = provider.getCurrentViewProvider();
		assertEquals(treeNames[1], vps.getViewName());
		assertEquals(tabbedPane.getSelectedComponent(), vps.getViewComponent());
		assertTrue(provider.getCurrentView().hasSameAddresses(cb.getView()));
		assertTrue(provider.getCurrentView().hasSameAddresses(vps.getCurrentView()));

		assertNotNull(program.getListing().getRootModule(DEFAULT_TREE_NAME));
	}

	@Test
	public void testDeleteView() throws Exception {

		env.showTool();

		// delete the "Tree Two" view
		setCurrentViewProvider("Tree Two");

		final DockingActionIf deleteAction = getAction(plugin, "Delete Tree View");
		performAction(deleteAction);

		waitForBusyTool(tool);

		assertNull(program.getListing().getRootModule("Tree Two"));
		String[] treeNames = program.getListing().getTreeNames();
		assertEquals(treeNames.length, tabbedPane.getTabCount());
		// view reverts to first tree
		assertEquals(0, tabbedPane.getSelectedIndex());
		assertTrue(provider.getCurrentView().hasSameAddresses(cb.getView()));

		undo(program);

		// Tree Two should come back
		assertNotNull(program.getListing().getRootModule("Tree Two"));
		ViewProviderService vps = provider.getCurrentViewProvider();
		assertEquals("Tree Two", vps.getViewName());
		assertTrue(provider.getCurrentView().hasSameAddresses(cb.getView()));
		assertTrue(provider.getCurrentView().hasSameAddresses(vps.getCurrentView()));

		redo(program);

		assertNull(program.getListing().getRootModule("Tree Two"));
		treeNames = program.getListing().getTreeNames();
		assertEquals(treeNames.length, tabbedPane.getTabCount());
		// view reverts to first tree
		assertEquals(0, tabbedPane.getSelectedIndex());
		assertTrue(provider.getCurrentView().hasSameAddresses(cb.getView()));
		assertTrue(provider.getCurrentView().hasSameAddresses(vps.getCurrentView()));

	}

	@Test
	public void testDeleteLastView() throws Exception {
		final DockingActionIf deleteAction = getAction(plugin, "Delete Tree View");

		setCurrentViewProvider("Main Tree");

		performAction(deleteAction);
		waitForBusyTool(tool);

		setCurrentViewProvider("Tree One");

		performAction(deleteAction);
		waitForBusyTool(tool);

		setCurrentViewProvider("Tree Two");

		performAction(deleteAction);
		waitForBusyTool(tool);

		setCurrentViewProvider("Tree Three");

		performAction(deleteAction);
		waitForBusyTool(tool);

		// attempt to delete the last view
		performAction(deleteAction);
		waitForBusyTool(tool);

		ViewProviderService vps = provider.getCurrentViewProvider();
		assertEquals(DEFAULT_TREE_NAME, vps.getViewName());
		assertEquals(tabbedPane.getSelectedComponent(), vps.getViewComponent());
		assertTrue(provider.getCurrentView().hasSameAddresses(cb.getView()));
		assertTrue(provider.getCurrentView().hasSameAddresses(vps.getCurrentView()));

	}

	@Test
	public void testDeleteLastVisibleView() throws Exception {

		final DockingActionIf closeAction = getAction(plugin, "Close Tree View");

		setCurrentViewProvider(DEFAULT_TREE_NAME);
		performAction(closeAction);

		setCurrentViewProvider("Main Tree");
		runSwing(() -> {
			closeAction.actionPerformed(new DefaultActionContext());
			provider.setCurrentViewProvider("Tree One");
			closeAction.actionPerformed(new DefaultActionContext());
			provider.setCurrentViewProvider("Tree Two");
			closeAction.actionPerformed(new DefaultActionContext());
			provider.setCurrentViewProvider("Tree Three");
			DockingActionIf deleteAction = getAction(plugin, "Delete Tree View");
			deleteAction.actionPerformed(new DefaultActionContext());
		});
		// cannot delete the last view
		ViewProviderService vps = provider.getCurrentViewProvider();
		assertEquals("Tree Three", vps.getViewName());
		assertEquals(tabbedPane.getSelectedComponent(), vps.getViewComponent());
		assertTrue(provider.getCurrentView().hasSameAddresses(cb.getView()));
		assertTrue(provider.getCurrentView().hasSameAddresses(vps.getCurrentView()));
	}

	@Test
	public void testRenameView() throws Exception {
		env.showTool();
		waitForTasks();

		setCurrentViewProvider(DEFAULT_TREE_NAME);

		DockingActionIf renameAction = getAction(plugin, "Rename Tree View");
		performAction(renameAction, false);

		InputDialog dialog = waitForDialogComponent(InputDialog.class);
		dialog.setValue("My Tree");
		pressButtonByText(dialog, "OK");
		waitForProgram(program);

		ViewProviderService vps = runSwing(() -> provider.getCurrentViewProvider());
		assertEquals("My Tree", vps.getViewName());
		assertNull(program.getListing().getRootModule(DEFAULT_TREE_NAME));
		assertTrue(provider.getCurrentView().hasSameAddresses(cb.getView()));
		assertTrue(provider.getCurrentView().hasSameAddresses(vps.getCurrentView()));

		undo(program);
		vps = runSwing(() -> provider.getCurrentViewProvider());
		assertEquals(DEFAULT_TREE_NAME, vps.getViewName());
		assertNotNull(program.getListing().getRootModule(DEFAULT_TREE_NAME));

		redo(program);
		provider.getCurrentViewProvider();
		vps = runSwing(() -> provider.getCurrentViewProvider());
		assertEquals("My Tree", vps.getViewName());
		assertNull(program.getListing().getRootModule(DEFAULT_TREE_NAME));
	}

	@Test
	public void testRenameViewDuplicate() throws Exception {

		env.showTool();

		waitForTasks();
		waitForSwing();

		setCurrentViewProvider(DEFAULT_TREE_NAME);

		DockingActionIf renameAction = getAction(plugin, "Rename Tree View");
		performAction(renameAction, false);

		InputDialog dialog = waitForDialogComponent(InputDialog.class);
		dialog.setValue("Main Tree");
		pressButtonByText(dialog, "OK");
		waitForProgram(program);

		ViewProviderService vps = provider.getCurrentViewProvider();
		assertEquals(DEFAULT_TREE_NAME, vps.getViewName());
		assertTrue(provider.getCurrentView().hasSameAddresses(cb.getView()));
		assertTrue(provider.getCurrentView().hasSameAddresses(vps.getCurrentView()));
	}

	@Test
	public void testSaveRestoreState() {

		setCurrentViewProvider("Main Tree");
		AddressSetView set = provider.getCurrentView();

		env.saveRestoreToolState();

		ViewProviderService vps = provider.getCurrentViewProvider();
		assertEquals("Main Tree", vps.getViewName());
		assertTrue(set.hasSameAddresses(provider.getCurrentView()));
		assertTrue(set.hasSameAddresses(cb.getView()));
		assertTrue(provider.getCurrentView().hasSameAddresses(vps.getCurrentView()));
	}

	@Test
	public void testCloseSaveRestoreState() throws Exception {
		//
		// Test that we can close one of the program's trees and have the close correctly persist
		// when saved and restored. This happens when a user closes a tree, then changes between
		// program tabs.
		//
		final DockingActionIf closeAction = getAction(plugin, "Close Tree View");
		setCurrentViewProvider(DEFAULT_TREE_NAME);
		performAction(closeAction);

		setCurrentViewProvider("Main Tree");
		AddressSetView set = provider.getCurrentView();

		env.saveRestoreToolState();

		String[] treeNames = program.getListing().getTreeNames();
		assertEquals(treeNames.length - 1, tabbedPane.getTabCount());

		ViewProviderService vps = provider.getCurrentViewProvider();
		assertEquals("Main Tree", vps.getViewName());
		assertTrue(set.hasSameAddresses(provider.getCurrentView()));
		assertTrue(set.hasSameAddresses(cb.getView()));
		assertTrue(provider.getCurrentView().hasSameAddresses(vps.getCurrentView()));
	}

	@SuppressWarnings("unused")
	private JTextField findTextField(Container container) {
		Component[] c = container.getComponents();
		for (Component element : c) {
			if (element instanceof JTextField) {
				return (JTextField) element;
			}
			if (element instanceof Container) {
				JTextField tf = findTextField((Container) element);
				if (tf != null) {
					return tf;
				}
			}
		}
		return null;
	}

	private void findTabbedPane() {
		Component[] comp = viewPanel.getComponents();
		for (Component element : comp) {
			if (element instanceof JTabbedPane) {
				tabbedPane = (JTabbedPane) element;
				break;
			}
		}

		assertNotNull(tabbedPane);
	}

	private void setCurrentViewProvider(final String viewName) {
		final AtomicReference<ViewProviderService> ref = new AtomicReference<>();
		runSwing(() -> {
			provider.setCurrentViewProvider(viewName);
			ref.set(provider.getCurrentViewProvider());
		});

		ViewProviderService newProvider = ref.get();
		assertEquals("Did not find the tree view provider: " + viewName, viewName,
			newProvider.getViewName());
	}

}
