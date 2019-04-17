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

import java.awt.*;
import java.awt.event.ActionListener;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.*;

import org.junit.*;

import docking.ActionContext;
import docking.EditWindow;
import docking.action.DockingActionIf;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.services.ProgramManager;
import ghidra.app.services.ViewManagerService;
import ghidra.app.util.PluginConstants;
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
		cb = env.getPlugin((CodeBrowserPlugin.class));

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
		assertEquals(PluginConstants.DEFAULT_TREE_NAME, vps.getViewName());
		int index = tabbedPane.getSelectedIndex();
		assertEquals(PluginConstants.DEFAULT_TREE_NAME, tabbedPane.getTitleAt(index));
	}

	@Test
	public void testCloseProgram() {
		programMgr.closeProgram();
		ViewProviderService vps = provider.getCurrentViewProvider();
		assertNotNull(vps);
		assertEquals(PluginConstants.DEFAULT_TREE_NAME, vps.getViewName());
		int index = tabbedPane.getSelectedIndex();
		assertEquals(PluginConstants.DEFAULT_TREE_NAME, tabbedPane.getTitleAt(index));
		assertTrue(provider.getCurrentView().isEmpty());
	}

	@Test
	public void testCreateDefaultView() throws Exception {
		ProgramTreePlugin treePlugin = env.getPlugin(ProgramTreePlugin.class);
		final DockingActionIf createTreeAction = getAction(treePlugin, "Create Default Tree View");
		SwingUtilities.invokeAndWait(() -> createTreeAction.actionPerformed(new ActionContext()));
		program.flushEvents();

		ViewProviderService vps = provider.getCurrentViewProvider();

		String[] treeNames = program.getListing().getTreeNames();

		assertEquals(treeNames.length, tabbedPane.getTabCount());
		assertEquals(PluginConstants.DEFAULT_TREE_NAME + "(1)", vps.getViewName());
		assertEquals(tabbedPane.getSelectedComponent(), vps.getViewComponent());
		SwingUtilities.invokeAndWait(() -> createTreeAction.actionPerformed(new ActionContext()));
		program.flushEvents();
		vps = provider.getCurrentViewProvider();
		treeNames = program.getListing().getTreeNames();

		assertEquals(treeNames.length, tabbedPane.getTabCount());
		assertEquals(PluginConstants.DEFAULT_TREE_NAME + "(2)", vps.getViewName());
		assertEquals(tabbedPane.getSelectedComponent(), vps.getViewComponent());

	}

	@Test
	public void testUndoRedo() throws Exception {
		ProgramTreePlugin treePlugin = env.getPlugin(ProgramTreePlugin.class);
		final DockingActionIf createTreeAction = getAction(treePlugin, "Create Default Tree View");
		SwingUtilities.invokeAndWait(() -> createTreeAction.actionPerformed(new ActionContext()));
		program.flushEvents();
		env.showTool();
		ViewProviderService vps = provider.getCurrentViewProvider();

		String[] treeNames = program.getListing().getTreeNames();

		assertEquals(treeNames.length, tabbedPane.getTabCount());
		assertEquals(PluginConstants.DEFAULT_TREE_NAME + "(1)", vps.getViewName());
		assertEquals(tabbedPane.getSelectedComponent(), vps.getViewComponent());
		SwingUtilities.invokeAndWait(() -> createTreeAction.actionPerformed(new ActionContext()));
		program.flushEvents();
		vps = provider.getCurrentViewProvider();
		treeNames = program.getListing().getTreeNames();

		assertEquals(treeNames.length, tabbedPane.getTabCount());
		assertEquals(PluginConstants.DEFAULT_TREE_NAME + "(2)", vps.getViewName());
		assertEquals(tabbedPane.getSelectedComponent(), vps.getViewComponent());

		undo(program);
		// tree 2 should be removed
		vps = provider.getCurrentViewProvider();
		treeNames = program.getListing().getTreeNames();

		assertEquals(treeNames.length, tabbedPane.getTabCount());
		assertEquals(PluginConstants.DEFAULT_TREE_NAME + "(1)", vps.getViewName());
		assertEquals(tabbedPane.getSelectedComponent(), vps.getViewComponent());

		redo(program);
		// tree 2 should be back    
		vps = provider.getCurrentViewProvider();
		treeNames = program.getListing().getTreeNames();

		assertEquals(treeNames.length, tabbedPane.getTabCount());
		assertEquals(PluginConstants.DEFAULT_TREE_NAME + "(2)", vps.getViewName());
		assertEquals(tabbedPane.getSelectedComponent(), vps.getViewComponent());

		undo(program);
		undo(program);
		// program 1 and 2 should be removed
		vps = provider.getCurrentViewProvider();
		treeNames = program.getListing().getTreeNames();

		assertEquals(treeNames.length, tabbedPane.getTabCount());
		assertEquals(PluginConstants.DEFAULT_TREE_NAME, vps.getViewName());
		assertEquals(tabbedPane.getSelectedComponent(), vps.getViewComponent());

		redo(program);
		// tree 1 should be back
		vps = provider.getCurrentViewProvider();
		treeNames = program.getListing().getTreeNames();

		assertEquals(treeNames.length, tabbedPane.getTabCount());
		assertEquals(PluginConstants.DEFAULT_TREE_NAME + "(1)", vps.getViewName());
		assertEquals(tabbedPane.getSelectedComponent(), vps.getViewComponent());

		redo(program);
		// tree 2 should be back    
		vps = provider.getCurrentViewProvider();
		treeNames = program.getListing().getTreeNames();

		assertEquals(treeNames.length, tabbedPane.getTabCount());
		assertEquals(PluginConstants.DEFAULT_TREE_NAME + "(2)", vps.getViewName());
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
		SwingUtilities.invokeAndWait(() -> closeAction.actionPerformed(new ActionContext()));

		String[] treeNames = program.getListing().getTreeNames();
		assertEquals(treeNames.length - 1, tabbedPane.getTabCount());
		ViewProviderService vps = provider.getCurrentViewProvider();
		assertEquals(treeNames[1], vps.getViewName());
		assertEquals(tabbedPane.getSelectedComponent(), vps.getViewComponent());
		assertTrue(provider.getCurrentView().hasSameAddresses(cb.getView()));
		assertTrue(provider.getCurrentView().hasSameAddresses(vps.getCurrentView()));

		assertNotNull(program.getListing().getRootModule(PluginConstants.DEFAULT_TREE_NAME));
	}

	@Test
	public void testDeleteView() throws Exception {
		// delete the "Tree Two" view
		setCurrentViewProvider("Tree Two");

		final DockingActionIf deleteAction = getAction(plugin, "Delete Tree View");
		SwingUtilities.invokeAndWait(() -> deleteAction.actionPerformed(new ActionContext()));
		program.flushEvents();
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

		SwingUtilities.invokeAndWait(() -> deleteAction.actionPerformed(new ActionContext()));
		program.flushEvents();

		setCurrentViewProvider("Tree One");

		SwingUtilities.invokeAndWait(() -> deleteAction.actionPerformed(new ActionContext()));
		program.flushEvents();

		setCurrentViewProvider("Tree Two");

		SwingUtilities.invokeAndWait(() -> deleteAction.actionPerformed(new ActionContext()));
		program.flushEvents();

		setCurrentViewProvider("Tree Three");

		SwingUtilities.invokeAndWait(() -> deleteAction.actionPerformed(new ActionContext()));
		program.flushEvents();

		// attempt to delete the last view
		SwingUtilities.invokeAndWait(() -> deleteAction.actionPerformed(new ActionContext()));
		program.flushEvents();

		ViewProviderService vps = provider.getCurrentViewProvider();
		assertEquals(PluginConstants.DEFAULT_TREE_NAME, vps.getViewName());
		assertEquals(tabbedPane.getSelectedComponent(), vps.getViewComponent());
		assertTrue(provider.getCurrentView().hasSameAddresses(cb.getView()));
		assertTrue(provider.getCurrentView().hasSameAddresses(vps.getCurrentView()));

	}

	@Test
	public void testDeleteLastVisibleView() throws Exception {

		final DockingActionIf closeAction = getAction(plugin, "Close Tree View");

		setCurrentViewProvider(PluginConstants.DEFAULT_TREE_NAME);
		SwingUtilities.invokeAndWait(() -> closeAction.actionPerformed(new ActionContext()));

		setCurrentViewProvider("Main Tree");
		SwingUtilities.invokeAndWait(() -> {
			closeAction.actionPerformed(new ActionContext());
			provider.setCurrentViewProvider("Tree One");
			closeAction.actionPerformed(new ActionContext());
			provider.setCurrentViewProvider("Tree Two");
			closeAction.actionPerformed(new ActionContext());
			provider.setCurrentViewProvider("Tree Three");
			DockingActionIf deleteAction = getAction(plugin, "Delete Tree View");
			deleteAction.actionPerformed(new ActionContext());
		});
		// cannot delete the last view
		ViewProviderService vps = provider.getCurrentViewProvider();
		assertEquals("Tree Three", vps.getViewName());
		assertEquals(tabbedPane.getSelectedComponent(), vps.getViewComponent());
		assertTrue(provider.getCurrentView().hasSameAddresses(cb.getView()));
		assertTrue(provider.getCurrentView().hasSameAddresses(vps.getCurrentView()));
	}

	// NOTE: this test has been commented out because it fails consitently due to timing errors.
	// However, this test will almost always run successfully after the first time it is run.  So,
	// this test can be uncommented and run to test the functionality of view renaming when 
	// changes are made.
	public void dontTestRenameView() throws Exception {
		env.showTool();

		final DockingActionIf renameAction = getAction(plugin, "Rename Tree View");

		waitForTasks();
		waitForPostedSwingRunnables();

		setCurrentViewProvider(PluginConstants.DEFAULT_TREE_NAME);
		SwingUtilities.invokeAndWait(() -> renameAction.actionPerformed(new ActionContext()));

		EditWindow editWindow = findEditWindow(tool.getToolFrame());
		assertNotNull(editWindow);

		final JTextField textField = (JTextField) getInstanceField("textField", editWindow);
		SwingUtilities.invokeAndWait(() -> {
			textField.setText("My Tree");
			ActionListener[] listeners = textField.getActionListeners();
			listeners[0].actionPerformed(null);
		});

		program.flushEvents();

		ViewProviderService vps = provider.getCurrentViewProvider();
		assertEquals("My Tree", vps.getViewName());
		assertNull(program.getListing().getRootModule(PluginConstants.DEFAULT_TREE_NAME));
		assertTrue(provider.getCurrentView().hasSameAddresses(cb.getView()));
		assertTrue(provider.getCurrentView().hasSameAddresses(vps.getCurrentView()));

		undo(program);
		vps = provider.getCurrentViewProvider();
		assertEquals(PluginConstants.DEFAULT_TREE_NAME, vps.getViewName());
		assertNotNull(program.getListing().getRootModule(PluginConstants.DEFAULT_TREE_NAME));

		redo(program);
		vps = provider.getCurrentViewProvider();
		assertEquals("My Tree", vps.getViewName());
		assertNull(program.getListing().getRootModule(PluginConstants.DEFAULT_TREE_NAME));
	}

	@Test
	public void testRenameViewDuplicate() throws Exception {

		env.showTool();

		final DockingActionIf renameAction = getAction(plugin, "Rename Tree View");

		waitForTasks();
		waitForPostedSwingRunnables();

		setCurrentViewProvider(PluginConstants.DEFAULT_TREE_NAME);
		SwingUtilities.invokeAndWait(() -> renameAction.actionPerformed(new ActionContext()));
		EditWindow editWindow = findEditWindow(tool.getToolFrame());
		assertNotNull(editWindow);
		final JTextField textField = (JTextField) getInstanceField("textField", editWindow);
		SwingUtilities.invokeAndWait(() -> {
			textField.requestFocus();
			textField.setText("Main Tree");
			ActionListener[] listeners = textField.getActionListeners();
			listeners[0].actionPerformed(null);
		});
		program.flushEvents();
		ViewProviderService vps = provider.getCurrentViewProvider();
		assertEquals(PluginConstants.DEFAULT_TREE_NAME, vps.getViewName());
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

	private EditWindow findEditWindow(Window window) {
		Window[] w = window.getOwnedWindows();
		for (Window element : w) {
			if (element instanceof EditWindow) {
				return (EditWindow) element;
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
		final AtomicReference<ViewProviderService> ref = new AtomicReference<ViewProviderService>();
		runSwing(() -> {
			provider.setCurrentViewProvider(viewName);
			ref.set(provider.getCurrentViewProvider());
		});

		ViewProviderService newProvider = ref.get();
		assertEquals("Did not find the tree view provider: " + viewName, viewName,
			newProvider.getViewName());
	}

}
