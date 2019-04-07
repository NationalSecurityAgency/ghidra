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
package ghidra.app.plugin.core.symboltree;

import static org.junit.Assert.*;

import javax.swing.tree.TreePath;

import org.junit.*;

import docking.ActionContext;
import docking.action.DockingActionIf;
import docking.action.ToggleDockingAction;
import docking.widgets.tree.GTreeNode;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.marker.MarkerManagerPlugin;
import ghidra.app.plugin.core.programtree.ProgramTreePlugin;
import ghidra.app.plugin.core.symboltree.nodes.SymbolNode;
import ghidra.app.util.viewer.field.LabelFieldFactory;
import ghidra.app.util.viewer.field.OperandFieldFactory;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;

public class SymbolTreePluginX86Test extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private PluginTool tool;
	private Program program;
	private SymbolTreePlugin plugin;
	private CodeBrowserPlugin cbPlugin;
	private GTreeNode rootNode;
	private DockingActionIf renameAction;
	private DockingActionIf cutAction;
	private DockingActionIf pasteAction;
	private DockingActionIf deleteAction;
	private DockingActionIf selectionAction;
	private DockingActionIf createNamespaceAction;
	private DockingActionIf createClassAction;
	private ToggleDockingAction goToToggleAction;
	private SymbolTreeTestUtils util;
	private SymbolGTree tree;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.getTool();
		tool.addPlugin(ProgramTreePlugin.class.getName());
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		tool.addPlugin(MarkerManagerPlugin.class.getName());
		tool.addPlugin(SymbolTreePlugin.class.getName());
		plugin = env.getPlugin(SymbolTreePlugin.class);
		cbPlugin = env.getPlugin(CodeBrowserPlugin.class);

		env.showTool();

		util = new SymbolTreeTestUtils(plugin);
		program = util.getProgram();

		util.showSymbolTree();
		getActions();
		rootNode = util.getRootNode();
		tree = util.getTree();
		runSwing(() -> goToToggleAction.setSelected(true));
	}

	@After
	public void tearDown() throws Exception {
		util.closeProgram();
		env.dispose();
	}

	@Test
	public void testSelectSymbolInTree2() throws Exception {
		// process program locations and find the appropriate symbol in the tree

		assertTrue(
			cbPlugin.goToField(util.addr(0x01002d06L), OperandFieldFactory.FIELD_NAME, 0, 0));

		util.waitForTree();
		GTreeNode fNode = rootNode.getChild(2);
		util.waitForTree();

		GTreeNode gNode = fNode.getChild(1);
		util.waitForTree();

		GTreeNode pNode = gNode.getChild("param_8");
		TreePath path = pNode.getTreePath();
		assertTrue(tree.isPathSelected(path));
	}

	@Test
	public void testGoToNotSelected() throws Exception {

		goToToggleAction.setSelected(false);
		performAction(goToToggleAction, getContext(), true);

		GTreeNode node = rootNode.getChild(0);
		util.selectNode(node);

		assertTrue(
			cbPlugin.goToField(util.addr(0x01002d06L), OperandFieldFactory.FIELD_NAME, 0, 0));

		assertEquals(node.getTreePath(), tree.getSelectionPath());

	}

	@Test
	public void testDeleteParameter() throws Exception {

		assertTrue(
			cbPlugin.goToField(util.addr(0x01002d06L), OperandFieldFactory.FIELD_NAME, 0, 0));

		util.waitForTree();

		// param_14 should be selected in the symbol tree
		GTreeNode fNode = rootNode.getChild(2);

		util.waitForTree();

		GTreeNode gNode = fNode.getChild(1);
		util.waitForTree();

		GTreeNode pNode = gNode.getChild("param_8");
		TreePath path = pNode.getTreePath();
		assertTrue(tree.isPathSelected(path));
		assertTrue(deleteAction.isEnabledForContext(util.getSymbolTreeContext()));

		int count = gNode.getChildCount();

		performAction(deleteAction, getContext(), true);
		program.flushEvents();
		waitForSwing();

		util.waitForTree();

		fNode = rootNode.getChild(2);
		gNode = fNode.getChild(1);
		assertEquals(count - 1, gNode.getChildCount());

		for (int i = 0; i < count - 1; i++) {
			GTreeNode n = gNode.getChild(i);
			Symbol s = ((SymbolNode) n).getSymbol();
			assertTrue(!s.getName().equals("param_14"));
		}
	}

	@Test
	public void testDeleteGlobalVariable() throws Exception {

		assertTrue(cbPlugin.goToField(util.addr(0x01006420L), LabelFieldFactory.FIELD_NAME, 0, 0));

		util.waitForTree();

		GTreeNode lNode = rootNode.getChild(2);
		util.waitForTree();

		GTreeNode gNode = lNode.getChild(0);
		util.waitForTree();
		int count = gNode.getChildCount();
		util.waitForTree();

		assertTrue(deleteAction.isEnabledForContext(util.getSymbolTreeContext()));
		performAction(deleteAction, getContext(), true);
		program.flushEvents();
		util.waitForTree();

		gNode = lNode.getChild(0);
		util.waitForTree();

		// labels get redistributed among the group nodes
		assertEquals(count, gNode.getChildCount());

		for (int i = 0; i < count - 1; i++) {
			GTreeNode n = gNode.getChild(i);
			Symbol s = ((SymbolNode) n).getSymbol();
			assertTrue(!s.getName().equals("entry"));
		}
	}

	private void getActions() {
		renameAction = getAction(plugin, "Rename Symbol");
		assertNotNull(renameAction);
		cutAction = getAction(plugin, "Cut SymbolTree Node");
		assertNotNull(cutAction);
		pasteAction = getAction(plugin, "Paste Symbols");
		assertNotNull(pasteAction);
		deleteAction = getAction(plugin, "Delete Symbols");
		assertNotNull(deleteAction);
		selectionAction = getAction(plugin, "Make Selection");
		assertNotNull(selectionAction);
		createClassAction = getAction(plugin, "Create Class");
		assertNotNull(createClassAction);
		createNamespaceAction = getAction(plugin, "Create Namespace");
		assertNotNull(createNamespaceAction);

		goToToggleAction = (ToggleDockingAction) getAction(plugin, "Navigation");
		assertNotNull(goToToggleAction);
	}

	private ActionContext getContext() {
		return plugin.getProvider().getActionContext(null);
	}
}
