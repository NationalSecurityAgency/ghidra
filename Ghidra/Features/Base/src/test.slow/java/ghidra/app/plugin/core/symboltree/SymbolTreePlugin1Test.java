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

import java.awt.Container;
import java.awt.datatransfer.Transferable;
import java.awt.dnd.DnDConstants;
import java.lang.reflect.InvocationTargetException;
import java.util.*;

import javax.swing.*;
import javax.swing.tree.DefaultTreeCellEditor;
import javax.swing.tree.TreePath;

import org.junit.*;

import docking.ActionContext;
import docking.action.DockingActionIf;
import docking.widgets.OptionDialog;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import docking.widgets.tree.support.GTreeDragNDropHandler;
import docking.widgets.tree.support.GTreeNodeTransferable;
import generic.test.AbstractGenericTest;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.marker.MarkerManagerPlugin;
import ghidra.app.plugin.core.programtree.ProgramTreePlugin;
import ghidra.app.plugin.core.symboltree.nodes.SymbolCategoryNode;
import ghidra.app.plugin.core.symboltree.nodes.SymbolNode;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;

/**
 * Tests for the symbol tree plugin.
 */
public class SymbolTreePlugin1Test extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private PluginTool tool;
	private Program program;
	private SymbolTreePlugin plugin;
	private DockingActionIf symTreeAction;
	private CodeBrowserPlugin cbPlugin;
	private GTreeNode rootNode;
	private GTreeNode namespacesNode;
	private GTree tree;
	private Namespace globalNamespace;
	private int index;
	private DockingActionIf renameAction;
	private DockingActionIf cutAction;
	private DockingActionIf pasteAction;
	private DockingActionIf deleteAction;
	private DockingActionIf selectionAction;
	private DockingActionIf createNamespaceAction;
	private DockingActionIf createClassAction;
	private DockingActionIf goToToggleAction;
	private DockingActionIf goToExtLocAction;
	private DockingActionIf createLibraryAction;
	private DockingActionIf setExternalProgramAction;
	private DockingActionIf createExternalLocationAction;
	private DockingActionIf editExternalLocationAction;
	private SymbolTreeTestUtils util;

	@Before
	public void setUp() throws Exception {

		env = new TestEnv();
		tool = env.getTool();
		tool.addPlugin(ProgramTreePlugin.class.getName());
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		tool.addPlugin(MarkerManagerPlugin.class.getName());
		tool.addPlugin(SymbolTreePlugin.class.getName());
		plugin = env.getPlugin(SymbolTreePlugin.class);

		symTreeAction = getAction(plugin, "Symbol Tree");
		cbPlugin = env.getPlugin(CodeBrowserPlugin.class);

		util = new SymbolTreeTestUtils(plugin);
		program = util.getProgram();

		globalNamespace = program.getGlobalNamespace();
		getActions();
		env.showTool();
	}

	@After
	public void tearDown() throws Exception {
		closeProgram();
		env.dispose();
	}

	@Test
	public void testCloseCategoryIfOrgnodesGetOutOfBalance() throws Exception {
		showSymbolTree();
		GTreeNode functionsNode = rootNode.getChild("Functions");
		assertFalse(functionsNode.isLoaded());
		functionsNode.expand();
		waitForTree(tree);
		assertTrue(functionsNode.isLoaded());

		// add lots of nodes to cause functionsNode to close
		addFunctions(SymbolCategoryNode.MAX_NODES_BEFORE_CLOSING);
		waitForTree(tree);

		assertFalse(functionsNode.isLoaded());

		functionsNode.expand();
		waitForTree(tree);

		// should have 4 nodes, one for each of the original 3 functions and a org node with
		// all new "FUNCTION*" named functions
		assertEquals(4, functionsNode.getChildCount());
	}

	private void addFunctions(int count) throws Exception {
		tx(program, () -> {
			for (int i = 0; i < count; i++) {
				String name = "FUNCTION_" + i;
				Address address = util.addr(0x1002000 + i);
				AddressSet body = new AddressSet(address);
				program.getListing().createFunction(name, address, body, SourceType.USER_DEFINED);
			}
		});
	}

	@Test
	public void testShowDisplay() throws Exception {
		showSymbolTree();

		assertEquals(6, rootNode.getChildCount());
		GTreeNode node = rootNode.getChild(0);
		assertEquals("Imports", node.getName());
		node = rootNode.getChild(1);
		assertEquals("Exports", node.getName());
		node = rootNode.getChild(2);
		assertEquals("Functions", node.getName());
		node = rootNode.getChild(3);
		assertEquals("Labels", node.getName());
		node = rootNode.getChild(4);
		assertEquals("Classes", node.getName());
		node = rootNode.getChild(5);
		assertEquals("Namespaces", node.getName());
	}

	@Test
	public void testExternals() throws Exception {
		showSymbolTree();
		List<?> list =
			getChildren(globalNamespace, SymbolCategory.IMPORTS_CATEGORY.getSymbolType());

		GTreeNode extNode = rootNode.getChild(0);
		util.expandNode(extNode);
		assertEquals(list.size(), extNode.getChildCount());

		checkGTreeNodes(list, extNode);

		GTreeNode node = extNode.getChild(0);
		util.expandNode(node);
		GTreeNode fNode = node.getChild(0);
		util.selectNode(fNode);

		assertTrue(goToExtLocAction.isEnabledForContext(util.getSymbolTreeContext()));
	}

	@Test
	public void testGoToExternal() throws Exception {
		showSymbolTree();

		GTreeNode extNode = rootNode.getChild(0);
		util.expandNode(extNode);

		GTreeNode node = extNode.getChild(0);
		util.expandNode(node);
		GTreeNode fNode = node.getChild(0);
		util.selectNode(fNode);

		Symbol extSym = ((SymbolNode) fNode).getSymbol();
		assertEquals(SymbolType.LABEL, extSym.getSymbolType());
		assertTrue(extSym.isExternal());
		assertNotNull(extSym);
		assertEquals("IsTextUnicode", extSym.getName());
		ExternalLocation extLoc = (ExternalLocation) extSym.getObject();
		int transactionID = program.startTransaction("test");
		try {
			program.getExternalManager().setExternalPath(extLoc.getLibraryName(), null, true);
		}
		finally {
			program.endTransaction(transactionID, true);
		}

		flushAndWaitForTree();

		cbPlugin.updateNow();

		// reselect - setting path rebuilt tree
		extNode = rootNode.getChild(0);
		node = extNode.getChild(0);
		util.expandNode(node);
		node = extNode.getChild(0);
		fNode = node.getChild(0);
		assertEquals("IsTextUnicode", fNode.getName());
		util.selectNode(fNode);

		TreePath selectionPath = tree.getSelectionPath();
		assertNotNull(selectionPath);
		Object selectedObject = selectionPath.getLastPathComponent();
		assertEquals(fNode, selectedObject);

		waitForPostedSwingRunnables();

		performAction(goToExtLocAction, util.getSymbolTreeContext(), false);
		waitForPostedSwingRunnables();

		OptionDialog d = waitForDialogComponent(tool.getToolFrame(), OptionDialog.class, 2000);
		assertNotNull(d);
		pressButtonByText(d, "Cancel");
	}

	@Test
	public void testFunctions() throws Exception {
		showSymbolTree();
		List<?> list =
			getChildren(globalNamespace, SymbolCategory.FUNCTION_CATEGORY.getSymbolType());
		GTreeNode fNode = rootNode.getChild(2);
		util.expandNode(fNode);

		assertEquals(list.size(), fNode.getChildCount());
		checkGTreeNodes(list, fNode);
	}

	@Test
	public void testLabels() throws Exception {
		showSymbolTree();
		List<?> list = getChildren(globalNamespace, SymbolCategory.LABEL_CATEGORY.getSymbolType());
		GTreeNode labelNode = rootNode.getChild(3);
		util.expandNode(labelNode);

		for (int i = 0; i < labelNode.getChildCount(); i++) {
			GTreeNode node = labelNode.getChild(i);
			util.expandNode(node);
		}
		checkLabelNodes(list, labelNode);
	}

	@Test
	public void testGlobalSymCategoryActionEnablement() throws Exception {
		// select the root node (BTW - node is not visible) only Create Library should show up
		showSymbolTree();
		util.selectNode(rootNode);
		ActionContext context = util.getSymbolTreeContext();
		assertTrue(createLibraryAction.isEnabledForContext(context));
		assertTrue(!createClassAction.isEnabledForContext(context));
		assertTrue(!createNamespaceAction.isEnabledForContext(context));
		assertTrue(!renameAction.isEnabledForContext(context));
		assertTrue(!cutAction.isEnabledForContext(context));
		assertTrue(!pasteAction.isEnabledForContext(context));
		assertTrue(!deleteAction.isEnabledForContext(context));
		assertTrue(!selectionAction.isEnabledForContext(context));
		assertTrue(!goToExtLocAction.isEnabledForContext(context));
		assertTrue(!goToExtLocAction.isEnabledForContext(context));
	}

	@Test
	public void testPasteActionEnabled() throws Exception {
		showSymbolTree();
		// cut label from a function
		// select Global; paste should be enabled
		GTreeNode fNode = rootNode.getChild(2);
		util.expandNode(fNode);
		GTreeNode gNode = fNode.getChild(1);
		util.expandNode(gNode);
		GTreeNode node = gNode.getChild(9);
		util.selectNode(node);
		performAction(cutAction, util.getSymbolTreeContext(), true);

		util.selectNode(rootNode);
		assertTrue(pasteAction.isEnabledForContext(util.getSymbolTreeContext()));

		// move a function to a namespace
		// cut a function; select global; paste should be enabled
		GTreeNode nsParentNode = rootNode.getChild(5);
		GTreeNode nsNode = util.createObject(nsParentNode, "MyNamespace", createNamespaceAction);
		doDrag(nsNode, gNode, DnDConstants.ACTION_MOVE);

		util.waitForTree();
		flushAndWaitForTree();

		nsParentNode = rootNode.getChild(5);
		nsNode = nsParentNode.getChild(0);
		util.expandNode(nsNode);
		util.waitForTree();
		waitForPostedSwingRunnables();
		util.waitForTree();
		gNode = nsNode.getChild(0);

		if (gNode == null) {
			if (tree.isExpanded(nsNode.getTreePath())) {
				gNode = nsNode.getChild(0);
			}
		}
		assertNotNull(gNode);

		gNode = nsNode.getChild(0);
		util.selectNode(gNode);
		assertTrue(cutAction.isEnabledForContext(util.getSymbolTreeContext()));
		performAction(cutAction, util.getSymbolTreeContext(), true);

		// select the root node
		util.selectNode(rootNode);
		assertTrue(pasteAction.isEnabledForContext(util.getSymbolTreeContext()));
	}

	@Test
	public void testPasteActionEnabled2() throws Exception {
		showSymbolTree();
		// cut label from Global
		// select a function; paste should be enabled because it's address is within the function

		SymbolTable symTable = program.getSymbolTable();
		// create label within body of ghidra function
		int transactionID = program.startTransaction("test");
		symTable.createLabel(util.addr(0x01002d04), "fred", SourceType.USER_DEFINED);
		program.endTransaction(transactionID, true);

		flushAndWaitForTree();

		GTreeNode fNode = rootNode.getChild(2);
		util.expandNode(fNode);

		GTreeNode labelsNode = rootNode.getChild("Labels");
		GTreeNode namespaceNode = rootNode.getChild("Namespaces");
		util.selectNode(namespaceNode);
		performAction(createNamespaceAction, util.getSymbolTreeContext(), true);
		util.waitForTree();
		tree.stopEditing();
		GTreeNode fredNode = labelsNode.getChild("fred");
		util.selectNode(fredNode);

		waitForPostedSwingRunnables();
		assertTrue(cutAction.isEnabledForContext(util.getSymbolTreeContext()));
		performAction(cutAction, util.getSymbolTreeContext(), true);

		GTreeNode gNode = namespaceNode.getChild(0);
		util.selectNode(gNode);
		assertTrue(pasteAction.isEnabledForContext(util.getSymbolTreeContext()));

		GTreeNode dNode = fNode.getChild(0);
		util.selectNode(dNode);
		assertTrue(!pasteAction.isEnabledForContext(util.getSymbolTreeContext()));
	}

	@Test
	public void testPasteActionEnabled3() throws Exception {
		showSymbolTree();
		// move function to other namespace
		// select this function; paste should be enabled for Functions node
		GTreeNode functionsNode = rootNode.getChild(2);
		util.expandNode(functionsNode);
		String doStuffNodeName = "doStuff";
		GTreeNode doStuffNode = functionsNode.getChild(doStuffNodeName);
		util.expandNode(doStuffNode);

		GTreeNode newNamespaceNode =
			util.createObject(namespacesNode, "MyNamespace", createNamespaceAction);
		doDrag(newNamespaceNode, doStuffNode, DnDConstants.ACTION_MOVE);
		newNamespaceNode = namespacesNode.getChild("MyNamespace");

		flushAndWaitForTree();

		GTreeNode draggedDoStuffNode = newNamespaceNode.getChild(doStuffNodeName);
		util.selectNode(draggedDoStuffNode);

		// clear clipboard
		util.clearClipboard();

		assertTrue(cutAction.isEnabledForContext(util.getSymbolTreeContext()));
		performAction(cutAction, util.getSymbolTreeContext(), true);

		// make sure action executed
		assertNotNull(util.getClipboardContents());

		util.waitForTree();
		waitForPostedSwingRunnables();

		util.selectNode(functionsNode);
		util.waitForTree();
		waitForPostedSwingRunnables();

		// verify node selected
		assertEquals("Node not selected.", functionsNode, util.getSelectedNode());

		assertTrue(pasteAction.isEnabledForContext(util.getSymbolTreeContext()));
	}

	@Test
	public void testSymCategoryActionEnablement() throws Exception {
		// select the external symbol category;
		// no actions should be applicable
		showSymbolTree();
		GTreeNode extNode = rootNode.getChild(0);
		util.selectNode(extNode);
		ActionContext context = util.getSymbolTreeContext();
		boolean createLibraryIsEnabled = createLibraryAction.isEnabledForContext(context);
		if (extNode.getName().equals("Imports")) {
			assertTrue(createLibraryIsEnabled);
		}
		else {
			assertFalse(createLibraryIsEnabled);
		}
		assertTrue(!createClassAction.isEnabledForContext(context));
		assertTrue(!createNamespaceAction.isEnabledForContext(context));
		assertTrue(!renameAction.isEnabledForContext(context));
		assertTrue(!renameAction.isEnabledForContext(context));
		assertTrue(!cutAction.isEnabledForContext(context));
		assertTrue(!cutAction.isEnabledForContext(context));
		assertTrue(!pasteAction.isEnabledForContext(context));
		assertTrue(!pasteAction.isEnabledForContext(context));
		assertTrue(!deleteAction.isEnabledForContext(context));
		assertTrue(!deleteAction.isEnabledForContext(context));
		assertTrue(!selectionAction.isEnabledForContext(context));
		assertTrue(!selectionAction.isEnabledForContext(context));

		GTreeNode lNode = rootNode.getChild(1);
		util.selectNode(lNode);
		context = util.getSymbolTreeContext();
		assertTrue(!createLibraryAction.isEnabledForContext(context));
		assertTrue(!createClassAction.isEnabledForContext(context));
		assertTrue(!createNamespaceAction.isEnabledForContext(context));
		assertTrue(!renameAction.isEnabledForContext(context));
		assertTrue(!renameAction.isEnabledForContext(context));
		assertTrue(!cutAction.isEnabledForContext(context));
		assertTrue(!cutAction.isEnabledForContext(context));
		assertTrue(!pasteAction.isEnabledForContext(context));
		assertTrue(!pasteAction.isEnabledForContext(context));
		assertTrue(!deleteAction.isEnabledForContext(context));
		assertTrue(!deleteAction.isEnabledForContext(context));
		assertTrue(!selectionAction.isEnabledForContext(context));
		assertTrue(!selectionAction.isEnabledForContext(context));
	}

	@Test
	public void testParameterActionEnablement() throws Exception {
		showSymbolTree();

		GTreeNode fNode = rootNode.getChild(2);
		util.expandNode(fNode);
		GTreeNode gNode = fNode.getChild(1);
		util.expandNode(gNode);
		GTreeNode pNode = gNode.getChild(0);
		util.selectNode(pNode);
		ActionContext context = util.getSymbolTreeContext();
		assertTrue(!cutAction.isEnabledForContext(context));
		assertTrue(!pasteAction.isEnabledForContext(context));
		assertTrue(renameAction.isEnabledForContext(context));
		assertTrue(renameAction.isEnabledForContext(context));
		assertTrue(selectionAction.isEnabledForContext(context));
		assertTrue(deleteAction.isEnabledForContext(context));
	}

	@Test
	public void testFunctionActionEnablement() throws Exception {
		showSymbolTree();

		GTreeNode fNode = rootNode.getChild(2);
		util.expandNode(fNode);
		GTreeNode gNode = fNode.getChild(1);
		util.expandNode(gNode);
		util.selectNode(gNode);
		ActionContext context = util.getSymbolTreeContext();
		assertTrue(cutAction.isEnabledForContext(context));
		assertTrue(!pasteAction.isEnabledForContext(context));
		assertTrue(renameAction.isEnabledForContext(context));
		assertTrue(renameAction.isEnabledForContext(context));
		assertTrue(selectionAction.isEnabledForContext(context));
		assertTrue(deleteAction.isEnabledForContext(context));
	}

	@Test
	public void testLocalSymbolActionEnablement() throws Exception {
		showSymbolTree();

		GTreeNode fNode = rootNode.getChild(2);
		util.expandNode(fNode);
		GTreeNode gNode = fNode.getChild(1);
		util.expandNode(gNode);
		GTreeNode pNode = gNode.getChild(9);
		util.selectNode(pNode);
		ActionContext context = util.getSymbolTreeContext();
		assertTrue(cutAction.isEnabledForContext(context));
		assertTrue(!pasteAction.isEnabledForContext(context));
		assertTrue(renameAction.isEnabledForContext(context));
		assertTrue(renameAction.isEnabledForContext(context));
		assertTrue(selectionAction.isEnabledForContext(context));
		assertTrue(deleteAction.isEnabledForContext(context));
	}

	@Test
	public void testCreateNamespace() throws Exception {
		showSymbolTree();

		GTreeNode newNsNode = createNewNamespace();

		//
		// Also, check the editors contents
		//
		TreePath path = newNsNode.getTreePath();
		int row = tree.getRowForPath(path);
		DefaultTreeCellEditor cellEditor = (DefaultTreeCellEditor) tree.getCellEditor();
		JTree jTree = (JTree) AbstractGenericTest.getInstanceField("tree", tree);

		Container container = (Container) cellEditor.getTreeCellEditorComponent(jTree, newNsNode,
			true, true, true, row);
		JTextField textField = (JTextField) container.getComponent(0);
		assertEquals("NewNamespace", textField.getText());
	}

	@Test
	public void testRenameNamespace() throws Exception {
		showSymbolTree();

		GTreeNode newNsNode = createNewNamespace();
		util.selectNode(newNsNode);

		renameSelectedNode();

		TreePath path = newNsNode.getTreePath();
		GTreeNode nsNode = newNsNode;
		String newName = "MyNamespace";
		setEditorText(path, nsNode, newName);

		namespacesNode = rootNode.getChild("Namespaces");
		GTreeNode renamedNode = namespacesNode.getChild(newName);
		assertNotNull(renamedNode);

		Symbol s = ((SymbolNode) newNsNode).getSymbol();
		assertEquals(newName, s.getName());
	}

	@Test
	public void testCreateClass() throws Exception {
		showSymbolTree();

		util.selectNode(rootNode.getChild("Classes"));
		performAction(createClassAction, util.getSymbolTreeContext(), true);

		GTreeNode cnode = rootNode.getChild(4);
		util.expandNode(cnode);

		// wait until NewClass gets added		
		GTreeNode newNode = waitForValue(() -> cnode.getChild(0));

		assertNotNull(newNode);
		Symbol s = ((SymbolNode) newNode).getSymbol();
		assertEquals("NewClass", s.getName());

		TreePath path = newNode.getTreePath();
		int row = tree.getRowForPath(path);
		JTree jTree = (JTree) AbstractGenericTest.getInstanceField("tree", tree);

		JTextField tf = runSwing(() -> {
			DefaultTreeCellEditor cellEditor = (DefaultTreeCellEditor) tree.getCellEditor();
			Container container = (Container) cellEditor.getTreeCellEditorComponent(jTree, newNode,
				true, true, true, row);
			JTextField textField = (JTextField) container.getComponent(0);
			return textField;
		});

		assertEquals("NewClass", tf.getText());
	}

	@Test
	public void testCreateClassInNamespace() throws Exception {
		showSymbolTree();
		GTreeNode nsParentNode = rootNode.getChild(5);
		util.selectNode(nsParentNode);
		GTreeNode nsNode = util.createObject(nsParentNode, "MyNamespace", createNamespaceAction);
		GTreeNode cNode = util.createObject(nsNode, "MyClass", createClassAction);
		Symbol s = ((SymbolNode) cNode).getSymbol();
		assertEquals("MyClass", s.getName());
	}

	@Test
	public void testRenameExternalLib() throws Exception {
		showSymbolTree();

		GTreeNode extNode = rootNode.getChild(0);
		util.expandNode(extNode);
		GTreeNode advNode = extNode.getChild(0);
		util.rename(advNode, "MyADVAI32.dll");

		Symbol s = ((SymbolNode) advNode).getSymbol();
		assertEquals("MyADVAI32.dll", s.getName());

	}

	@Test
	public void testRenameExternalFunction() throws Exception {
		showSymbolTree();

		GTreeNode extNode = rootNode.getChild(0);
		util.expandNode(extNode);

		GTreeNode advNode = extNode.getChild(0);
		util.expandNode(advNode);

		GTreeNode regNode = advNode.getChild(1);
		util.rename(regNode, "MyRegCloseKey");

		Symbol s = ((SymbolNode) regNode).getSymbol();
		assertEquals("MyRegCloseKey", s.getName());
	}

	@Test
	public void testRenameLabel() throws Exception {
		showSymbolTree();

		GTreeNode labelNode = rootNode.getChild(3);
		util.expandNode(labelNode);

		GTreeNode isTextUnicodeNode = labelNode.getChild("ADVAPI32.dll_IsTextUnicode");

		Symbol s = ((SymbolNode) isTextUnicodeNode).getSymbol();
		String oldName = s.getName();
		String newName = "MY" + s.getName();
		util.rename(isTextUnicodeNode, newName);
		util.waitForTree();
		assertEquals(newName, s.getName());

		GTreeNode renamedNode = labelNode.getChild("MYADVAPI32.dll_IsTextUnicode");
		assertNotNull(renamedNode);

		// undo/redo
		undo(program);

		util.waitForTree();
		labelNode = rootNode.getChild(3);
		isTextUnicodeNode = labelNode.getChild("ADVAPI32.dll_IsTextUnicode");
		s = ((SymbolNode) isTextUnicodeNode).getSymbol();
		assertEquals(oldName, s.getName());

		redo(program);
		util.waitForTree();

		labelNode = rootNode.getChild(3);
		renamedNode = labelNode.getChild("MYADVAPI32.dll_IsTextUnicode");
		s = ((SymbolNode) renamedNode).getSymbol();
		assertEquals(newName, s.getName());
	}

	@Test
	public void testRenameLabelWithNamespace() throws Exception {
		//
		// The user can type a name with a namespace during a rename.  The format is:
		//   ns1::ns2::name
		//
		// This will create a new node under the Namespaces node
		//
		showSymbolTree();

		GTreeNode labelNode = rootNode.getChild(3);
		util.expandNode(labelNode);

		String advapiName = "ADVAPI32.dll_IsTextUnicode";
		GTreeNode advapi32Node = labelNode.getChild(advapiName);

		Symbol s = ((SymbolNode) advapi32Node).getSymbol();
		String newNamespace = "bob";
		String prefix = "MY";
		String newNameWithoutNamespace = prefix + s.getName();
		String newName = newNamespace + Namespace.DELIMITER + newNameWithoutNamespace;
		util.rename(advapi32Node, newName);
		util.waitForTree();
		assertEquals(newNameWithoutNamespace, s.getName());

		GTreeNode newNamespaceNode = namespacesNode.getChild(newNamespace);
		assertNotNull(newNamespaceNode);
		GTreeNode renamedNode = newNamespaceNode.getChild(newNameWithoutNamespace);
		assertNotNull(renamedNode);
		assertEquals("MYADVAPI32.dll_IsTextUnicode", renamedNode.toString());

		Symbol renamedSymbol = ((SymbolNode) renamedNode).getSymbol();
		Namespace parentNamespace = renamedSymbol.getParentNamespace();
		String currentNamespaceString = parentNamespace.getName(true);
		assertEquals(newNamespace, currentNamespaceString);
	}

	@Test
	public void testRenameNamespaceWithNamespace() throws Exception {
		showSymbolTree();

		GTreeNode newNsNode = createNewNamespace();
		util.selectNode(newNsNode);

		renameSelectedNode();

		TreePath path = newNsNode.getTreePath();
		GTreeNode nsNode = newNsNode;
		String newNamespace = "OuterNamespace";
		String newName = "MyNamespace";
		String newFullName = newNamespace + Namespace.DELIMITER + newName;
		setEditorText(path, nsNode, newFullName);

		namespacesNode = rootNode.getChild("Namespaces");
		GTreeNode newNamespaceNode = namespacesNode.getChild(newNamespace);
		assertNotNull(newNamespaceNode);
		GTreeNode renamedNode = newNamespaceNode.getChild(newName);
		assertNotNull(renamedNode);

		Symbol s = ((SymbolNode) newNsNode).getSymbol();
		assertEquals(newName, s.getName());
	}

	@Test
	public void testRenameParameter() throws Exception {

		showSymbolTree();

		GTreeNode fNode = rootNode.getChild(2);
		util.expandNode(fNode);

		GTreeNode gNode = fNode.getChild(1);
		util.expandNode(gNode);

		GTreeNode pNode = gNode.getChild(2);

		Symbol s = ((SymbolNode) pNode).getSymbol();
		String newName = "MY" + s.getName();
		util.rename(pNode, newName);
		assertEquals(newName, s.getName());
	}

	@Test
	public void testRenameLocalLabel() throws Exception {
		showSymbolTree();

		GTreeNode fNode = rootNode.getChild(2);
		util.expandNode(fNode);

		GTreeNode gNode = fNode.getChild(1);
		util.expandNode(gNode);

		GTreeNode node = gNode.getChild(5);
		Symbol s = ((SymbolNode) node).getSymbol();
		String newName = "MY" + s.getName();
		util.rename(node, newName);
		assertEquals(newName, s.getName());
	}

	@Test
	public void testProgramClosed() throws Exception {

		showSymbolTree();

		closeProgram();

		assertTrue(tool.isVisible(util.getProvider()));

	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private void doDrag(final GTreeNode destinationNode, GTreeNode dragNode, final int dragAction) {
		final GTreeDragNDropHandler dragNDropHandler = tree.getDragNDropHandler();
		List<GTreeNode> dropList = new ArrayList<>();
		dropList.add(dragNode);
		final Transferable transferable = new GTreeNodeTransferable(dragNDropHandler, dropList);

		executeOnSwingWithoutBlocking(
			() -> dragNDropHandler.drop(destinationNode, transferable, dragAction));
		waitForPostedSwingRunnables();
	}

	private GTreeNode createNewNamespace() throws Exception {
		util.selectNode(namespacesNode);
		util.waitForTree();
		performAction(createNamespaceAction, util.getSymbolTreeContext(), false);

		util.waitForTree();
		GTreeNode nsnode = rootNode.getChild("Namespaces");// get again, as its been modified

		waitForEditing();
		stopEditing();

		GTreeNode newNode = nsnode.getChild("NewNamespace");
		assertNotNull("New node not created", newNode);
		return newNode;
	}

	private void waitForEditing() throws Exception {
		int cnt = 0;
		while (!tree.isEditing()) {
			Thread.sleep(100);
			assertTrue("Timed-out waiting for tree to edit", ++cnt < 50);
		}
	}

	private void stopEditing() throws Exception {
		SwingUtilities.invokeAndWait(() -> tree.stopEditing());
	}

	private void renameSelectedNode() throws Exception {
		SwingUtilities.invokeAndWait(
			() -> renameAction.actionPerformed(util.getSymbolTreeContext()));
		waitForEditing();
	}

	private void setEditorText(final TreePath path, final GTreeNode nsNode, final String newName)
			throws InterruptedException, InvocationTargetException {
		SwingUtilities.invokeAndWait(() -> {
			int row = tree.getRowForPath(path);
			DefaultTreeCellEditor cellEditor = (DefaultTreeCellEditor) tree.getCellEditor();
			JTree jTree = (JTree) AbstractGenericTest.getInstanceField("tree", tree);
			Container container = (Container) cellEditor.getTreeCellEditorComponent(jTree, nsNode,
				true, true, true, row);
			JTextField textField = (JTextField) container.getComponent(0);

			textField.setText(newName);
			tree.stopEditing();
		});

		flushAndWaitForTree();
	}

	private void closeProgram() throws Exception {
		final ProgramManager pm = tool.getService(ProgramManager.class);
		SwingUtilities.invokeAndWait(() -> pm.closeProgram());
	}

	private void showSymbolTree() throws Exception {
		util.showSymbolTree();
		rootNode = util.getRootNode();
		namespacesNode = rootNode.getChild("Namespaces");
		tree = util.getTree();
	}

	private void getActions() throws Exception {
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
		createLibraryAction = getAction(plugin, "Create Library");
		assertNotNull(createLibraryAction);
		setExternalProgramAction = getAction(plugin, "Set External Program");
		assertNotNull(setExternalProgramAction);
		createExternalLocationAction = getAction(plugin, "Create External Location");
		assertNotNull(createExternalLocationAction);
		editExternalLocationAction = getAction(plugin, "Edit External Location");
		assertNotNull(editExternalLocationAction);

		goToToggleAction = getAction(plugin, "Navigation");
		assertNotNull(goToToggleAction);

		goToExtLocAction = getAction(plugin, "Go To External Location");
		assertNotNull(goToExtLocAction);
	}

	private List<?> getChildren(Namespace namespace, SymbolType type) {
		List<Symbol> list = new ArrayList<>();

		SymbolIterator it = program.getSymbolTable().getSymbols(namespace);
		while (it.hasNext()) {
			Symbol s = it.next();
			if (s.getSymbolType() == type) {
				if (type != SymbolType.LABEL || s.isGlobal()) {
					list.add(s);
				}
			}
		}
		Collections.sort(list, util.getSymbolComparator());
		return list;
	}

	private List<?> getChildSymbols(Symbol symbol) {
		SymbolType type = symbol.getSymbolType();
		List<Symbol> list = new ArrayList<>();
		SymbolTable symbolTable = program.getSymbolTable();
		SymbolIterator iter = symbolTable.getChildren(symbol);
		while (iter.hasNext()) {
			list.add(iter.next());
		}

		Collections.sort(list, (type == SymbolType.FUNCTION) ? util.getFunctionComparator()
				: util.getSymbolComparator());
		return list;
	}

	private void checkGTreeNodes(List<?> symbolList, GTreeNode parentNode) throws Exception {

		for (int i = 0; i < symbolList.size(); i++) {
			Symbol s = (Symbol) symbolList.get(i);
			GTreeNode node = parentNode.getChild(i);
			assertEquals(s, ((SymbolNode) node).getSymbol());
			List<Object> nodeList = new ArrayList<>();
			if (!node.isLeaf()) {
				util.expandAll(node, nodeList);
				List<?> subList = getChildSymbols(s);
				assertEquals(subList.size(), nodeList.size());

				for (int j = 0; j < subList.size(); j++) {
					s = (Symbol) subList.get(j);
					GTreeNode dNode = (GTreeNode) nodeList.get(j);
					assertEquals(s, ((SymbolNode) dNode).getSymbol());
				}
			}
		}
	}

	private void checkLabelNodes(List<?> symbolList, GTreeNode parentNode) {
		for (int i = 0; i < parentNode.getChildCount(); i++) {
			Symbol s = (Symbol) symbolList.get(index);
			GTreeNode node = parentNode.getChild(i);
			if (node instanceof SymbolNode) {
				assertEquals(s, ((SymbolNode) node).getSymbol());
				++index;
			}
			else {
				checkLabelNodes(symbolList, node);
			}
		}
	}

	private void flushAndWaitForTree() {
		program.flushEvents();
		waitForPostedSwingRunnables();
		util.waitForTree();
	}
}
