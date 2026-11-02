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
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;

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
import ghidra.app.plugin.core.symboltree.actions.NavigateOnIncomingAction;
import ghidra.app.plugin.core.symboltree.nodes.*;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.exception.UsrException;
import ghidra.util.task.TaskMonitor;

/**
 * Tests for the symbol tree plugin.
 */
public class SymbolTreePlugin1Test extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private PluginTool tool;
	private Program program;
	private SymbolTreePlugin plugin;
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
	private DockingActionIf navigateIncomingAction;
	private DockingActionIf goToExtLocAction;
	private DockingActionIf createLibraryAction;
	private DockingActionIf setExternalProgramAction;
	private DockingActionIf createExternalLocationAction;
	private DockingActionIf editExternalLocationAction;
	private SymbolTreeTestUtils util;
	private SymbolTreeProvider provider;

	@Before
	public void setUp() throws Exception {

		env = new TestEnv();
		tool = env.getTool();
		tool.addPlugin(ProgramTreePlugin.class.getName());
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		tool.addPlugin(MarkerManagerPlugin.class.getName());
		tool.addPlugin(SymbolTreePlugin.class.getName());
		plugin = env.getPlugin(SymbolTreePlugin.class);
		provider = plugin.getProvider();

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

		// The default value is 200.  Use a smaller value for testing for speed.
		runSwing(() -> plugin.setNodeGroupThreshold(20));

		showSymbolTree();

		GTreeNode globalsNode = rootNode.getChild("Globals");
		assertFalse(globalsNode.isLoaded());
		globalsNode.expand();
		waitForTree(tree);
		assertTrue(globalsNode.isLoaded());

		// add function to exceed limit to trigger organization of the nodes
		int reorganizeLimit = ((SymbolTreeRootNode) rootNode).getReorganizeLimit();
		addFunctions(reorganizeLimit);
		waitForTree(tree);

		assertFalse(globalsNode.isLoaded());

		globalsNode.expand();
		waitForTree(tree);

		assertEquals(8, globalsNode.getChildCount());
		assertEquals("ADVAPI32.dll_", globalsNode.getChild(0).getName());
		assertEquals("doStuff", globalsNode.getChild(1).getName());
		assertEquals("entry", globalsNode.getChild(2).getName());
		assertEquals("FUNCTION_", globalsNode.getChild(3).getName());
		assertEquals("ghidra", globalsNode.getChild(4).getName());
		assertEquals("IsTextUnicode", globalsNode.getChild(5).getName());
		assertEquals("Reg", globalsNode.getChild(6).getName());
		assertEquals("sscanf", globalsNode.getChild(7).getName());
	}

	@Test
	public void testShowDisplay() throws Exception {
		showSymbolTree();

		assertEquals(4, rootNode.getChildCount());
		GTreeNode node = rootNode.getChild(0);
		assertEquals("Imports", node.getName());
		node = rootNode.getChild(1);
		assertEquals("Exports", node.getName());
		node = rootNode.getChild(2);
		assertEquals("Globals", node.getName());
		node = rootNode.getChild(3);
		assertEquals("Namespaces", node.getName());
	}

	@Test
	public void testExternals() throws Exception {
		showSymbolTree();
		List<?> list = getChildren(globalNamespace, SymbolType.LIBRARY);

		GTreeNode importsNode = rootNode.getChild("Imports");
		util.expandNode(importsNode);
		assertEquals(list.size(), importsNode.getChildCount());

		checkLabelNodes(list, importsNode);

		GTreeNode libraryNode = importsNode.getChild(0);
		util.expandNode(libraryNode);
		GTreeNode fNode = libraryNode.getChild(0);
		util.selectNode(fNode);

		assertTrue(goToExtLocAction.isEnabledForContext(util.getSymbolTreeContext()));
	}

	@Test
	public void testExternalInNamespace() throws Exception {
		showSymbolTree();

		createExternalFooInNamespaceBob();

		GTreeNode importsNode = rootNode.getChild("Imports");
		util.expandNode(importsNode);
		GTreeNode user32 = importsNode.getChild("USER32.dll");
		util.expandNode(user32);
		assertEquals(1, user32.getChildCount());
		GTreeNode bobNs = user32.getChild(0);
		assertEquals("bob", bobNs.getName());
		util.expandNode(bobNs);
		assertEquals("foo", bobNs.getChild(0).getName());

		createExternalBar();
		setBarNamespace("bob");

		user32 = importsNode.getChild("USER32.dll");
		assertEquals(1, user32.getChildCount());
		bobNs = user32.getChild(0);
		assertEquals("bob", bobNs.getName());
		assertEquals(2, bobNs.getChildCount());
		assertEquals("bar", bobNs.getChild(0).getName());
		assertEquals("foo", bobNs.getChild(1).getName());

		setBarNamespace(null);
		assertEquals(2, user32.getChildCount());
		assertEquals("bar", user32.getChild(0).getName());
		assertEquals("bob", user32.getChild(1).getName());
	}

	@Test
	public void testDeleteExternalSymbolInNamespace() throws Exception {
		showSymbolTree();

		Symbol fooSym = createExternalFooInNamespaceBob();
		createExternalBar();

		GTreeNode importsNode = rootNode.getChild("Imports");
		util.expandNode(importsNode);
		GTreeNode user32 = importsNode.getChild("USER32.dll");
		util.expandNode(user32);
		assertEquals(2, user32.getChildCount());
		assertEquals("bar", user32.getChild(0).getName());
		assertEquals("bob", user32.getChild(1).getName());

		deleteSymbol(fooSym);

		user32 = importsNode.getChild("USER32.dll");
		assertEquals(1, user32.getChildCount());
		assertEquals("bar", user32.getChild(0).getName());
	}

	@Test
	public void testExternalParameter() throws Exception {
		showSymbolTree();

		createExternalFunctionFoo();

		GTreeNode importsNode = rootNode.getChild("Imports");
		util.expandNode(importsNode);
		GTreeNode user32 = importsNode.getChild("USER32.dll");
		util.expandNode(user32);
		assertEquals(1, user32.getChildCount());
		assertEquals("foo", user32.getChild(0).getName());
		GTreeNode foo = user32.getChild(0);
		util.expandNode(foo);

		addParameterToFunctionFoo();

		foo = user32.getChild(0);
		assertEquals(1, foo.getChildCount());
		assertEquals("param1", foo.getChild(0).getName());

		removeParametersForFunctionFoo();
	}

	@Test
	public void testAddExternalFunction() throws Exception {
		showSymbolTree();
		List<?> list = getChildren(globalNamespace, SymbolType.LIBRARY);

		GTreeNode importsNode = rootNode.getChild("Imports");
		util.expandNode(importsNode);
		assertEquals(list.size(), importsNode.getChildCount());
		checkLabelNodes(list, importsNode);

		GTreeNode advapi32 = importsNode.getChild("ADVAPI32.dll");
		util.expandNode(advapi32);
		assertEquals(7, advapi32.getChildCount());
		GTreeNode node = advapi32.getChild("IsTextUnicode");
		assertNotNull(node);

		createExternaFunction();
		assertEquals(8, advapi32.getChildCount());

		node = advapi32.getChild(0);
		assertEquals("doFoo", node.getName());
		util.expandNode(node);
		assertEquals(1, node.getChildCount());
		assertEquals("p1", node.getChild(0).getName());

		addAnotherParameter(node);
		node = advapi32.getChild(0);	// have to re-aquiire node since it got removed/added 
		assertEquals(2, node.getChildCount());
		assertEquals("p1", node.getChild(0).getName());
		assertEquals("p2", node.getChild(1).getName());

	}

	@Test
	public void testAddExternalLabelInNamespace() throws Exception {
		showSymbolTree();
		GTreeNode importsNode = rootNode.getChild(SymbolCategory.IMPORTS.getName());
		util.expandNode(importsNode);
		GTreeNode advapiNode = importsNode.getChild("ADVAPI32.dll");
		util.expandNode(advapiNode);
		assertNull(advapiNode.getChild("fooNs"));
		createExternaLabelInNamespace("bob", "fooNs");
		GTreeNode fooNs = advapiNode.getChild("fooNs");
		assertNotNull(fooNs);
		assertFalse(fooNs.isLoaded());
		util.expandNode(fooNs);
		assertNotNull(fooNs.getChild("bob"));
	}

	@Test
	public void testAddExternalLabelInNamespaceDeeper() throws Exception {
		showSymbolTree();
		GTreeNode importsNode = rootNode.getChild(SymbolCategory.IMPORTS.getName());
		util.expandNode(importsNode);
		GTreeNode advapiNode = importsNode.getChild("ADVAPI32.dll");
		util.expandNode(advapiNode);
		assertNull(advapiNode.getChild("fooNs"));
		createExternaLabelInNamespace("bob", "fooNs", "barNs");
		GTreeNode fooNs = advapiNode.getChild("fooNs");
		assertNotNull(fooNs);
		assertFalse(fooNs.isLoaded());
		util.expandNode(fooNs);
		GTreeNode barNs = fooNs.getChild("barNs");
		assertNotNull(barNs);
		util.expandNode(barNs);
		assertNotNull(barNs.getChild("bob"));
	}

	@Test
	public void testAddExternalLabelInNamespaceAlreadyOpen() throws Exception {
		showSymbolTree();
		GTreeNode importsNode = rootNode.getChild(SymbolCategory.IMPORTS.getName());
		util.expandNode(importsNode);
		GTreeNode advapiNode = importsNode.getChild("ADVAPI32.dll");
		util.expandNode(advapiNode);
		assertNull(advapiNode.getChild("fooNs"));
		createExternaLabelInNamespace("bob", "fooNs");

		GTreeNode fooNs = advapiNode.getChild("fooNs");
		assertNotNull(fooNs);
		assertFalse(fooNs.isLoaded());
		util.expandNode(fooNs);
		assertNotNull(fooNs.getChild("bob"));
		createExternaLabelInNamespace("joe", "fooNs");

		assertNotNull(fooNs.getChild("joe"));
	}

	@Test
	public void testRemoveExternalLabelInNamespaceRemovesEmptyNamespace() throws Exception {
		showSymbolTree();
		GTreeNode importsNode = rootNode.getChild("Imports");
		util.expandNode(importsNode);
		GTreeNode advapiNode = importsNode.getChild("ADVAPI32.dll");
		util.expandNode(advapiNode);
		assertNull(advapiNode.getChild("fooNs"));

		createExternaLabelInNamespace("bob", "fooNs");
		createExternaLabelInNamespace("joe", "fooNs");

		GTreeNode fooNs = advapiNode.getChild("fooNs");
		util.expandNode(fooNs);
		assertNotNull(fooNs.getChild("bob"));
		assertNotNull(fooNs.getChild("joe"));

		removeSymbol("bob", "fooNs");

		assertNull(fooNs.getChild("bob"));
		assertNotNull(fooNs.getChild("joe"));

		removeSymbol("joe", "fooNs");

		assertNull(fooNs.getParent()); // fooNs should be disposed
		assertNull(advapiNode.getChild("fooNs"));
	}

	@Test
	public void testRemoveExternalLabelInNamespaceRemovesEmptyNamespaceDownOneLevel()
			throws Exception {
		showSymbolTree();
		GTreeNode importsNode = rootNode.getChild(SymbolCategory.IMPORTS.getName());
		util.expandNode(importsNode);
		GTreeNode advapiNode = importsNode.getChild("ADVAPI32.dll");
		util.expandNode(advapiNode);
		assertNull(advapiNode.getChild("fooNs"));
		createExternaLabelInNamespace("bob", "fooNs", "barNs");
		createExternaLabelInNamespace("joe", "fooNs", "barNs");
		GTreeNode fooNs = advapiNode.getChild("fooNs");
		util.expandNode(fooNs);
		GTreeNode barNs = fooNs.getChild("barNs");
		assertNotNull(barNs.getChild("bob"));
		assertNotNull(barNs.getChild("joe"));

		removeSymbol("bob", "fooNs", "barNs");

		assertNull(barNs.getChild("bob"));
		assertNotNull(barNs.getChild("joe"));

		removeSymbol("joe", "fooNs", "barNs");

		assertNull(barNs.getParent()); // barNs should be disposed
		assertNull(fooNs.getParent()); // fooNs should be disposed
		assertNull(advapiNode.getChild("fooNs"));
	}

	private void removeSymbol(String symbolName, String... namespaceNames) throws Exception {
		program.withTransaction("test", () -> {
			SymbolTable symbolMgr = program.getSymbolTable();
			Namespace namespace = getNamespace(namespaceNames);
			List<Symbol> symbols = symbolMgr.getSymbols(symbolName, namespace);
			Symbol s = symbols.get(0);
			s.delete();
		});
		waitForTree(tree);

	}

	private void createExternaLabelInNamespace(String labelName, String... namespaceNames)
			throws Exception {
		program.withTransaction("test", () -> {
			ExternalManager extMgr = program.getExternalManager();
			SymbolTable symbolMgr = program.getSymbolTable();
			Library advapi32 = (Library) symbolMgr.getLibrarySymbol("ADVAPI32.dll").getObject();
			Namespace namespace = getNamespace(namespaceNames);
			extMgr.addExtLocation(advapi32, namespace, labelName, null, SourceType.USER_DEFINED);
		});
		waitForSwing();
		waitForTree(tree);
	}

	private Namespace getNamespace(String[] namespaceNames) throws Exception {
		SymbolTable symbolMgr = program.getSymbolTable();
		Namespace namespace = program.getGlobalNamespace();
		for (String namespaceName : namespaceNames) {
			Namespace ns = symbolMgr.getNamespace(namespaceName, namespace);
			if (ns == null) {
				ns = symbolMgr.createNameSpace(namespace, namespaceName, SourceType.USER_DEFINED);
			}
			namespace = ns;
		}
		return namespace;
	}

	@Test
	public void testGoToExternal() throws Exception {
		showSymbolTree();

		GTreeNode importsNode = rootNode.getChild("Imports");
		util.expandNode(importsNode);

		GTreeNode libraryNode = importsNode.getChild("ADVAPI32.dll");
		util.expandNode(libraryNode);
		GTreeNode node = libraryNode.getChild("IsTextUnicode");
		util.selectNode(node);

		Symbol extSym = ((SymbolNode) node).getSymbol();
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
		importsNode = rootNode.getChild("Imports");
		libraryNode = importsNode.getChild("ADVAPI32.dll");
		util.expandNode(libraryNode);
		node = libraryNode.getChild("IsTextUnicode");
		assertEquals("IsTextUnicode", node.getName());
		util.selectNode(node);

		TreePath selectionPath = tree.getSelectionPath();
		assertNotNull(selectionPath);
		Object selectedObject = selectionPath.getLastPathComponent();
		assertEquals(node, selectedObject);

		waitForSwing();

		performAction(goToExtLocAction, util.getSymbolTreeContext(), false);
		waitForSwing();

		OptionDialog d = waitForDialogComponent(OptionDialog.class);
		assertNotNull(d);
		pressButtonByText(d, "Cancel");
	}

	@Test
	public void testGlobals() throws Exception {
		showSymbolTree();
		List<Symbol> list = getChildren(globalNamespace, SymbolType.FUNCTION);
		list.addAll(getChildren(globalNamespace, SymbolType.LABEL));
		Collections.sort(list, util.getSymbolComparator());
		GTreeNode globalsNode = rootNode.getChild("Globals");
		util.expandNode(globalsNode);

		assertEquals(list.size(), globalsNode.getChildCount());
		checkGTreeNodes(list, globalsNode);
	}

	@Test
	public void testGlobalSymCategoryActionEnablement() throws Exception {
		// select the root node (BTW - node is not visible) only Create Library should show up
		showSymbolTree();
		util.selectNode(rootNode);
		ActionContext context = util.getSymbolTreeContext();
		assertTrue(createLibraryAction.isEnabledForContext(context));
		assertFalse(createClassAction.isEnabledForContext(context));
		assertFalse(createNamespaceAction.isEnabledForContext(context));
		assertFalse(renameAction.isEnabledForContext(context));
		assertFalse(cutAction.isEnabledForContext(context));
		assertFalse(pasteAction.isEnabledForContext(context));
		assertFalse(deleteAction.isEnabledForContext(context));
		assertFalse(selectionAction.isEnabledForContext(context));
		assertFalse(goToExtLocAction.isEnabledForContext(context));
		assertFalse(goToExtLocAction.isEnabledForContext(context));
	}

	@Test
	public void testPasteActionEnabled() throws Exception {
		showSymbolTree();
		// cut label from a function
		// select Global; paste should be enabled
		GTreeNode globalsNode = rootNode.getChild("Globals");
		util.expandNode(globalsNode);
		GTreeNode ghidraNode = globalsNode.getChild("ghidra");
		util.expandNode(ghidraNode);
		GTreeNode node = ghidraNode.getChild("AnotherLocal");
		util.selectNode(node);
		performAction(cutAction, util.getSymbolTreeContext(), true);

		// move a function to a namespace
		// cut a function; select global; paste should be enabled

		GTreeNode nsNode = util.createObject(namespacesNode, "MyNamespace", createNamespaceAction);
		doDrag(nsNode, ghidraNode, DnDConstants.ACTION_MOVE);

		util.waitForTree();
		flushAndWaitForTree();

		namespacesNode = rootNode.getChild("Namespaces");
		nsNode = namespacesNode.getChild(0);
		util.expandNode(nsNode);
		util.waitForTree();
		waitForSwing();
		util.waitForTree();
		ghidraNode = nsNode.getChild(0);

		if (ghidraNode == null) {
			if (tree.isExpanded(nsNode.getTreePath())) {
				ghidraNode = nsNode.getChild(0);
			}
		}
		assertNotNull(ghidraNode);

		ghidraNode = nsNode.getChild(0);
		util.selectNode(ghidraNode);
		assertTrue(cutAction.isEnabledForContext(util.getSymbolTreeContext()));
		performAction(cutAction, util.getSymbolTreeContext(), true);
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

		GTreeNode globalsNode = rootNode.getChild("Globals");
		GTreeNode namespaceNode = rootNode.getChild("Namespaces");
		util.selectNode(namespaceNode);
		performAction(createNamespaceAction, util.getSymbolTreeContext(), true);
		util.waitForTree();
		runSwing(() -> tree.stopEditing());
		GTreeNode fredNode = globalsNode.getChild("fred");
		util.selectNode(fredNode);

		waitForSwing();
		assertTrue(cutAction.isEnabledForContext(util.getSymbolTreeContext()));
		performAction(cutAction, util.getSymbolTreeContext(), true);

		// NewNamespace node
		GTreeNode gNode = namespaceNode.getChild(0);
		util.selectNode(gNode);
		assertTrue(pasteAction.isEnabledForContext(util.getSymbolTreeContext()));

		// doStuff function node
		waitForSwing();
		GTreeNode dNode = globalsNode.getChild(0);
		util.selectNode(dNode);
		assertFalse(pasteAction.isEnabledForContext(util.getSymbolTreeContext()));
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
		waitForSwing();

		util.selectNode(functionsNode);
		util.waitForTree();
		waitForSwing();

		// verify node selected
		assertEquals("Node not selected.", functionsNode, util.getSelectedNode());

		assertTrue(pasteAction.isEnabledForContext(util.getSymbolTreeContext()));
	}

	@Test
	public void testSymCategoryActionEnablement() throws Exception {
		// select the external symbol category;
		// no actions should be applicable
		showSymbolTree();
		GTreeNode importsNode = rootNode.getChild("Imports");
		util.selectNode(importsNode);
		ActionContext context = util.getSymbolTreeContext();
		boolean createLibraryIsEnabled = createLibraryAction.isEnabledForContext(context);
		if (importsNode.getName().equals("Imports")) {
			assertTrue(createLibraryIsEnabled);
		}
		else {
			assertFalse(createLibraryIsEnabled);
		}
		assertFalse(createClassAction.isEnabledForContext(context));
		assertFalse(createNamespaceAction.isEnabledForContext(context));
		assertFalse(renameAction.isEnabledForContext(context));
		assertFalse(cutAction.isEnabledForContext(context));
		assertFalse(pasteAction.isEnabledForContext(context));
		assertFalse(deleteAction.isEnabledForContext(context));
		assertFalse(selectionAction.isEnabledForContext(context));

		GTreeNode lNode = rootNode.getChild(1);
		util.selectNode(lNode);
		context = util.getSymbolTreeContext();
		assertFalse(createLibraryAction.isEnabledForContext(context));
		assertFalse(createClassAction.isEnabledForContext(context));
		assertFalse(createNamespaceAction.isEnabledForContext(context));
		assertFalse(renameAction.isEnabledForContext(context));
		assertFalse(cutAction.isEnabledForContext(context));
		assertFalse(pasteAction.isEnabledForContext(context));
		assertFalse(deleteAction.isEnabledForContext(context));
		assertFalse(selectionAction.isEnabledForContext(context));
	}

	@Test
	public void testParameterActionEnablement() throws Exception {
		showSymbolTree();

		GTreeNode globalsNode = rootNode.getChild("Globals");
		util.expandNode(globalsNode);
		GTreeNode gNode = globalsNode.getChild("ghidra");
		util.expandNode(gNode);
		GTreeNode pNode = gNode.getChild(0);
		util.selectNode(pNode);
		ActionContext context = util.getSymbolTreeContext();
		assertFalse(cutAction.isEnabledForContext(context));
		assertFalse(pasteAction.isEnabledForContext(context));
		assertTrue(renameAction.isEnabledForContext(context));
		assertTrue(renameAction.isEnabledForContext(context));
		assertTrue(selectionAction.isEnabledForContext(context));
		assertTrue(deleteAction.isEnabledForContext(context));
	}

	@Test
	public void testFunctionActionEnablement() throws Exception {
		showSymbolTree();

		GTreeNode globalsNode = rootNode.getChild("Globals");
		util.expandNode(globalsNode);
		GTreeNode gNode = globalsNode.getChild("ghidra");
		util.expandNode(gNode);
		util.selectNode(gNode);
		ActionContext context = util.getSymbolTreeContext();
		assertTrue(cutAction.isEnabledForContext(context));
		assertFalse(pasteAction.isEnabledForContext(context));
		assertTrue(renameAction.isEnabledForContext(context));
		assertTrue(renameAction.isEnabledForContext(context));
		assertTrue(selectionAction.isEnabledForContext(context));
		assertTrue(deleteAction.isEnabledForContext(context));
	}

	@Test
	public void testLocalSymbolActionEnablement() throws Exception {
		showSymbolTree();

		GTreeNode globalsNode = rootNode.getChild("Globals");
		util.expandNode(globalsNode);
		GTreeNode gNode = globalsNode.getChild("ghidra");
		util.expandNode(gNode);
		GTreeNode pNode = gNode.getChild(9);
		util.selectNode(pNode);
		ActionContext context = util.getSymbolTreeContext();
		assertTrue(cutAction.isEnabledForContext(context));
		assertFalse(pasteAction.isEnabledForContext(context));
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

		Container container = (Container) runSwing(
			() -> cellEditor.getTreeCellEditorComponent(jTree, newNsNode, true, true, true, row));
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

		namespacesNode = rootNode.getChild("Namespaces");
		util.selectNode(namespacesNode);
		performAction(createClassAction, util.getSymbolTreeContext(), true);

		util.expandNode(namespacesNode);

		// wait until NewClass gets added
		GTreeNode newNode = waitForValue(() -> namespacesNode.getChild(0));

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
		GTreeNode nsParentNode = rootNode.getChild("Namespaces");
		util.selectNode(nsParentNode);
		GTreeNode nsNode = util.createObject(nsParentNode, "MyNamespace", createNamespaceAction);
		GTreeNode cNode = util.createObject(nsNode, "MyClass", createClassAction);
		Symbol s = ((SymbolNode) cNode).getSymbol();
		assertEquals("MyClass", s.getName());
	}

	@Test
	public void testRenameExternalLib() throws Exception {
		showSymbolTree();

		GTreeNode importsNode = rootNode.getChild("Imports");
		util.expandNode(importsNode);
		GTreeNode advNode = importsNode.getChild(0);
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

		GTreeNode labelNode = rootNode.getChild("Globals");
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
		labelNode = rootNode.getChild("Globals");
		isTextUnicodeNode = labelNode.getChild("ADVAPI32.dll_IsTextUnicode");
		s = ((SymbolNode) isTextUnicodeNode).getSymbol();
		assertEquals(oldName, s.getName());

		redo(program);
		util.waitForTree();

		labelNode = rootNode.getChild("Globals");
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

		GTreeNode globalsNode = rootNode.getChild("Globals");
		util.expandNode(globalsNode);

		String advapiName = "ADVAPI32.dll_IsTextUnicode";
		GTreeNode advapi32Node = globalsNode.getChild(advapiName);

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

		GTreeNode globalsNode = rootNode.getChild("Globals");
		util.expandNode(globalsNode);

		GTreeNode gNode = globalsNode.getChild("ghidra");
		util.expandNode(gNode);

		GTreeNode pNode = gNode.getChild("param_2");

		Symbol s = ((SymbolNode) pNode).getSymbol();
		String newName = "MY" + s.getName();
		util.rename(pNode, newName);
		assertEquals(newName, s.getName());
	}

	@Test
	public void testRenameLocalLabel() throws Exception {
		showSymbolTree();

		GTreeNode globalsNode = rootNode.getChild("Globals");
		util.expandNode(globalsNode);

		GTreeNode gNode = globalsNode.getChild("ghidra");
		util.expandNode(gNode);

		GTreeNode node = gNode.getChild("AnotherLocal");
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

	@Test
	public void testAddNode_FunctionInAClass() throws Exception {

		//
		// This tests a particular edge case where adding a function inside of a class would cause
		// the tree to throw an exception due to an improper child node lookup.  This test was
		// triggering the exception before the fix.
		//
		showSymbolTree();
		namespacesNode = rootNode.getChild("Namespaces");
		assertFalse(namespacesNode.isLoaded());
		namespacesNode.expand();
		waitForTree(tree);
		assertTrue(namespacesNode.isLoaded());
		addFunctionInClass(100);
		waitForTree(tree);

		GTreeNode parentClassNode = namespacesNode.getChild("PARENT_CLASS");
		parentClassNode.expand();
		waitForTree(tree);

		// Grab a node with a large index that will not be in the parent node
		FunctionSymbolNode fNode = (FunctionSymbolNode) parentClassNode.getChild("FUNCTION_99");
		SymbolTreeRootNode symbolRootNode = (SymbolTreeRootNode) rootNode;
		Symbol symbol = fNode.getSymbol();

		// symbolAdded() was throwing an exception before the fix
		symbolRootNode.symbolAdded(symbol, TaskMonitor.DUMMY);
	}

//==================================================================================================
// Private Methods
//==================================================================================================
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

	private void addFunctionInClass(int count) throws Exception {
		tx(program, () -> {

			GhidraClass parentClass =
				program.getSymbolTable().createClass(null, "PARENT_CLASS", SourceType.USER_DEFINED);

			for (int i = 0; i < count; i++) {
				String name = "FUNCTION_" + i;
				Address address = util.addr(0x1002000 + i);
				AddressSet body = new AddressSet(address);
				program.getListing()
						.createFunction(name, parentClass, address, body, SourceType.USER_DEFINED);
			}
		});
	}

	private void doDrag(final GTreeNode destinationNode, GTreeNode dragNode, final int dragAction) {
		final GTreeDragNDropHandler dragNDropHandler = tree.getDragNDropHandler();
		List<GTreeNode> dropList = new ArrayList<>();
		dropList.add(dragNode);
		final Transferable transferable = new GTreeNodeTransferable(dragNDropHandler, dropList);

		executeOnSwingWithoutBlocking(
			() -> dragNDropHandler.drop(destinationNode, transferable, dragAction));
		waitForSwing();
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
		runSwing(() -> tree.stopEditing());
	}

	private void renameSelectedNode() throws Exception {
		SwingUtilities
				.invokeAndWait(() -> renameAction.actionPerformed(util.getSymbolTreeContext()));
		waitForEditing();
	}

	private void setEditorText(final TreePath path, final GTreeNode nsNode, final String newName) {
		runSwing(() -> {
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
		runSwing(() -> pm.closeProgram());
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

		navigateIncomingAction = getAction(plugin, NavigateOnIncomingAction.NAME);
		assertNotNull(navigateIncomingAction);

		goToExtLocAction = getAction(plugin, "Go To External Location");
		assertNotNull(goToExtLocAction);
	}

	private List<Symbol> getChildren(Namespace namespace, SymbolType type) {
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
		waitForSwing();
		util.waitForTree();
	}

	@SuppressWarnings("deprecation")
	private void removeParametersForFunctionFoo() {
		ExternalManager extMgr = program.getExternalManager();
		ExternalLocation extLoc = extMgr.getUniqueExternalLocation("USER32.dll", "foo");
		Function function = extLoc.getFunction();

		tx(program, () -> {
			function.removeParameter(0);
		});
		waitForTree(tree);
	}

	private void deleteSymbol(Symbol s) {
		tx(program, () -> {
			s.delete();
		});
		waitForTree(tree);
	}

	@SuppressWarnings("deprecation")
	private void addParameterToFunctionFoo() {
		ExternalManager extMgr = program.getExternalManager();
		ExternalLocation extLoc = extMgr.getUniqueExternalLocation("USER32.dll", "foo");
		Function function = extLoc.getFunction();

		tx(program, () -> {
			ParameterImpl p = new ParameterImpl("param1", new WordDataType(), program);
			function.addParameter(p, SourceType.USER_DEFINED);
		});
		waitForTree(tree);
	}

	private void setBarNamespace(String namespaceName) {
		tx(program, () -> {
			SymbolTable symbolTable = program.getSymbolTable();
			Namespace ns = namespaceName == null ? program.getGlobalNamespace()
					: symbolTable.getNamespace(namespaceName, null);
			symbolTable.getSymbols("bar").next().setNamespace(ns);
		});
		waitForTree(tree);
	}

	private void createExternalBar() throws UsrException {
		ExternalManager extMgr = program.getExternalManager();
		Library library = extMgr.getExternalLibrary("USER32.dll");
		program.withTransaction("test", () -> {
			extMgr.addExtLocation(library, "bar", null, SourceType.USER_DEFINED);
		});
		waitForTree(tree);
	}

	private Symbol createExternalFooInNamespaceBob() throws UsrException {
		ExternalManager extMgr = program.getExternalManager();
		Library library = extMgr.getExternalLibrary("USER32.dll");
		AtomicReference<Symbol> fooSym = new AtomicReference<Symbol>();
		program.withTransaction("test", () -> {
			Namespace bob =
				program.getSymbolTable().createNameSpace(null, "bob", SourceType.USER_DEFINED);
			ExternalLocation extLoc =
				extMgr.addExtLocation(library, "foo", null, SourceType.USER_DEFINED);
			Symbol s = extLoc.getSymbol();
			s.setNamespace(bob);
			fooSym.set(s);
		});
		waitForTree(tree);
		return fooSym.get();
	}

	private void createExternalFunctionFoo() throws UsrException {
		ExternalManager extMgr = program.getExternalManager();
		Library library = extMgr.getExternalLibrary("USER32.dll");
		program.withTransaction("test", () -> {
			extMgr.addExtFunction(library, "foo", null, SourceType.USER_DEFINED);
		});
		waitForTree(tree);
	}

	private void addAnotherParameter(GTreeNode node) throws UsrException {
		Symbol symbol = ((SymbolNode) node).getSymbol();
		Function function = (Function) symbol.getObject();
		program.withTransaction("test", () -> {
			Parameter param = new ParameterImpl("p2", new DWordDataType(), 4, program);
			function.addParameter(param, SourceType.USER_DEFINED);
		});
		waitForSwing();
	}

	private void createExternaFunction() throws UsrException {
		program.withTransaction("test", () -> {
			ExternalManager extMgr = program.getExternalManager();
			ExternalLocation extLoc =
				extMgr.addExtFunction("ADVAPI32.dll", "doFoo", null, SourceType.USER_DEFINED);
			Function function = extLoc.getFunction();
			Parameter parameter1 = new ParameterImpl("p1", new DWordDataType(), 4, program);
			function.addParameter(parameter1, SourceType.USER_DEFINED);
		});
		waitForSwing();
	}

}
