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

import java.awt.Rectangle;
import java.util.List;
import java.util.stream.Collectors;

import javax.swing.JTree;
import javax.swing.SwingUtilities;
import javax.swing.tree.TreePath;

import org.junit.*;

import docking.ActionContext;
import docking.action.DockingActionIf;
import docking.action.ToggleDockingAction;
import docking.widgets.tree.GTreeNode;
import generic.test.AbstractGenericTest;
import ghidra.app.cmd.label.CreateNamespacesCmd;
import ghidra.app.cmd.label.RenameLabelCmd;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.marker.MarkerManagerPlugin;
import ghidra.app.plugin.core.programtree.ProgramTreePlugin;
import ghidra.app.plugin.core.symboltree.actions.NavigateOnIncomingAction;
import ghidra.app.plugin.core.symboltree.nodes.*;
import ghidra.app.util.viewer.field.*;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.task.TaskMonitor;

/**
 * Tests for the symbol tree plugin.
 */
public class SymbolTreePlugin2Test extends AbstractGhidraHeadedIntegrationTest {

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
	private DockingActionIf convertToClassAction;
	private ToggleDockingAction navigateIncomingAction;
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
		SwingUtilities.invokeAndWait(() -> navigateIncomingAction.setSelected(true));
	}

	@After
	public void tearDown() throws Exception {
		util.closeProgram();
		env.dispose();
	}

	@Test
	public void testNavigateToSymbol() throws Exception {

		// select a node; code browser should go there

		assertTrue(navigateIncomingAction.isSelected());

		GTreeNode globalsNode = getGlobalsNode();
		util.expandNode(globalsNode);

		GTreeNode gNode = globalsNode.getChild("ghidra");
		util.expandNode(gNode);

		GTreeNode node = gNode.getChild(5);
		Symbol s = ((SymbolNode) node).getSymbol();

		clickOnNode(node);
		ListingTextField f = (ListingTextField) cbPlugin.getCurrentField();
		assertEquals(s.getName(), f.getText());
	}

	@Test
	public void testNavigateToFunction() throws Exception {
		// select a node; code browser should go there
		GTreeNode globalsNode = getGlobalsNode();
		util.expandNode(globalsNode);

		GTreeNode gNode = globalsNode.getChild("ghidra");
		util.expandNode(gNode);
		Symbol s = ((SymbolNode) gNode).getSymbol();
		Function f = (Function) s.getObject();

		clickOnNode(gNode);
		ListingTextField tf = (ListingTextField) cbPlugin.getCurrentField();
		assertTrue(tf.getFieldFactory() instanceof FunctionSignatureFieldFactory);
		assertEquals(f.getEntryPoint(), cbPlugin.getCurrentAddress());
	}

	@Test
	public void testNavigateToParameter() throws Exception {

		GTreeNode globalsNode = getGlobalsNode();
		util.expandNode(globalsNode);

		GTreeNode gNode = globalsNode.getChild("ghidra");
		util.expandNode(gNode);

		GTreeNode pNode = gNode.getChild("param_1");
		clickOnNode(pNode);

		Symbol s = ((SymbolNode) pNode).getSymbol();
		assertEquals(s.getProgramLocation(), cbPlugin.getCurrentLocation());
		ListingTextField tf = (ListingTextField) cbPlugin.getCurrentField();
		assertEquals(s.getName(), tf.getText());
	}

	@Test
	public void testGoToExternalReference() throws Exception {

		GTreeNode extNode = rootNode.getChild(0);
		util.expandNode(extNode);

		GTreeNode node = extNode.getChild(0);
		util.expandNode(node);
		GTreeNode globalsNode = node.getChild(0);

		Symbol extSym = ((SymbolNode) globalsNode).getSymbol();
		assertNotNull(extSym);
		Address addr = null;
		ExternalLocation extLoc = (ExternalLocation) extSym.getObject();
		String libName = extLoc.getLibraryName();
		ReferenceIterator iter = program.getReferenceManager().getExternalReferences();
		while (iter.hasNext()) {
			ExternalReference ref = (ExternalReference) iter.next();
			if (libName.equals(ref.getLibraryName())) {
				addr = ref.getFromAddress();
				break;
			}
		}
		assertNotNull(addr);
		clickOnNode(globalsNode);
		cbPlugin.updateNow();
		assertEquals(addr, cbPlugin.getCurrentAddress());
	}

	@Test
	public void testSelectSymbolInTree() throws Exception {

		//
		// process program locations and find the appropriate symbol in the tree
		//

		Symbol s = getUniqueSymbol(program, "doStuff");
		assertNotNull(s);

		assertTrue(
			cbPlugin.goToField(s.getAddress(), VariableNameFieldFactory.FIELD_NAME, 1, 0, 0));
		util.waitForTree();

		// parm_1 should be selected in the symbol tree
		GTreeNode globalsNode = getGlobalsNode();
		GTreeNode doStufglobalsNode = globalsNode.getChild("doStuff");

		GTreeNode param_1Node = doStufglobalsNode.getChild("param_1");
		TreePath path = param_1Node.getTreePath();

		TreePath selectedPath = runSwing(() -> tree.getSelectionPath());
		assertNotNull(selectedPath);
		assertEquals(path, selectedPath);
	}

	@Test
	public void testDeleteLocalVariable() throws Exception {
		GTreeNode globalsNode = getGlobalsNode();
		util.expandNode(globalsNode);

		GTreeNode ghidraNode = globalsNode.getChild("ghidra");
		util.expandNode(ghidraNode);

		GTreeNode node = ghidraNode.getChild("AnotherLocal");
		util.selectNode(node);
		int count = ghidraNode.getChildCount();

		ActionContext context = util.getSymbolTreeContext();
		performTreeAction(deleteAction, context);

		assertEquals(count - 1, ghidraNode.getChildCount());
		for (int i = 0; i < count - 1; i++) {
			GTreeNode n = ghidraNode.getChild(i);
			Symbol s = ((SymbolNode) n).getSymbol();
			assertFalse(s.getName().equals("AnotherLocal"));
		}

		// test undo/redo
		undo(program);

		util.waitForTree();
		globalsNode = getGlobalsNode();
		ghidraNode = globalsNode.getChild("ghidra");
		boolean found = false;
		for (int i = 0; i < count - 1; i++) {
			GTreeNode n = ghidraNode.getChild(i);
			Symbol s = ((SymbolNode) n).getSymbol();
			if (s.getName().equals("AnotherLocal")) {
				found = true;
				break;
			}
		}
		assertTrue(found);

		redo(program);

		util.waitForTree();
		globalsNode = getGlobalsNode();
		ghidraNode = globalsNode.getChild("ghidra");

		for (int i = 0; i < count - 1; i++) {
			GTreeNode n = ghidraNode.getChild(i);
			Symbol s = ((SymbolNode) n).getSymbol();
			assertNotEquals("AnotherLocal", s.getName());
		}
	}

	@Test
	public void testDeleteFunction() throws Exception {
		GTreeNode globalsNode = getGlobalsNode();
		util.expandNode(globalsNode);
		assertEquals(18, globalsNode.getChildCount());

		GTreeNode doStuffNode = globalsNode.getChild("doStuff");
		util.expandNode(doStuffNode);
		util.selectNode(doStuffNode);

		ActionContext context = util.getSymbolTreeContext();
		performTreeAction(deleteAction, context);

		globalsNode = getGlobalsNode();
		assertEquals(18, globalsNode.getChildCount());
	}

	@Test
	public void testDeleteNamespace() throws Exception {

		GTreeNode nsParentNode = rootNode.getChild(SymbolCategory.NAMESPACES.getName());
		GTreeNode nsNode = util.createObject(nsParentNode, "MyNamespace", createNamespaceAction);
		util.createObject(nsNode, "MyClass", createClassAction);

		util.selectNode(nsNode);
		ActionContext context = util.getSymbolTreeContext();
		performTreeAction(deleteAction, context);

		for (int i = 0; i < nsParentNode.getChildCount(); i++) {
			GTreeNode n = rootNode.getChild(i);
			if (n.getName().equals("MyNamespace")) {
				fail("Expected MyNamespace node to be deleted");
			}
		}

	}

	@Test
	public void testConvertNamespaceToClass() throws Exception {
		String classNodeName = "MyClass";
		GTreeNode nsNode = rootNode.getChild(SymbolCategory.NAMESPACES.getName());
		GTreeNode classNode = util.createObject(
			nsNode, classNodeName, createNamespaceAction);

		util.selectNode(classNode);
		ActionContext context = util.getSymbolTreeContext();
		performTreeAction(convertToClassAction, context);

		GTreeNode namespacesNode = rootNode.getChild(SymbolCategory.NAMESPACES.getName());
		classNode = namespacesNode.getChild(classNodeName);
		assertTrue(classNode instanceof ClassSymbolNode);
		assertNotNull(classNode);
		waitForCondition(tree::isEditing);

		tree.cancelEditing();
		waitForSwing();
	}

	@Test
	public void testClassNestedUnderNonClassNamespace_RenameClass() throws Exception {

		/*
		
		 	Namespaces		 	
		 		FooNs
		 			Class1
		 */

		Namespace fooNs = createNamespace("FooNs");
		GhidraClass class1 = createClass(fooNs, "Class1");

		expandNamesapces();

		//@formatter:off
		assertNamespaceNodes(
			"FooNs::Class1"
		);
		//@formatter:on

		renameSymbol(class1.getSymbol(), "Class1.renamed");

		//@formatter:off
		assertNamespaceNodes(
			"FooNs::Class1.renamed"
		);
		//@formatter:on

	}

	@Test
	public void testClassCategoryDuplicates_NestedClass_RenameLabel() throws Exception {

		/*
		 	Classes
		 		
		 	Namespaces		 	
		 		FooNs
		 			Class1
		 				Label1
		 				BarNs		 				
		 					Class2
		 						Label2
		 */

		Namespace fooNs = createNamespace("FooNs");
		GhidraClass class1 = createClass(fooNs, "Class1");
		Namespace barNs = createNamespace(class1, "BarNs");
		createLabel(class1, "Label1", "0x1001100");
		GhidraClass class2 = createClass(barNs, "Class2");
		Symbol lable2 = createLabel(class2, "Label2", "0x1001104");
		expandNamesapces();

		// verify all leaf nodes
		//@formatter:off
		assertNamespaceNodes(
			"FooNs::Class1::Label1",
			"FooNs::Class1::BarNs::Class2::Label2"
		);
		//@formatter:on

		renameSymbol(lable2, "Label2.renamed");

		//@formatter:off
		assertNamespaceNodes(
			"FooNs::Class1::Label1",
			"FooNs::Class1::BarNs::Class2::Label2.renamed"
		);
		//@formatter:on

	}

	@Test
	public void testClassCategoryDuplicates_NestedClass_ChangeNamespace() throws Exception {

		/*
		
		 	Classes
		 		
		 	Namespaces		 	
		 		FooNs
		 			Class1
		 				Label1
		 				BarNs		 				
		 					Class2
		 						Label2
		 */

		Namespace fooNs = createNamespace("FooNs");
		GhidraClass class1 = createClass(fooNs, "Class1");
		Namespace barNs = createNamespace(class1, "BarNs");
		Symbol label1 = createLabel(class1, "Label1", "0x1001100");
		GhidraClass class2 = createClass(barNs, "Class2");
		createLabel(class2, "Label2", "0x1001104");

		expandNamesapces();

		// verify all leaf nodes
		//@formatter:off
		assertNamespaceNodes(
			"FooNs::Class1::Label1",
			"FooNs::Class1::BarNs::Class2::Label2"
		);
		//@formatter:on

		moveLabel(label1, barNs);

		//@formatter:off
		assertNamespaceNodes(
			"FooNs::Class1::BarNs::Label1",
			"FooNs::Class1::BarNs::Class2::Label2"
		);
		//@formatter:on

	}

	@Test
	public void testClassCategoryDuplicates_NestedClass_RenameNamespace() throws Exception {

		/*
		 			 	
		 	Classes
		 	
		 	Namespaces		 	
		 		FooNs
		 			Class1
		 				Label1
		 				BarNs		 				
		 					Class2
		 						Label2
		 */

		Namespace fooNs = createNamespace("FooNs");
		GhidraClass class1 = createClass(fooNs, "Class1");
		Namespace barNs = createNamespace(class1, "BarNs");
		createLabel(class1, "Label1", "0x1001100");
		GhidraClass class2 = createClass(barNs, "Class2");
		createLabel(class2, "Label2", "0x1001104");

		expandNamesapces();

		// verify all leaf nodes
		//@formatter:off
		assertNamespaceNodes(
			"FooNs::Class1::Label1",
			"FooNs::Class1::BarNs::Class2::Label2"
		);
		//@formatter:on

		renameNamespace(barNs, "BarNs.renamed");

		//@formatter:off
		assertNamespaceNodes(
			"FooNs::Class1::Label1",
			"FooNs::Class1::BarNs.renamed::Class2::Label2"
		);
		//@formatter:on

	}

	@Test
	public void testActionsOnGroup() throws Exception {
		// select a group node; only cut, delete, make selection should be
		// on the popup

		GTreeNode globalsNode = rootNode.getChild("Globals");
		util.expandNode(globalsNode);

		util.selectNode(globalsNode);

		ActionContext context = util.getSymbolTreeContext();
		assertFalse(renameAction.isEnabledForContext(context));
		assertFalse(cutAction.isEnabledForContext(context));
		assertFalse(pasteAction.isEnabledForContext(context));
		assertFalse(deleteAction.isEnabledForContext(context));
		assertFalse(selectionAction.isEnabledForContext(context));
		assertFalse(createNamespaceAction.isEnabledForContext(context));
		assertFalse(createClassAction.isEnabledForContext(context));
	}

	@Test
	public void testUpdate() throws Exception {
		// create a new label; verify that it shows up in the tree
		GTreeNode globalsNode = rootNode.getChild("Globals");
		util.expandNode(globalsNode);

		// add a label
		tx(program, () -> {
			SymbolTable symTable = program.getSymbolTable();
			symTable.createLabel(util.addr(0x010048a1L), "abcdefg", SourceType.USER_DEFINED);
		});

		util.waitForTree();

		globalsNode = rootNode.getChild("Globals");
		util.waitForTree();

		GTreeNode node = globalsNode.getChild("abcdefg");
		assertNotNull(node);
	}

	@Test
	public void testExternalRename() throws Exception {
		// rename a label in the global namespace
		// verify that the tree updates

		Function f = program.getFunctionManager().getFunctionAt(util.addr(0x01002cf5L));
		Symbol s = getUniqueSymbol(program, "AnotherLocal", f);
		assertNotNull(s);

		tx(program, () -> {
			s.setName("MyAnotherLocal", SourceType.USER_DEFINED);
		});

		util.waitForTree();

		GTreeNode globalsNode = getGlobalsNode();
		util.expandNode(globalsNode);

		GTreeNode gNode = globalsNode.getChild("ghidra");
		util.expandNode(gNode);

		GTreeNode node = gNode.getChild(9);
		assertEquals("MyAnotherLocal", (((SymbolNode) node).getSymbol()).getName());

		// undo/redo
		undo(program);
		util.waitForTree();

		globalsNode = getGlobalsNode();
		util.expandNode(globalsNode);

		gNode = globalsNode.getChild("ghidra");
		util.expandNode(gNode);

		node = gNode.getChild(9);
		assertEquals("AnotherLocal", (((SymbolNode) node).getSymbol()).getName());

		redo(program);
		globalsNode = getGlobalsNode();
		util.expandNode(globalsNode);

		gNode = globalsNode.getChild("ghidra");
		util.expandNode(gNode);

		node = gNode.getChild(9);
		assertEquals("MyAnotherLocal", (((SymbolNode) node).getSymbol()).getName());
	}

	@Test
	public void testOrgNode_Namespaces() throws Exception {

		// set org node threshold to a low value 
		ToolOptions options = tool.getOptions(SymbolTreePlugin.OPTIONS_CATEGORY);
		int newThreshold = 4;
		options.setInt(SymbolTreePlugin.OPTION_NAME_GROUP_THRESHOLD, newThreshold);

		/*
		 	Create enough nodes to trigger an org node.
		 	
		 	Namespaces
		 		NsGroup1
		 			NsGroup10
		 				NsGroup100
		 		NsGroup2
		 		NsGroup3
		 */
		createOrgNamespaces(newThreshold);

		// create a new namespace node that would appear under an org node
		NamespaceSymbolNode parentNode = openNamespaceNodes("NsGroup1::NsGroup10::NsGroup100");
		Namespace parentNs = parentNode.getNamespace();
		createNamespace(parentNs, "NewNamespace");

		// verify node is in the tree
		assertNamespaceNodes("NsGroup1::NsGroup10::NsGroup100::NewNamespace");
	}

	@Test
	public void testDeleteOrgNode() throws Exception {

		//
		// Tests that OrganizationNodes can be deleted from the UI
		// 

		// set org node threshold to a low value 
		ToolOptions options = tool.getOptions(SymbolTreePlugin.OPTIONS_CATEGORY);
		int newThreshold = 4;
		options.setInt(SymbolTreePlugin.OPTION_NAME_GROUP_THRESHOLD, newThreshold);

		/*
		 	Create enough nodes to trigger an org node.
		 	
		 	Namespaces
		 		NsGroup1
		 			NsGroup10
		 				NsGroup100
		 		NsGroup2
		 		NsGroup3
		 */
		createOrgNamespaces(newThreshold);
		openNamespaceNodes("NsGroup1::NsGroup10::NsGroup100");

		GTreeNode group10 = getNode(tree, "Root", "Namespaces", "NsGroup1", "NsGroup10");

		List<GTreeNode> children = group10.getChildren();
		List<SymbolNode> symbols =
			children.stream().map(n -> (SymbolNode) n).collect(Collectors.toList());

		util.selectNode(group10);

		ActionContext context = util.getSymbolTreeContext();
		performTreeAction(deleteAction, context);

		GTreeNode group1 = getNode(tree, "Root", "Namespaces", "NsGroup1");
		group10 = group1.getChild("NsGroup10");
		assertNull(group10);

		for (SymbolNode node : symbols) {
			Symbol symbol = node.getSymbol();
			assertTrue(symbol.isDeleted());
		}
	}

	@Test
	public void testFindClassInNamespace() throws Exception {

		Namespace namespace = createNamespace(null, "namespace");
		GhidraClass myClass = createClass(namespace, "myClass");
		SymbolTreeRootNode root = (SymbolTreeRootNode) tree.getModelRoot();
		GTreeNode result = root.findSymbolNode(myClass.getSymbol(), true, TaskMonitor.DUMMY);
		assertNotNull(result);
	}

	@Test
	public void testFindNamespaceInClass() throws Exception {
		GhidraClass myClass = createClass(null, "myClass");
		Namespace namespace = createNamespace(myClass, "subNamespace");
		SymbolTreeRootNode root = (SymbolTreeRootNode) tree.getModelRoot();
		GTreeNode result = root.findSymbolNode(namespace.getSymbol(), true, TaskMonitor.DUMMY);
		assertNotNull(result);
	}
//=================================================================================================
// Private Methods
//=================================================================================================	

	private NamespaceCategoryNode getNamespacesNode() {
		GTreeNode root = tree.getViewRoot();
		return (NamespaceCategoryNode) root.getChild("Namespaces");
	}

	private NamespaceSymbolNode openNamespaceNodes(String path) {

		GTreeNode parent = getNamespacesNode();
		String[] parts = path.split("::");
		for (String name : parts) {
			GTreeNode child = parent.getChild(name);
			String message =
				"Child '%s' not found in parent '%s' \n\tfor path '%s'"
						.formatted(name, parent, path);
			assertNotNull(message, child);
			tree.expandPath(child);
			parent = child;
		}
		waitForTree(tree);

		return (NamespaceSymbolNode) parent;
	}

	private void createOrgNamespaces(int threshold) throws Exception {
		int groupCount = 3;
		for (int i = 0; i < groupCount; i++) {
			// groups need to share a common prefix
			String groupName = "Group" + (i + 1); // 1-based for readability
			int childCount = (threshold + 1);
			for (int j = 0; j < childCount; j++) {

				String subGroupName = groupName + j;
				for (int k = 0; k < childCount; k++) {

					createNamespace("Ns" + subGroupName + k);
				}
			}
		}
	}

	private void expandNamesapces() {
		GTreeNode node = rootNode.getChild("Namespaces");
		tree.expandTree(node);
		waitForTree(tree);
	}

	private void renameSymbol(Symbol s, String newName) {
		RenameLabelCmd cmd = new RenameLabelCmd(s, newName, SourceType.USER_DEFINED);
		if (!applyCmd(program, cmd)) {
			fail("Rename failed: " + cmd.getStatusMsg());
		}
		waitForTree(tree);
	}

	private void moveLabel(Symbol symbol, Namespace ns) {
		tx(program, () -> {
			symbol.setNamespace(ns);
		});
		waitForTree(tree);
	}

	private void renameNamespace(Namespace barNs, String newName) {
		Symbol symbol = barNs.getSymbol();
		renameSymbol(symbol, newName);
	}

	private void assertNamespaceNodes(String... paths) {
		GTreeNode root = tree.getViewRoot();
		GTreeNode parent = root.getChild("Namespaces");
		assertNodes(parent, paths);
	}

	private void assertNodes(GTreeNode category, String... paths) {

		for (String path : paths) {
			GTreeNode parent = category;
			String[] parts = path.split("::");
			for (String name : parts) {
				GTreeNode child = parent.getChild(name);
				String message =
					"Child '%s' not found in parent '%s' \n\tfor path '%s'\n\tCategory '%s'"
							.formatted(name, parent, path, category);
				assertNotNull(message, child);
				parent = child;
			}
		}
	}

	private Namespace createNamespace(String name) throws Exception {
		return createNamespace(program.getGlobalNamespace(), name);
	}

	private Namespace createNamespace(Namespace parent, String name) throws Exception {
		CreateNamespacesCmd cmd = new CreateNamespacesCmd(name, parent, SourceType.USER_DEFINED);
		applyCmd(program, cmd);
		return cmd.getNamespace();
	}

	private GhidraClass createClass(Namespace parent, String name) throws Exception {
		GhidraClass c = tx(program, () -> {
			SymbolTable symbolTable = program.getSymbolTable();
			return symbolTable.createClass(parent, name, SourceType.USER_DEFINED);
		});
		assertNotNull(c);
		return c;
	}

	private Symbol createLabel(Namespace parent, String name, String addr) {
		Symbol s = tx(program, () -> {
			SymbolTable symbolTable = program.getSymbolTable();
			AddressFactory af = program.getAddressFactory();
			Address address = af.getAddress(addr);
			return symbolTable.createLabel(address, name, parent, SourceType.USER_DEFINED);
		});
		assertNotNull(s);
		return s;
	}

	private GTreeNode getGlobalsNode() {
		return runSwing(() -> rootNode.getChild("Globals"));
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
		convertToClassAction = getAction(plugin, "Convert to Class");
		assertNotNull(convertToClassAction);

		navigateIncomingAction =
			(ToggleDockingAction) getAction(plugin, NavigateOnIncomingAction.NAME);
		assertNotNull(navigateIncomingAction);
	}

	private void performTreeAction(DockingActionIf action, ActionContext context) {
		assertTrue(action.isEnabledForContext(context));
		performAction(action, context, true);
		program.flushEvents();
		util.waitForTree();
	}

	private void clickOnNode(GTreeNode node) throws Exception {
		JTree jTree = (JTree) AbstractGenericTest.getInstanceField("tree", tree);

		Rectangle rect = jTree.getPathBounds(node.getTreePath());
		clickMouse(jTree, 1, rect.x + 2, rect.y + 2, 1, 0);
		util.waitForTree();

	}

}
