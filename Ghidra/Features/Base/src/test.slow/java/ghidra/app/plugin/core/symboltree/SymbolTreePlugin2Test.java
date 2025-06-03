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
import ghidra.app.plugin.core.symboltree.nodes.SymbolCategoryNode;
import ghidra.app.plugin.core.symboltree.nodes.SymbolNode;
import ghidra.app.util.viewer.field.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;

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
		SwingUtilities.invokeAndWait(() -> goToToggleAction.setSelected(true));
	}

	@After
	public void tearDown() throws Exception {
		util.closeProgram();
		env.dispose();
	}

	@Test
	public void testNavigateToSymbol() throws Exception {

		// select a node; code browser should go there

		assertTrue(goToToggleAction.isSelected());

		GTreeNode fNode = getFunctionsNode();
		util.expandNode(fNode);

		GTreeNode gNode = fNode.getChild(1);
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
		GTreeNode fNode = getFunctionsNode();
		util.expandNode(fNode);

		GTreeNode gNode = fNode.getChild(1);
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

		GTreeNode fNode = getFunctionsNode();
		util.expandNode(fNode);

		GTreeNode gNode = fNode.getChild(1);
		util.expandNode(gNode);

		GTreeNode pNode = gNode.getChild(0);
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
		GTreeNode fNode = node.getChild(0);

		Symbol extSym = ((SymbolNode) fNode).getSymbol();
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
		clickOnNode(fNode);
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
		GTreeNode fNode = getFunctionsNode();
		GTreeNode doStuffNode = fNode.getChild(0);

		GTreeNode param_1Node = doStuffNode.getChild(0);
		TreePath path = param_1Node.getTreePath();

		TreePath selectedPath = runSwing(() -> tree.getSelectionPath());
		assertNotNull(selectedPath);
		assertEquals(path, selectedPath);
	}

	@Test
	public void testDeleteLocalVariable() throws Exception {
		GTreeNode functionsNode = getFunctionsNode();
		util.expandNode(functionsNode);

		GTreeNode ghidraNode = functionsNode.getChild(1);
		util.expandNode(ghidraNode);

		GTreeNode node = ghidraNode.getChild(9);
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
		functionsNode = getFunctionsNode();
		ghidraNode = functionsNode.getChild(1);
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
		functionsNode = getFunctionsNode();
		ghidraNode = functionsNode.getChild(1);

		for (int i = 0; i < count - 1; i++) {
			GTreeNode n = ghidraNode.getChild(i);
			Symbol s = ((SymbolNode) n).getSymbol();
			assertNotEquals("AnotherLocal", s.getName());
		}
	}

	@Test
	public void testDeleteFunction() throws Exception {
		GTreeNode functionsNode = getFunctionsNode();
		util.expandNode(functionsNode);

		GTreeNode doStuffNode = functionsNode.getChild(0);
		util.expandNode(doStuffNode);
		util.selectNode(doStuffNode);

		ActionContext context = util.getSymbolTreeContext();
		performTreeAction(deleteAction, context);

		functionsNode = getFunctionsNode();
		assertEquals(2, functionsNode.getChildCount());
	}

	@Test
	public void testDeleteNamespace() throws Exception {

		GTreeNode nsParentNode = rootNode.getChild(5);
		GTreeNode nsNode = util.createObject(nsParentNode, "MyNamespace", createNamespaceAction);
		util.createObject(nsNode, "MyClass", createClassAction);

		util.selectNode(nsNode);
		ActionContext context = util.getSymbolTreeContext();
		performTreeAction(deleteAction, context);

		nsParentNode = rootNode.getChild(4);
		for (int i = 0; i < nsParentNode.getChildCount(); i++) {
			GTreeNode n = rootNode.getChild(i);
			assertTrue(n instanceof SymbolCategoryNode);
			SymbolCategory cat = ((SymbolCategoryNode) n).getSymbolCategory();
			assertTrue(cat.getSymbolType() != SymbolType.NAMESPACE);
		}

	}

	@Test
	public void testConvertNamespaceToClass() throws Exception {
		String classNodeName = "MyClass";
		GTreeNode nsNode = rootNode.getChild(SymbolCategory.NAMESPACE_CATEGORY.getName());
		GTreeNode classNode = util.createObject(
			nsNode, classNodeName, createNamespaceAction);

		util.selectNode(classNode);
		ActionContext context = util.getSymbolTreeContext();
		performTreeAction(convertToClassAction, context);

		GTreeNode classRootNode = rootNode.getChild(SymbolCategory.CLASS_CATEGORY.getName());
		classNode = classRootNode.getChild(classNodeName);
		assertNotNull(classNode);
		waitForCondition(tree::isEditing);
	}

	@Test
	public void testClassCategoryDuplicates_NestedClass_RenameLabel() throws Exception {

		/*
		 	
		 	The Classes folder flattens classes so every class appears at the top level.  Because
		 	users can expand classes, top level classes may also appear nested under other classes.
		 	
		 	Classes
		 		Class1		 			
		 			Label1
		 			BarNs
		 				Class2
		 					Label2
		 		Class2
		 			Label2
		 		
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

		expandClasses();
		expandNamesapces();

		// verify all leaf nodes
		//@formatter:off
		assertNamespaceNodes(
			"FooNs::Class1::Label1",
			"FooNs::Class1::BarNs::Class2::Label2"
		);
		//@formatter:on

		//@formatter:off
		assertClassNodes(
			"Class1::Label1",
			"Class1::BarNs::Class2::Label2",
			"Class2::Label2"
		);
		//@formatter:on

		renameSymbol(lable2, "Label2.renamed");

		//@formatter:off
		assertNamespaceNodes(
			"FooNs::Class1::Label1",
			"FooNs::Class1::BarNs::Class2::Label2.renamed"
		);
		//@formatter:on

		//@formatter:off
		assertClassNodes(
			"Class1::Label1",
			"Class1::BarNs::Class2::Label2.renamed",
			"Class2::Label2.renamed"
		);
		//@formatter:on
	}

	@Test
	public void testClassCategoryDuplicates_NestedClass_ChangeNamespace() throws Exception {

		/*
		 	
		 	The Classes folder flattens classes so every class appears at the top level.  Because
		 	users can expand classes, top level classes may also appear nested under other classes.
		 	
		 	Classes
		 		Class1		 			
		 			Label1
		 			BarNs
		 				Class2
		 					Label2
		 		Class2
		 			Label2
		 		
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

		expandClasses();
		expandNamesapces();

		// verify all leaf nodes
		//@formatter:off
		assertNamespaceNodes(
			"FooNs::Class1::Label1",
			"FooNs::Class1::BarNs::Class2::Label2"
		);
		//@formatter:on

		//@formatter:off
		assertClassNodes(
			"Class1::Label1",
			"Class1::BarNs::Class2::Label2",
			"Class2::Label2"
		);
		//@formatter:on

		moveLabel(label1, barNs);

		//@formatter:off
		assertNamespaceNodes(
			"FooNs::Class1::BarNs::Label1",
			"FooNs::Class1::BarNs::Class2::Label2"
		);
		//@formatter:on

		//@formatter:off
		assertClassNodes(
			"Class1",
			"Class1::BarNs::Label1",
			"Class1::BarNs::Class2::Label2",
			"Class2::Label2"
		);
		//@formatter:on
	}

	@Test
	public void testClassCategoryDuplicates_NestedClass_RenameNamespace() throws Exception {

		/*
		 	
		 	The Classes folder flattens classes so every class appears at the top level.  Because
		 	users can expand classes, top level classes may also appear nested under other classes.
		 	
		 	Classes
		 		Class1		 			
		 			Label1
		 			BarNs
		 				Class2
		 					Label2
		 		Class2
		 			Label2
		 		
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

		expandClasses();
		expandNamesapces();

		// verify all leaf nodes
		//@formatter:off
		assertNamespaceNodes(
			"FooNs::Class1::Label1",
			"FooNs::Class1::BarNs::Class2::Label2"
		);
		//@formatter:on

		//@formatter:off
		assertClassNodes(
			"Class1::Label1",
			"Class1::BarNs::Class2::Label2",
			"Class2::Label2"
		);
		//@formatter:on

		renameNamespace(barNs, "BarNs.renamed");

		//@formatter:off
		assertNamespaceNodes(
			"FooNs::Class1::Label1",
			"FooNs::Class1::BarNs.renamed::Class2::Label2"
		);
		//@formatter:on

		//@formatter:off
		assertClassNodes(
			"Class1::Label1",
			"Class1::BarNs.renamed::Class2::Label2",
			"Class2::Label2"
		);
		//@formatter:on
	}

	@Test
	public void testActionsOnGroup() throws Exception {
		// select a group node; only cut, delete, make selection should be
		// on the popup

		GTreeNode lNode = rootNode.getChild(3);
		util.expandNode(lNode);

		util.selectNode(lNode);

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
		GTreeNode lNode = rootNode.getChild(3);
		util.expandNode(lNode);

		// add a label
		tx(program, () -> {
			SymbolTable symTable = program.getSymbolTable();
			symTable.createLabel(util.addr(0x010048a1L), "abcdefg", SourceType.USER_DEFINED);
		});

		util.waitForTree();

		lNode = rootNode.getChild(3);
		util.waitForTree();

		GTreeNode node = lNode.getChild(0);
		assertNotNull(node);
		assertEquals("abcdefg", node.toString());
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

		GTreeNode fNode = getFunctionsNode();
		util.expandNode(fNode);

		GTreeNode gNode = fNode.getChild(1);
		util.expandNode(gNode);

		GTreeNode node = gNode.getChild(9);
		assertEquals("MyAnotherLocal", (((SymbolNode) node).getSymbol()).getName());

		// undo/redo
		undo(program);
		util.waitForTree();

		fNode = getFunctionsNode();
		util.expandNode(fNode);

		gNode = fNode.getChild(1);
		util.expandNode(gNode);

		node = gNode.getChild(9);
		assertEquals("AnotherLocal", (((SymbolNode) node).getSymbol()).getName());

		redo(program);
		fNode = getFunctionsNode();
		util.expandNode(fNode);

		gNode = fNode.getChild(1);
		util.expandNode(gNode);

		node = gNode.getChild(9);
		assertEquals("MyAnotherLocal", (((SymbolNode) node).getSymbol()).getName());
	}

//=================================================================================================
// Private Methods
//=================================================================================================	

	private void expandClasses() {
		GTreeNode node = rootNode.getChild("Classes");
		tree.expandTree(node);
		waitForTree(tree);
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

	private void assertClassNodes(String... paths) {
		GTreeNode root = tree.getViewRoot();
		GTreeNode parent = root.getChild("Classes");
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

	private GTreeNode getFunctionsNode() {
		return runSwing(() -> rootNode.getChild(2));
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

		goToToggleAction = (ToggleDockingAction) getAction(plugin, "Navigation");
		assertNotNull(goToToggleAction);
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
