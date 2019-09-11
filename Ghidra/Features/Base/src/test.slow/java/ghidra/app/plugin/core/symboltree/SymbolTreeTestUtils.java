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

import static generic.test.AbstractGTest.*;
import static generic.test.AbstractGenericTest.*;
import static ghidra.test.AbstractGhidraHeadedIntegrationTest.*;
import static org.junit.Assert.*;

import java.awt.Container;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.ClipboardOwner;
import java.util.Comparator;
import java.util.List;

import javax.swing.JTextField;
import javax.swing.JTree;
import javax.swing.tree.DefaultTreeCellEditor;
import javax.swing.tree.TreePath;

import org.apache.commons.lang3.StringUtils;

import docking.ActionContext;
import docking.action.DockingActionIf;
import docking.action.ToggleDockingAction;
import docking.test.AbstractDockingTest;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import docking.widgets.tree.support.GTreeNodeTransferable;
import ghidra.app.plugin.core.symboltree.nodes.*;
import ghidra.app.services.ProgramManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.Undefined1DataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.test.ToyProgramBuilder;

/**
 * Utility class that has common methods needed by the Junit tests.
 */
class SymbolTreeTestUtils {

	private Program program;
	private SymbolTreePlugin plugin;
	private DockingActionIf symTreeAction;
	private SymbolGTree tree;
	private GTreeNode rootGTreeNode;
	private SymbolTreeProvider provider;
	private DockingActionIf renameAction;
	private DockingActionIf cutAction;
	private DockingActionIf pasteAction;
	private DockingActionIf deleteAction;
	private DockingActionIf selectionAction;
	private DockingActionIf createNamespaceAction;
	private DockingActionIf createClassAction;
	private ToggleDockingAction goToToggleAction;

	/** A comparator to sort Symbols the same way as the SymbolNode sorts */
	// Note: a bit of guilty knowledge: the SymbolNodes will sort first on name, then on
	//       symbol.  Tests will break if SymbolNode.compareTo() is changed.
	private Comparator<Symbol> symbolComparator = (s1, s2) -> {
		int nameCompare = s1.getName().compareToIgnoreCase(s2.getName());

		// sort alphabetically first		
		if (nameCompare != 0) {
			return nameCompare;
		}

		int result = SymbolTreeNode.SYMBOL_COMPARATOR.compare(s1, s2);
		return result;
	};

	private Comparator<Symbol> functionComparator = new FunctionSymbolComparator();

	SymbolTreeTestUtils(SymbolTreePlugin plugin) throws Exception {
		this.plugin = plugin;
		this.program = buildProgram();

		symTreeAction = getAction(plugin, "Symbol Tree");
	}

	SymbolTreeTestUtils(SymbolTreePlugin plugin, Program program) {
		this.plugin = plugin;
		this.program = program;

		symTreeAction = getAction(plugin, "Symbol Tree");
	}

	public static Program buildProgram() throws Exception {

		ToyProgramBuilder builder = new ToyProgramBuilder("notepad", true);
		Program program = builder.getProgram();

		builder.createMemory("test", "0x1001000", 0x5500);

		// create an 'Exports' node
		builder.createEntryPoint("0x1006420", "entry");
		builder.createLabel("0x1006420", "entry");

		// imports symbol tree node
		builder.createExternalLibraries("ADVAPI32.dll", "comdlg32.dll", "GDI32.dll", "KERNEL32.dll",
			"MSVCRT.dll", "SHELL32.dll", "USER32.dll", "WINSPOOL.DRV");
		builder.createExternalReference("0x1001000", "ADVAPI32.dll", "IsTextUnicode", 0);
		builder.createLabel("0x1001000", "ADVAPI32.dll_IsTextUnicode");
		builder.createExternalReference("0x1001004", "ADVAPI32.dll", "RegCreateKeyW", 0);
		builder.createLabel("0x1001004", "ADVAPI32.dll_RegCreateKeyW");
		builder.createExternalReference("0x1001008", "ADVAPI32.dll", "RegQueryValueExW", 0);
		builder.createLabel("0x1001008", "ADVAPI32.dll_RegQueryValueExW");
		builder.createExternalReference("0x100100c", "ADVAPI32.dll", "RegSetValueExW", 0);
		builder.createLabel("0x100100c", "ADVAPI32.dll_RegSetValueExW");
		builder.createExternalReference("0x1001010", "ADVAPI32.dll", "RegOpenKeyExA", 0);
		builder.createLabel("0x1001010", "ADVAPI32.dll_RegOpenKeyExA");
		builder.createExternalReference("0x1001014", "ADVAPI32.dll", "RegQueryValueExA", 0);
		builder.createLabel("0x1001014", "ADVAPI32.dll_RegQueryValueExA");
		builder.createExternalReference("0x1001018", "ADVAPI32.dll", "RegCloseKey", 0);
		builder.createLabel("0x1001018", "ADVAPI32.dll_RegCloseKey");

		ExternalManager externalManager = builder.getProgram().getExternalManager();
		int tx = program.startTransaction("Test Transaction");
		externalManager.setExternalPath("ADVAPI32.dll", "/path/to/ADVAPI32.DLL", true);
		program.endTransaction(tx, true);

		// functions
		builder.createEmptyFunction("doStuff", null, "0x10048a3", 19, new Undefined1DataType(),
			new ParameterImpl("param_1", new IntegerDataType(), program),
			new ParameterImpl("param_2", new IntegerDataType(), program));

		//@formatter:off
		ParameterImpl p = new ParameterImpl(null /*auto name*/, new IntegerDataType(), program);
		builder.createEmptyFunction("ghidra", null, "0x1002cf5", 121, new Undefined1DataType(),
			p, p, p, p, p, p, p, p, p);
		//@formatter:on

		builder.createStackReference("1002d06", RefType.DATA, 0x8, SourceType.ANALYSIS, 0);
		builder.createMemoryCallReference("0x1002cf9", "0x10048a3"); // call 'doStuff' function

		builder.createLabel("0x1002d2b", "AnotherLocal", "ghidra");
		builder.createLabel("0x1002d1f", "MyLocal", "ghidra");

		//@formatter:off
		Function function = builder.createEmptyFunction("sscanf", null, "0x100415a", 78, 
			new Undefined1DataType(),
			new ParameterImpl("destStr", new IntegerDataType(), program), 
			new ParameterImpl("param_3", new IntegerDataType(), program),
			new ParameterImpl("param_4", new IntegerDataType(), program));
		//@formatter:on

		Variable var = new LocalVariableImpl("i", new IntegerDataType(), -0x4, program);
		builder.addFunctionVariable(function, var);
		var = new LocalVariableImpl("count", new IntegerDataType(), -0x8, program);
		builder.addFunctionVariable(function, var);
		var = new LocalVariableImpl("formatCount", new IntegerDataType(), -0xc, program);
		builder.addFunctionVariable(function, var);

		return program;
	}

	SymbolTreeRootNode getRootNode() {
		return (SymbolTreeRootNode) rootGTreeNode;
	}

	SymbolGTree getTree() {
		return tree;
	}

	void setPlugin(SymbolTreePlugin plugin) {
		this.plugin = plugin;
	}

	GTreeNode createObject(GTreeNode parenGTreeNode, String newName, DockingActionIf action)
			throws Exception {

		assertNotNull(action);

		selectNode(parenGTreeNode);
		int childCount = parenGTreeNode.getChildCount();
		int index = parenGTreeNode.getIndexInParent();
		GTreeNode pNode = parenGTreeNode.getParent();

		AbstractDockingTest.performAction(action, getSymbolTreeContext(), false);
		waitForSwing();
		waitForTree();
		program.flushEvents();

		if (pNode != null) {
			// re-acquire parent
			parenGTreeNode = pNode.getChild(index);
		}
		GTreeNode node = parenGTreeNode.getChild(childCount > 0 ? childCount - 1 : 0);

		waitForTree();

		runSwing(() -> tree.stopEditing());
		waitForCondition(() -> !tree.isEditing());

		rename(node, newName);
		return parenGTreeNode.getChild(newName);
	}

	SymbolTreeProvider getProvider() {
		return provider;
	}

	Comparator<Symbol> getSymbolComparator() {
		return symbolComparator;
	}

	Comparator<Symbol> getFunctionComparator() {
		return functionComparator;
	}

	void collapseTree() {
		GTreeNode root = tree.getViewRoot();
		List<GTreeNode> topLevelNodes = root.getChildren();
		topLevelNodes.forEach(n -> tree.collapseAll(n));
		waitForTree();
	}

	void expandNode(GTreeNode parenGTreeNode) throws Exception {
		tree.expandPath(parenGTreeNode);
		waitForTree();
	}

	void expandAll(GTreeNode parenGTreeNode, List<Object> list) throws Exception {
		expandNode(parenGTreeNode);
		for (int i = 0; i < parenGTreeNode.getChildCount(); i++) {
			GTreeNode node = parenGTreeNode.getChild(i);
			if (node instanceof OrganizationNode) {
				expandAll(node, list);
			}
			else {
				list.add(node);
			}
		}
	}

	void selectNode(GTreeNode node) throws Exception {
		GTreeNode parent = node.getParent();
		if (parent != null) {
			tree.expandTree(node.getParent());
		}
		tree.setSelectedNode(node);
		waitForTree();
	}

	void selectNodes(GTreeNode[] nodes) throws Exception {
		final TreePath[] paths = new TreePath[nodes.length];
		for (int i = 0; i < paths.length; i++) {
			paths[i] = nodes[i].getTreePath();
		}
		tree.setSelectionPaths(paths);
		waitForTree();
	}

	GTreeNode getSelectedNode() {

		GTreeNode node = runSwing(() -> {

			TreePath path = tree.getSelectionPath();
			if (path == null) {
				return null;
			}

			return (GTreeNode) path.getLastPathComponent();
		});
		return node;
	}

	ActionContext getSymbolTreeContext() {
		return runSwing(() -> provider.getActionContext(null));
	}

	void rename(GTreeNode node, final String newName) throws Exception {
		selectNode(node);

		final TreePath path = node.getTreePath();
		assertTrue(tree.isPathSelected(path));

		final GTreeNode nsNode = node;
		assertTrue(renameAction.isEnabledForContext(getSymbolTreeContext()));
		runSwing(() -> renameAction.actionPerformed(getSymbolTreeContext()));

		waitForTree();

		runSwing(() -> {
			int row = tree.getRowForPath(path);
			JTree jTree = (JTree) getInstanceField("tree", tree);
			DefaultTreeCellEditor cellEditor = (DefaultTreeCellEditor) tree.getCellEditor();
			Container container = (Container) cellEditor.getTreeCellEditorComponent(jTree, nsNode,
				true, true, true, row);
			JTextField textField = (JTextField) container.getComponent(0);

			textField.setText(newName);
			tree.stopEditing();
		});
		program.flushEvents();
		waitForSwing();
		waitForTree();
	}

	void waitForTree() {
		waitForSwing();
		AbstractDockingTest.waitForTree(tree);
	}

	Address addr(long offset) {
		return program.getMinAddress().getNewAddress(offset);
	}

	void showSymbolTree() throws Exception {
		showSymbolTree(true);
	}

	void showSymbolTree(boolean openProgram) throws Exception {
		if (openProgram) {
			openProgram();
		}

		AbstractDockingTest.performAction(symTreeAction, true);
		provider = plugin.getProvider();
		tree = findComponent(provider.getComponent(), SymbolGTree.class);
		waitForTree();
		rootGTreeNode = tree.getViewRoot();
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

	void setGoToNavigationSelected(boolean selected) {
		runSwing(() -> goToToggleAction.setSelected(true));
	}

	void closeProgram() throws Exception {
		final ProgramManager pm = plugin.getTool().getService(ProgramManager.class);
		runSwing(() -> pm.closeProgram());
	}

	Program getProgram() {
		return program;
	}

	void openProgram() {
		ProgramManager pm = plugin.getTool().getService(ProgramManager.class);
		pm.openProgram(program.getDomainFile());
	}

	void clearClipboard() {
		Clipboard clipboard = (Clipboard) getInstanceField("localClipboard", provider);
		ClipboardOwner owner = (ClipboardOwner) getInstanceField("clipboardOwner", provider);
		clipboard.setContents(null, owner);
	}

	List<?> getClipboardContents() {
		Clipboard clipboard = provider.getClipboard();
		GTreeNodeTransferable contents = (GTreeNodeTransferable) clipboard.getContents(this);
		return contents.getAllData();
	}

	private class FunctionSymbolComparator implements Comparator<Symbol> {
		@Override
		public int compare(Symbol s1, Symbol s2) {
			Object obj1 = s1.getObject();
			Object obj2 = s2.getObject();
			if ((obj1 instanceof Variable) && (obj2 instanceof Variable)) {
				Variable v1 = (Variable) s1.getObject();
				Variable v2 = (Variable) s2.getObject();
				return v1.compareTo(v2);
			}
			if (obj1 instanceof Variable) {
				return -1;
			}
			if (obj2 instanceof Variable) {
				return 1;
			}

			return symbolComparator.compare(s1, s2);
		}
	}

	public static GTreeNode getNode(GTree tree, String... path) {
		GTreeNode rootNode = tree.getModelRoot();
		String rootName = path[0];
		if (!rootNode.getName().equals(rootName)) {
			throw new RuntimeException(
				"When selecting paths by name the first path element must be the " +
					"name of the root node - path: " + StringUtils.join(path, '.'));
		}
		GTreeNode node = rootNode;
		for (int i = 1; i < path.length; i++) {
			GTreeNode child = node.getChild(path[i]);
			if (child == null) {
				return null; // not in the tree
			}
			node = child;
		}
		return node;
	}
}
