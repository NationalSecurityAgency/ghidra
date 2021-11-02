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
package ghidra.app.plugin.core.datamgr;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;

import java.awt.Container;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.io.File;
import java.io.FileNotFoundException;
import java.net.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.*;
import javax.swing.tree.DefaultTreeCellEditor;
import javax.swing.tree.TreePath;

import org.junit.*;

import docking.DialogComponentProvider;
import docking.DockingUtils;
import docking.action.DockingActionIf;
import docking.action.ToggleDockingActionIf;
import docking.actions.KeyBindingUtils;
import docking.tool.ToolConstants;
import docking.tool.util.DockingToolConstants;
import docking.widgets.OptionDialog;
import docking.widgets.dialogs.NumberRangeInputDialog;
import docking.widgets.tree.GTreeNode;
import ghidra.app.context.ProgramActionContext;
import ghidra.app.plugin.core.compositeeditor.ApplyAction;
import ghidra.app.plugin.core.compositeeditor.CompositeEditorTableAction;
import ghidra.app.plugin.core.datamgr.actions.*;
import ghidra.app.plugin.core.datamgr.archive.Archive;
import ghidra.app.plugin.core.datamgr.archive.DataTypeManagerHandler;
import ghidra.app.plugin.core.datamgr.tree.*;
import ghidra.app.plugin.core.function.AbstractEditFunctionSignatureDialog;
import ghidra.app.plugin.core.programtree.ProgramTreePlugin;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.datatype.DataTypeSelectionEditor;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.data.ProgramDataTypeManager;
import ghidra.program.model.data.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import util.CollectionUtils;
import utilities.util.FileUtilities;

/**
 * Tests for managing categories through the data manager plugin and tests for
 * actions being enabled when a node is selected.
 */

public class DataTypeManagerPluginTest extends AbstractGhidraHeadedIntegrationTest {
	private static final String BUILTIN_NAME = "BuiltInTypes";
	private static final String PROGRAM_FILENAME = "sample";

	private TestEnv env;
	private PluginTool tool;
	private ProgramBuilder builder;
	private ProgramDB program;
	private DataTypeManagerPlugin plugin;
	private DataTypeArchiveGTree tree;
	private JTree jTree;
	private ProgramActionContext treeContext;

	private ArchiveNode programNode;
	private DockingActionIf cutAction;
	private DockingActionIf pasteAction;
	private DataTypesProvider provider;

	@Before
	public void setUp() throws Exception {

		removeBinTestDir();

		env = new TestEnv();
		program = buildProgram();
		tool = env.launchDefaultTool(program);

		plugin = env.getPlugin(DataTypeManagerPlugin.class);
		provider = plugin.getProvider();
		tree = provider.getGTree();
		jTree = (JTree) invokeInstanceMethod("getJTree", tree);
		waitForTree();
		ArchiveRootNode archiveRootNode = (ArchiveRootNode) tree.getModelRoot();
		programNode = (ArchiveNode) archiveRootNode.getChild(PROGRAM_FILENAME);
		assertNotNull("Did not successfully wait for the program node to load", programNode);

		tool.showComponentProvider(provider, true);

		treeContext = new DataTypesActionContext(provider, program, tree, null);

		removeDistractingPlugins();
	}

	private void removeDistractingPlugins() {

		// cleanup the display a bit
		ProgramTreePlugin ptp = env.getPlugin(ProgramTreePlugin.class);
		tool.removePlugins(new Plugin[] { ptp });
	}

	private ProgramDB buildProgram() throws Exception {
		builder = new ProgramBuilder("sample", ProgramBuilder._TOY, this);

		builder.createMemory(".text", "0x1001000", 0x100);
		CategoryPath miscPath = new CategoryPath("/MISC");
		builder.addCategory(miscPath);
		StructureDataType struct = new StructureDataType("ArrayStruct", 4);
		struct.setCategoryPath(miscPath);
		builder.addDataType(struct);
		UnionDataType union = new UnionDataType("ArrayUnion");
		union.setCategoryPath(miscPath);
		union.add(new ByteDataType());
		builder.addDataType(union);

		CategoryPath cat1Path = new CategoryPath("/Category1");
		builder.addCategory(cat1Path);
		CategoryPath cat2Path = new CategoryPath(cat1Path, "Category2");
		builder.addCategory(cat2Path);
		CategoryPath cat4Path = new CategoryPath(cat2Path, "Category4");
		builder.addCategory(cat4Path);
		builder.addCategory(new CategoryPath(cat2Path, "Category5"));

		CategoryPath cat3Path = new CategoryPath(cat2Path, "Category3");
		builder.addCategory(cat3Path);
		StructureDataType dt = new StructureDataType("IntStruct", 0);
		dt.add(new WordDataType());
		dt.setCategoryPath(cat3Path);
		builder.addDataType(dt);

		dt = new StructureDataType("CharStruct", 0);
		dt.add(new CharDataType());
		dt.setCategoryPath(cat4Path);
		builder.addDataType(dt);

		StructureDataType dllTable = new StructureDataType("DLL_Table", 0);
		dllTable.add(new WordDataType());
		builder.addDataType(dllTable);

		StructureDataType myStruct = new StructureDataType("MyStruct", 0);
		myStruct.add(new ByteDataType(), "struct_field_names", null);
		myStruct.setCategoryPath(cat2Path);
		builder.addDataType(myStruct);

		return builder.getProgram();
	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
		removeBinTestDir();
	}

	@Test
	public void testInvalidArchive() throws Exception {
		final DataTypeManagerHandler managerHandler = plugin.getDataTypeManagerHandler();
		final String[] invalidNames = { "BADARCHIVENAME.gdt" };
		runSwing(() -> invokeInstanceMethod("openArchives", managerHandler,
			new Class[] { String[].class }, new Object[] { invalidNames }));

		GTreeNode rootNode = tree.getModelRoot();
		GTreeNode invalidChild = rootNode.getChild("BADARCHIVENAME");
		assertNull("Tree did not close invalid archive.", invalidChild);
	}

	@Test
	public void testCreateCategory() throws Exception {
		// select a category
		GTreeNode miscNode = programNode.getChild("MISC");
		assertNotNull(miscNode);
		expandNode(miscNode);

		int childCount = miscNode.getChildCount();
		selectNode(miscNode);

		final DockingActionIf action = getAction(plugin, "New Category");
		assertTrue(action.isEnabledForContext(treeContext));

		// select "New Category" action
		DataTypeTestUtils.performAction(action, tree, false);

		runSwing(() -> jTree.stopEditing());
		waitForSwing();

		waitForTree();

		// verify that  the tree opens a new node with the default
		// category name is "New Category"
		assertEquals(childCount + 1, miscNode.getChildCount());
		GTreeNode node = miscNode.getChild("New Category");
		assertNotNull(node);
	}

	@Test
	public void testCreateCategory_WhileFiltered() throws Exception {
		// select a category
		GTreeNode miscNode = programNode.getChild("MISC");
		assertNotNull(miscNode);
		expandNode(miscNode);

		int childCount = miscNode.getChildCount();
		selectNode(miscNode);

		filterTree(miscNode.getName());

		DockingActionIf action = getAction(plugin, "New Category");
		assertTrue(action.isEnabledForContext(treeContext));

		// select "New Category" action
		DataTypeTestUtils.performAction(action, tree, false);

		DialogComponentProvider dialog = waitForDialogComponent("Cannot Edit Tree Node");
		close(dialog);

		// verify that  the tree opens a new node with the default category name is "New Category"
		assertEquals(childCount + 1, miscNode.getChildCount());
		GTreeNode node = miscNode.getChild("New Category");
		assertNotNull(node);
	}

	@Test
	public void testCreatePointerFromBuiltin() throws Exception {
		//
		// Test that creating a pointer to a built-in type will put that pointer in the program's
		// archive
		//
		disablePointerFilter();// make sure our new type is not filtered out

		ArchiveNode builtInNode = getBuiltInNode();
		expandNode(builtInNode);
		String boolNodeName = "bool";
		GTreeNode boolNode = builtInNode.getChild(boolNodeName);
		assertNotNull(boolNode);
		selectNode(boolNode);

		final DockingActionIf action = getAction(plugin, "Create Pointer");
		assertTrue(action.isEnabledForContext(treeContext));
		performAction(action, treeContext, true);
		waitForSwing();// the action uses an invokeLater()
		waitForTree();

		final AtomicReference<GTreeNode> selectedNodeReference = new AtomicReference<>();
		runSwing(() -> {
			TreePath selectionPath = tree.getSelectionPath();
			GTreeNode selectedNode = (GTreeNode) selectionPath.getLastPathComponent();
			selectedNodeReference.set(selectedNode);
		});

		GTreeNode selectedNode = selectedNodeReference.get();
		assertNotNull(selectedNode);
		assertEquals(boolNodeName + " *", selectedNode.getName());
	}

	@Test
	public void testCreateTypeDefFromDialog() throws Exception {
		// select a category - this will be the parent category
		expandNode(programNode);
		String miscNodeName = "MISC";
		final CategoryNode miscNode = (CategoryNode) programNode.getChild(miscNodeName);
		assertNotNull(miscNode);
		expandNode(miscNode);
		selectNode(miscNode);

		final DockingActionIf action = getAction(plugin, "Create Typedef From Dialog");
		assertTrue(action.isEnabledForContext(treeContext));
		performAction(action, treeContext, false);

		//
		// Grab the dialog and set:
		// -the name
		// -the data type
		//
		CreateTypeDefDialog dialog = waitForDialogComponent(CreateTypeDefDialog.class);

		String newTypeDefName = "TestTypeDef";
		JTextField textField = (JTextField) getInstanceField("nameTextField", dialog);
		setText(textField, newTypeDefName);

		final String dataTypeText = "char *";
		final DataTypeSelectionEditor editor =
			(DataTypeSelectionEditor) getInstanceField("dataTypeEditor", dialog);
		runSwing(() -> editor.setCellEditorValueAsText(dataTypeText));

		JButton okButton = (JButton) getInstanceField("okButton", dialog);
		pressButton(okButton);

		waitForTree();
		TreePath[] selectionPaths = tree.getSelectionPaths();
		assertNotNull(selectionPaths);
		assertEquals(1, selectionPaths.length);

		TreePath treePath = selectionPaths[0];
		GTreeNode selectedNode = (GTreeNode) treePath.getLastPathComponent();
		String selectedNodeName = selectedNode.getName();
		assertEquals(newTypeDefName, selectedNodeName);
	}

	@Test
	public void testRenameCategory() throws Exception {
		// select a category
		expandNode(programNode);
		String miscNodeName = "MISC";
		final CategoryNode miscNode = (CategoryNode) programNode.getChild(miscNodeName);
		assertNotNull(miscNode);
		expandNode(miscNode);
		selectNode(miscNode);

		final DockingActionIf action = getAction(plugin, "Rename");
		assertTrue(action.isEnabledForContext(treeContext));

		// select "Rename" action
		final String newCategoryName = "My Misc Category";
		DataTypeTestUtils.performAction(action, tree);
		waitForTree();
		runSwing(() -> {
			int rowForPath = jTree.getRowForPath(miscNode.getTreePath());

			DefaultTreeCellEditor cellEditor = (DefaultTreeCellEditor) tree.getCellEditor();
			Container container = (Container) cellEditor.getTreeCellEditorComponent(jTree, miscNode,
				true, true, true, rowForPath);
			JTextField textField = (JTextField) container.getComponent(0);

			textField.setText(newCategoryName);
			jTree.stopEditing();
		});
		waitForProgram();
		waitForTree();

		// make sure the new node is selected
		TreePath[] selectionPaths = tree.getSelectionPaths();
		assertNotNull(selectionPaths);
		assertEquals(1, selectionPaths.length);

		CategoryNode newMiscNode = (CategoryNode) programNode.getChild(newCategoryName);
		GTreeNode selectedNode = (GTreeNode) selectionPaths[0].getLastPathComponent();
		assertEquals(newMiscNode, selectedNode);

		assertEquals("My Misc Category", newMiscNode.getName());
		Category c = getRootCategory().getCategory(newCategoryName);
		assertNotNull(c);
		assertEquals(newMiscNode.getCategory(), c);
		assertNull(programNode.getChild(miscNodeName));

		// undo
		undo();

		assertNotNull(programNode.getChild(miscNodeName));
		assertNull(programNode.getChild(newCategoryName));

		// redo
		redo();

		assertNull(programNode.getChild(miscNodeName));
		assertNotNull(programNode.getChild(newCategoryName));
	}

	@Test
	public void testRenameCategoryDuplicate() throws Exception {
		expandNode(programNode);
		String miscNodeName = "MISC";
		final CategoryNode miscNode = (CategoryNode) programNode.getChild(miscNodeName);
		assertNotNull(miscNode);
		expandNode(miscNode);
		selectNode(miscNode);

		final DockingActionIf action = getAction(plugin, "Rename");
		assertTrue(action.isEnabledForContext(treeContext));
		DataTypeTestUtils.performAction(action, tree);
		waitForTree();
		runSwingLater(() -> {
			TreePath editingPath = jTree.getEditingPath();
			GTreeNode editingNode = (GTreeNode) editingPath.getLastPathComponent();
			int rowForPath = jTree.getRowForPath(editingPath);

			DefaultTreeCellEditor cellEditor = (DefaultTreeCellEditor) tree.getCellEditor();
			Container container = (Container) cellEditor.getTreeCellEditorComponent(jTree,
				editingNode, true, true, true, rowForPath);
			JTextField textField = (JTextField) container.getComponent(0);

			textField.setText("Category1");
			jTree.stopEditing();
		});

		close(waitForErrorDialog());
		waitForSwing();

		assertFalse(jTree.isEditing());
	}

	@Test
	public void testCopyCategory2DataType() throws Exception {
		// not allowed in the same data type manager
		GTreeNode cat1Node = programNode.getChild("Category1");
		expandNode(cat1Node);

		GTreeNode cat2Node = cat1Node.getChild("Category2");
		expandNode(cat2Node);

		GTreeNode cat5Node = cat2Node.getChild("Category5");
		expandNode(cat5Node);
		selectNode(cat5Node);

		DockingActionIf copyAction = getAction(plugin, "Copy");
		assertTrue(copyAction.isEnabledForContext(treeContext));

		GTreeNode miscNode = programNode.getChild("MISC");
		expandNode(miscNode);
		DataTypeNode unionNode = (DataTypeNode) miscNode.getChild("ArrayUnion");
		selectNode(unionNode);

		pasteAction = getAction(plugin, "Paste");
		assertFalse(pasteAction.isEnabledForContext(treeContext));
	}

	@Test
	public void testDeleteCategoryInProgram() throws Exception {
		// delete category from the Program
		// delete Category4
		GTreeNode cat1Node = programNode.getChild("Category1");
		expandNode(cat1Node);

		CategoryNode cat2Node = (CategoryNode) cat1Node.getChild("Category2");
		expandNode(cat2Node);

		GTreeNode cat4Node = cat2Node.getChild("Category4");
		selectNode(cat4Node);

		final DockingActionIf action = getAction(plugin, "Delete");
		assertTrue(action.isEnabledForContext(treeContext));

		DataTypeTestUtils.performAction(action, tree, false);

		// hit the Yes button the dialog
		pressButtonOnOptionDialog("Yes");

		// must again retrieve the nodes after a delete, as the old nodes are disposed
		cat1Node = programNode.getChild("Category1");
		cat2Node = (CategoryNode) cat1Node.getChild("Category2");
		assertNull(cat2Node.getChild("Category4"));
		ArrayList<DataType> list = new ArrayList<>();
		Archive archive = cat2Node.getArchiveNode().getArchive();
		archive.getDataTypeManager().findDataTypes("CharStruct", list);
		assertEquals(0, list.size());

		undo();

		cat1Node = programNode.getChild("Category1");
		cat2Node = (CategoryNode) cat1Node.getChild("Category2");
		assertNotNull(cat2Node.getChild("Category4"));

		redo();

		cat1Node = programNode.getChild("Category1");
		cat2Node = (CategoryNode) cat1Node.getChild("Category2");
		assertNull(cat2Node.getChild("Category4"));
	}

	@Test
	public void testDeleteCategoryInProgram2() throws Exception {
		// delete category from the Program
		// delete Category2 from Category1
		CategoryNode cat1Node = (CategoryNode) programNode.getChild("Category1");
		expandNode(cat1Node);

		CategoryNode cat2Node = (CategoryNode) cat1Node.getChild("Category2");
		selectNode(cat2Node);

		final DockingActionIf action = getAction(plugin, "Delete");
		assertTrue(action.isEnabledForContext(treeContext));

		DataTypeTestUtils.performAction(action, tree, false);
		waitForSwing();

		// hit the Yes button the dialog
		pressButtonOnOptionDialog("Yes");

		// must again retrieve the nodes after a delete, as the old nodes are disposed
		cat1Node = (CategoryNode) programNode.getChild("Category1");
		cat2Node = (CategoryNode) cat1Node.getChild("Category2");
		assertNull(cat1Node.getChild("Category2"));
		ArrayList<DataType> list = new ArrayList<>();
		Archive archive = cat1Node.getArchiveNode().getArchive();
		archive.getDataTypeManager().findDataTypes("CharStruct", list);
		assertEquals(0, list.size());
		archive.getDataTypeManager().findDataTypes("IntStruct", list);

		undo();

		cat1Node = (CategoryNode) programNode.getChild("Category1");
		cat2Node = (CategoryNode) cat1Node.getChild("Category2");
		assertNotNull(cat2Node);
		list = new ArrayList<>();
		archive = cat1Node.getArchiveNode().getArchive();
		archive.getDataTypeManager().findDataTypes("CharStruct", list);
		assertEquals(1, list.size());
		list.clear();
		archive.getDataTypeManager().findDataTypes("IntStruct", list);
		assertEquals(1, list.size());

		redo();

		cat1Node = (CategoryNode) programNode.getChild("Category1");
		assertNull(cat1Node.getChild("Category2"));
		list = new ArrayList<>();
		archive = cat1Node.getArchiveNode().getArchive();
		archive.getDataTypeManager().findDataTypes("CharStruct", list);
		assertEquals(0, list.size());
		archive.getDataTypeManager().findDataTypes("IntStruct", list);
	}

	@Test
	public void testBuiltInCategoryForDataTypes() throws Exception {
		// verify that you cannot cut/paste data types to built in types category
		GTreeNode cat1Node = programNode.getChild("Category1");
		expandNode(cat1Node);

		GTreeNode cat2Node = cat1Node.getChild("Category2");
		expandNode(cat2Node);

		DataTypeNode myStructNode = (DataTypeNode) cat2Node.getChild("MyStruct");

		GTreeNode rootNode = tree.getModelRoot();
		GTreeNode builtInNode = rootNode.getChild("BuiltInTypes");

		selectNode(myStructNode);

		DockingActionIf copyAction = getAction(plugin, "Copy");
		cutAction = getAction(plugin, "Cut");
		pasteAction = getAction(plugin, "Paste");

		assertTrue(cutAction.isEnabledForContext(treeContext));
		assertTrue(copyAction.isEnabledForContext(treeContext));

		DataTypeTestUtils.performAction(cutAction, tree, false);

		selectNode(builtInNode);
		assertFalse(pasteAction.isEnabledForContext(treeContext));
	}

	@Test
	public void testBuiltInCategoryForCategories() throws Exception {
		// verify that you cannot cut/paste other categories to the built in types category
		GTreeNode cat1Node = programNode.getChild("Category1");
		expandNode(cat1Node);

		GTreeNode cat2Node = cat1Node.getChild("Category2");
		expandNode(cat2Node);

		GTreeNode rootNode = tree.getModelRoot();
		GTreeNode builtInNode = rootNode.getChild("BuiltInTypes");

		selectNode(cat2Node);

		DockingActionIf copyAction = getAction(plugin, "Copy");
		cutAction = getAction(plugin, "Cut");
		pasteAction = getAction(plugin, "Paste");

		assertTrue(cutAction.isEnabledForContext(treeContext));
		assertTrue(copyAction.isEnabledForContext(treeContext));

		DataTypeTestUtils.performAction(cutAction, tree);

		selectNode(builtInNode);
		assertFalse(pasteAction.isEnabledForContext(treeContext));
	}

	@Test
	public void testCloseProgram() throws Exception {

		runSwing(() -> {
			ProgramManager pm = tool.getService(ProgramManager.class);
			pm.closeProgram();
		});
		GTreeNode rootNode = tree.getModelRoot();
		assertEquals(1, rootNode.getChildCount());
	}

	@Test
	public void testExpandAll() throws Exception {

		GTreeNode rootNode = tree.getModelRoot();
		selectNode(rootNode);
		DockingActionIf expandAction = getAction(plugin, "Expand All");
		assertTrue(expandAction.isEnabledForContext(treeContext));
		DataTypeTestUtils.performAction(expandAction, tree);

		waitForTree();

		//verify all nodes are expanded
		checkNodesExpanded(rootNode);
	}

	@Test
	public void testDetailedSearch() throws Exception {
		toggleDetailedSearch(false);
		filterTree("struct_field_name");
		assertEmptyTree();

		toggleDetailedSearch(true);
		assertSingleFilterMatch(
			new String[] { "Data Types", "sample", "Category1", "Category2", "MyStruct" });
	}

	@Test
	public void testCollapseAll() throws Exception {

		GTreeNode rootNode = tree.getModelRoot();
		selectNode(rootNode);
		DockingActionIf collapseAction = getAction(plugin, "Collapse All");
		assertTrue(collapseAction.isEnabledForContext(treeContext));
		DataTypeTestUtils.performAction(collapseAction, tree);

		//verify all nodes are collapsed
		checkNodesCollapsed(rootNode);
	}

	@Test
	public void testSaveRestoreFilterStates() throws Exception {
		final ToggleDockingActionIf arraysAction =
			(ToggleDockingActionIf) getAction(plugin, "Filter Arrays");
		assertTrue(arraysAction.isSelected());
		arraysAction.setSelected(false);
		DataTypeTestUtils.performAction(arraysAction, tree);

		// state is off
		final ToggleDockingActionIf pointerAction =
			(ToggleDockingActionIf) getAction(plugin, "Filter Pointers");
		assertTrue(pointerAction.isSelected());

		pointerAction.setSelected(false);
		DataTypeTestUtils.performAction(pointerAction, tree, false);

		// state is off
		env.saveRestoreToolState();
		plugin = env.getPlugin(DataTypeManagerPlugin.class);
		ToggleDockingActionIf action = (ToggleDockingActionIf) getAction(plugin, "Filter Arrays");
		assertFalse(action.isSelected());
		action = (ToggleDockingActionIf) getAction(plugin, "Filter Pointers");
		assertFalse(action.isSelected());
	}

	@Test
	public void testDataTypePreviewCopyHtmlText() throws Exception {

		openPreview();

		GTreeNode bNode = programNode.getChild("DLL_Table");
		assertNotNull(bNode);
		selectNode(bNode);

		String previewText = getPreviewText();
		assertThat(previewText, startsWith("<html>"));

		selectEntirePreview();

		boolean actionFired = copyPreviewViaKeyMapping();
		assertTrue(actionFired);
	}

	@Test
	public void testEditFunctionDefintionDataType() throws Exception {
		createFunctionDefinition("Bob", "Joe"); // creates function definition for "undefined Bob(byte Joe)" 
		FunctionDefinition fun = getFunctionDefinition("Bob");
		assertParamName(fun, 0, "Joe");
		editSignature("Bob", "int Bob(long aaa, ...)");
		fun = getFunctionDefinition("Bob");
		assertParamName(fun, 0, "aaa");
		assertParamType(fun, 0, new LongDataType());
		assertEquals(IntegerDataType.class, fun.getReturnType().getClass());
		assertTrue(fun.hasVarArgs());
	}

	@Test
	public void testEditFunctionDefintionName() throws Exception {
		createFunctionDefinition("Bob", "Joe"); // creates function definition for "undefined Bob(byte Joe)" 
		FunctionDefinition fun = getFunctionDefinition("Bob");
		assertParamName(fun, 0, "Joe");
		editSignature("Bob", "undefined Tom(byte Joe)");
		DataType dt = program.getDataTypeManager().getDataType("/Bob");
		assertNull(dt);
		fun = getFunctionDefinition("Tom");
		assertNotNull(fun);
	}

	@Test
	public void testEditFunctionDefintionDataTypeParamNameOnly() throws Exception {
		createFunctionDefinition("Bob", "Joe"); // creates function definition for "undefined Bob(byte Joe)" 
		FunctionDefinition fun = getFunctionDefinition("Bob");
		assertParamName(fun, 0, "Joe");
		editSignature("Bob", "undefined Bob(byte Tom)");
		fun = getFunctionDefinition("Bob");
		assertParamName(fun, 0, "Tom");
	}

	@Test
	public void testEditingFunctionDefinitionWithNullParamName() {
		createFunctionDefinition("Bob", (String) null);
		FunctionDefinition fun = getFunctionDefinition("Bob");
		assertEquals("", fun.getArguments()[0].getName());
	}

	@Test
	public void testEditingFunctionDefinitionWithVariousParameterNames() {
		createFunctionDefinition("Bob", (String) null, "", "Tom");
		FunctionDefinition fun = getFunctionDefinition("Bob");
		assertEquals("", fun.getArguments()[0].getName());
		assertEquals("", fun.getArguments()[1].getName());
		assertEquals("Tom", fun.getArguments()[2].getName());
	}

	@Test
	public void testEditorActionsGetRegisteredWithoutEditing() {

		// the owner for the action is the tool, since the registered item is just a placeholder
		// because the editor actions are shared actions
		String owner = " (" + ToolConstants.SHARED_OWNER + ')';
		String actionName = CompositeEditorTableAction.EDIT_ACTION_PREFIX + ApplyAction.ACTION_NAME;
		String optionName = actionName + owner;
		ToolOptions options = tool.getOptions(DockingToolConstants.KEY_BINDINGS);

		String message = "Editor action was not registered before editor was shown";
		assertTrue(message, options.isRegistered(optionName));

		DockingActionIf action = getAction(tool, ToolConstants.SHARED_OWNER, actionName);
		assertNotNull(message, action);
	}

	@Test
	public void testAction_FindStructureByOffset() {

		DockingActionIf action = getAction(plugin, FindStructuresByOffsetAction.NAME);
		performAction(action, false);

		NumberRangeInputDialog dialog = waitForDialogComponent(NumberRangeInputDialog.class);
		setText(dialog, "0x1");

		pressButtonByText(dialog, "OK");

		DataTypesProvider resultsProvider = waitForComponentProvider(DataTypesProvider.class,
			FindStructuresByOffsetAction.NAME);
		assertMatchingStructures(resultsProvider, "ArrayStruct");
	}

	@Test
	public void testAction_FindStructureByOffset_NoMatches() {

		DockingActionIf action = getAction(plugin, FindStructuresByOffsetAction.NAME);
		performAction(action, false);

		NumberRangeInputDialog dialog = waitForDialogComponent(NumberRangeInputDialog.class);
		setText(dialog, "0x100");

		pressButtonByText(dialog, "OK");

		DataTypesProvider resultsProvider = waitForComponentProvider(DataTypesProvider.class,
			FindStructuresByOffsetAction.NAME);
		assertMatchingStructures(resultsProvider);
	}

	@Test
	public void testAction_FindStructureByOffset_Range() {

		DockingActionIf action = getAction(plugin, FindStructuresByOffsetAction.NAME);
		performAction(action, false);

		NumberRangeInputDialog dialog = waitForDialogComponent(NumberRangeInputDialog.class);
		setText(dialog, "0x1:0x3,20");

		pressButtonByText(dialog, "OK");

		DataTypesProvider resultsProvider = waitForComponentProvider(DataTypesProvider.class,
			FindStructuresByOffsetAction.NAME);
		assertMatchingStructures(resultsProvider, "ArrayStruct");
	}

	@Test
	public void testAction_FindStructureByOffset_MixedInput() {

		createStructureWithOffset_0x4(); // 0x4
		createStructureWithOffset_0x8(); // 0x4, 0x8
		createStructureWithOffset_0x10(); // 0x4, 0x8, 0x10
		createStructureWithOffset_0x20(); // 0x8, 0x16, 0x20

		DockingActionIf action = getAction(plugin, FindStructuresByOffsetAction.NAME);
		performAction(action, false);

		NumberRangeInputDialog dialog = waitForDialogComponent(NumberRangeInputDialog.class);
		setText(dialog, "0x8:0x10, 32");

		pressButtonByText(dialog, "OK");

		DataTypesProvider resultsProvider = waitForComponentProvider(DataTypesProvider.class,
			FindStructuresByOffsetAction.NAME);
		assertMatchingStructures(resultsProvider, "Structure_0x8", "Structure_0x10",
			"Structure_0x20");
	}

	@Test
	public void testAction_FindStructureBySize() {

		createStructureWithOffset_0x4(); // 6
		createStructureWithOffset_0x8(); // 10
		createStructureWithOffset_0x10(); // 12
		createStructureWithOffset_0x20(); // 22

		DockingActionIf action = getAction(plugin, FindStructuresBySizeAction.NAME);
		performAction(action, false);

		NumberRangeInputDialog dialog = waitForDialogComponent(NumberRangeInputDialog.class);
		setText(dialog, "10");

		pressButtonByText(dialog, "OK");

		DataTypesProvider resultsProvider = waitForComponentProvider(DataTypesProvider.class,
			FindStructuresBySizeAction.NAME);
		assertMatchingStructures(resultsProvider, "Structure_0x8");
	}

	@Test
	public void testAction_FindStructureBySize_Ranage() {

		createStructureWithOffset_0x4(); // 6
		createStructureWithOffset_0x8(); // 10
		createStructureWithOffset_0x10(); // 12
		createStructureWithOffset_0x20(); // 22

		DockingActionIf action = getAction(plugin, FindStructuresBySizeAction.NAME);
		performAction(action, false);

		NumberRangeInputDialog dialog = waitForDialogComponent(NumberRangeInputDialog.class);
		setText(dialog, "12:22");

		pressButtonByText(dialog, "OK");

		DataTypesProvider resultsProvider = waitForComponentProvider(DataTypesProvider.class,
			FindStructuresBySizeAction.NAME);
		assertMatchingStructures(resultsProvider, "Structure_0x10", "Structure_0x20");
	}

//==================================================================================================
// Private methods
//==================================================================================================

	private void createStructureWithOffset_0x4() {

		StructureDataType stuct = new StructureDataType("Structure_0x4", 0);
		stuct.add(new DWordDataType());
		stuct.add(new WordDataType());
		builder.addDataType(stuct);
	}

	private void createStructureWithOffset_0x8() {

		StructureDataType stuct = new StructureDataType("Structure_0x8", 0);
		stuct.add(new DWordDataType());
		stuct.add(new DWordDataType());
		stuct.add(new WordDataType());
		builder.addDataType(stuct);
	}

	private void createStructureWithOffset_0x10() {

		StructureDataType stuct = new StructureDataType("Structure_0x10", 0);
		stuct.add(new DWordDataType());
		stuct.add(new DWordDataType());
		stuct.add(new WordDataType());
		stuct.add(new WordDataType());
		builder.addDataType(stuct);
	}

	private void createStructureWithOffset_0x20() {

		StructureDataType stuct = new StructureDataType("Structure_0x20", 0);
		stuct.add(new QWordDataType());
		stuct.add(new QWordDataType());
		stuct.add(new DWordDataType());
		stuct.add(new WordDataType());
		builder.addDataType(stuct);
	}

	private void setText(NumberRangeInputDialog dialog, String text) {
		runSwing(() -> dialog.setValue(text));
	}

	private void editSignature(String name, String newSignature) {
		expandNode(programNode);
		GTreeNode child = programNode.getChild(name);
		selectNode(child);
		final DockingActionIf action = getAction(plugin, "Edit");
		assertTrue(action.isEnabledForContext(treeContext));
		performAction(action, treeContext, false);

		AbstractEditFunctionSignatureDialog dialog =
			waitForDialogComponent(AbstractEditFunctionSignatureDialog.class);

		JTextField textField = (JTextField) getInstanceField("signatureField", dialog);
		setText(textField, newSignature);
		pressButtonByText(dialog, "OK");

	}

	private void assertParamName(FunctionDefinition fun, int index, String name) {
		ParameterDefinition param = fun.getArguments()[index];
		assertEquals(name, param.getName());
	}

	private void assertParamType(FunctionDefinition fun, int index, DataType dt) {
		ParameterDefinition param = fun.getArguments()[index];
		assertEquals(dt.getClass(), param.getDataType().getClass());
	}

	private FunctionDefinition getFunctionDefinition(String name) {
		ProgramDataTypeManager dataTypeManager = program.getDataTypeManager();
		DataType dataType = dataTypeManager.getDataType("/" + name);
		assertTrue(dataType instanceof FunctionDefinition);
		return (FunctionDefinition) dataType;
	}

	private void createFunctionDefinition(String functionName, String... paramNames) {
		ProgramDataTypeManager dataTypeManager = program.getDataTypeManager();
		int id = dataTypeManager.startTransaction("test");
		FunctionDefinitionDataType dt = new FunctionDefinitionDataType(functionName);
		ParameterDefinition[] args = new ParameterDefinition[paramNames.length];
		for (int i = 0; i < paramNames.length; i++) {
			args[i] = new ParameterDefinitionImpl(paramNames[i], new ByteDataType(), null);
		}
		dt.setArguments(args);
		dataTypeManager.addDataType(dt, null);
		dataTypeManager.endTransaction(id, true);
	}

	private void selectEntirePreview() {
		runSwing(() -> {
			JTextPane pane = provider.getPreviewPane();
			// note: the selectAll only works when the caret selection is visible (this normally
			//       happens when the component has focus)
			pane.getCaret().setSelectionVisible(true);
			pane.selectAll();
		});
		waitForSwing();
	}

	private boolean copyPreviewViaKeyMapping() throws Exception {

		KeyStroke controlC =
			KeyStroke.getKeyStroke(KeyEvent.VK_C, DockingUtils.CONTROL_KEY_MODIFIER_MASK);
		JTextPane previewPane = provider.getPreviewPane();
		Action defaultAction =
			KeyBindingUtils.getAction(previewPane, controlC, JComponent.WHEN_FOCUSED);

		SpyAction spyAction = new SpyAction(defaultAction);

		KeyBindingUtils.registerAction(previewPane, controlC, spyAction, JComponent.WHEN_FOCUSED);

		triggerKey(previewPane, DockingUtils.CONTROL_KEY_MODIFIER_MASK, KeyEvent.VK_C, 'c');
		waitForSwing();

		return spyAction.actionFired();
	}

	private String getPreviewText() {
		AtomicReference<String> ref = new AtomicReference<>();
		runSwing(() -> ref.set(provider.getPreviewText()));
		return ref.get();
	}

	private void openPreview() {
		runSwing(() -> provider.setPreviewWindowVisible(true));
	}

	private ArchiveNode getBuiltInNode() {
		ArchiveRootNode archiveRootNode = (ArchiveRootNode) tree.getModelRoot();
		ArchiveNode builtinNode = (ArchiveNode) archiveRootNode.getChild(BUILTIN_NAME);
		assertNotNull(builtinNode);
		return builtinNode;
	}

	private void assertSingleFilterMatch(String[] path) {
		GTreeNode rootNode = tree.getViewRoot();

		GTreeNode node = rootNode;
		for (int i = 0; i < path.length; i++) {
			String nodeName = path[i];
			assertEquals(node.getName(), nodeName);

			final GTreeNode finalNode = node;
			final GTreeNode[] childBox = new GTreeNode[1];
			runSwing(() -> {
				int childCount = finalNode.getChildCount();
				if (childCount == 1) {
					childBox[0] = finalNode.getChild(0);
				}
			});

			if (i + 1 < path.length) {
				String expectedChild = path[i + 1];
				assertNotNull("Parent '" + node.getName() + "' did not have child " + expectedChild,
					childBox[0]);
				node = childBox[0];
			}
		}
	}

	private void assertMatchingStructures(DataTypesProvider resultsProvider, String... names) {

		DataTypeArchiveGTree gTree = resultsProvider.getGTree();
		waitForTree(gTree);
		Map<String, Structure> structures = getStructures(resultsProvider);
		assertEquals("Incorrect number of matches.\n\tExpected: " + Arrays.toString(names) +
			"\n\tFound: " + structures.keySet(), names.length, structures.size());
		for (String name : names) {
			if (!structures.containsKey(name)) {
				fail("Structure not found in results: '" + name + "'.\nFound: " +
					structures.keySet());
			}
		}
	}

	private Map<String, Structure> getStructures(DataTypesProvider resultsProvider) {

		Map<String, Structure> map = new HashMap<>();
		DataTypeArchiveGTree gTree = resultsProvider.getGTree();
		GTreeNode rootNode = gTree.getViewRoot();
		Iterator<GTreeNode> it = rootNode.iterator(true);
		for (GTreeNode node : CollectionUtils.asIterable(it)) {
			if (!(node instanceof DataTypeNode)) {
				continue;
			}
			DataTypeNode dtNode = (DataTypeNode) node;
			DataType dt = dtNode.getDataType();
			if (dt instanceof Structure) {
				map.put(dt.getName(), (Structure) dt);
			}
		}

		return map;
	}

	private void assertEmptyTree() {
		final GTreeNode rootNode = tree.getViewRoot();
		final Integer[] box = new Integer[1];
		runSwing(() -> box[0] = rootNode.getChildCount());
		assertEquals("Root node is not empty as expected", 0, (int) box[0]);
	}

	private void filterTree(String text) {
		tree.setFilterText(text);
		waitForTree();
	}

	private void toggleDetailedSearch(final boolean enable) {
		final DockingActionIf includeDataMembersAction =
			getAction(plugin, "Include Data Members in Filter");
		runSwing(() -> {
			ToggleDockingActionIf toggleAction = (ToggleDockingActionIf) includeDataMembersAction;
			toggleAction.setSelected(enable);
		});
		waitForTree();
	}

	private void disablePointerFilter() {
		DockingActionIf filterPointersAction = getAction(plugin, "Filter Pointers");
		ToggleDockingActionIf toggleAction = (ToggleDockingActionIf) filterPointersAction;
		setToggleActionSelected(toggleAction, treeContext, false);
		waitForTree();
	}

	private void undo() throws Exception {
		runSwing(() -> {
			try {
				program.undo();
				program.flushEvents();
			}
			catch (Exception e) {
				failWithException("Exception performing undo", e);
			}
		});
		waitForTasks();
		waitForTree();
	}

	private void redo() throws Exception {
		runSwing(() -> {
			try {
				program.redo();
				program.flushEvents();
			}
			catch (Exception e) {
				failWithException("Exception performing undo", e);
			}
		});
		waitForTasks();
		waitForTree();
	}

	private void pressButtonOnOptionDialog(String buttonName) throws Exception {
		OptionDialog d = waitForDialogComponent(OptionDialog.class);
		assertNotNull(d);
		JButton button = findButtonByText(d, buttonName);
		assertNotNull(button);
		runSwing(() -> button.doClick());
		waitForProgram();
	}

	private void waitForProgram() throws Exception {
		program.flushEvents();
		waitForTasks();
	}

	private Category getRootCategory() {
		return program.getListing().getDataTypeManager().getRootCategory();
	}

	private void checkNodesExpanded(GTreeNode parent) {
		assertTrue(tree.isExpanded(parent.getTreePath()));

		int nchild = parent.getChildCount();
		for (int i = 0; i < nchild; i++) {
			GTreeNode node = parent.getChild(i);
			if (node.getChildCount() > 0) {
				checkNodesExpanded(node);
			}
		}
	}

	private void checkNodesCollapsed(GTreeNode parent) {
		if (parent != tree.getModelRoot()) {
			assertFalse(tree.isExpanded(parent.getTreePath()));
		}

		int nchild = parent.getChildCount();
		for (int i = 0; i < nchild; i++) {
			GTreeNode node = parent.getChild(i);
			if (node.getChildCount() > 0) {
				checkNodesCollapsed(node);
			}
		}
	}

	/**
	 * This directory is bin in eclipse; it will be a resources directory in the classpath when run
	 * in batch mode.   The directory is one specifically created by and for this test.
	 * @return class output directory
	 * @throws FileNotFoundException Could not find class output directory
	 */
	private File getClassesDirectory() throws FileNotFoundException {
		File file = getTestDataTypeFile();
		if (file == null) {
			throw new FileNotFoundException("Could not find resource TestDataType.txt");
		}
		File parent = file.getParentFile();
		String parentPath = parent.getAbsolutePath();
		int pos = parentPath.lastIndexOf("ghidra");
		String destPath = parentPath.substring(0, pos - 1);
		String newpath =
			destPath + File.separator + "ghidra" + File.separator + "app" + File.separator + "test";
		return new File(newpath);
	}

	private void removeBinTestDir() {
		try {
			File binDir = getClassesDirectory();
			if (binDir.isDirectory()) {
				FileUtilities.deleteDir(binDir);
			}
		}
		catch (FileNotFoundException e) {
			System.err.println("Unable to delete test dir?: " + e.getMessage());
		}
	}

	private File getTestDataTypeFile() {
		URL url = getClass().getResource("TestDataType.txt");
		try {
			URI uri = new URI(url.toExternalForm());
			return new File(uri);
		}
		catch (URISyntaxException e) {
			throw new RuntimeException("Cannot find TestDataType.txt");
		}

	}

	private void expandNode(GTreeNode node) {
		tree.expandPath(node);
		waitForTree();
	}

	private void selectNode(GTreeNode node) {
		tree.setSelectedNode(node);
		waitForTree();
	}

	private void waitForTree() {
		waitForTree(tree);
	}

	private class SpyAction extends AbstractAction {

		private Action defaultAction;
		private AtomicBoolean actionFired = new AtomicBoolean();

		public SpyAction(Action defaultAction) {
			this.defaultAction = defaultAction;
		}

		boolean actionFired() {
			return actionFired.get();
		}

		@Override
		public void actionPerformed(ActionEvent e) {
			defaultAction.actionPerformed(e);
			actionFired.set(true);
		}

	}

}
