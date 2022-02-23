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

import static org.junit.Assert.*;

import java.awt.datatransfer.Transferable;
import java.awt.dnd.DnDConstants;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JTextField;

import org.junit.*;

import docking.action.DockingActionIf;
import docking.menu.ActionState;
import docking.widgets.tree.GTreeNode;
import docking.widgets.tree.support.GTreeDragNDropHandler;
import docking.widgets.tree.support.GTreeNodeTransferable;
import ghidra.app.context.ProgramActionContext;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.datamgr.actions.ConflictHandlerModesAction;
import ghidra.app.plugin.core.datamgr.tree.*;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.datatype.DataTypeSelectionDialog;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.*;
import ghidra.program.model.data.DataTypeConflictHandler.ConflictResolutionPolicy;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.DuplicateNameException;

/**
 * Tests copy/paste/drag/drop operations
 */
public class DataTypeCopyMoveDragTest extends AbstractGhidraHeadedIntegrationTest {
	private static final String PROGRAM_FILENAME = "notepad";

	private TestEnv env;
	private PluginTool tool;
	private ProgramDB program;
	private DataTypeManagerPlugin plugin;
	private DataTypesProvider provider;
	private DockingActionIf pasteAction;
	private ConflictHandlerModesAction conflictHandlerModesAction;
	private ProgramActionContext treeContext;
	private DataTypeArchiveGTree tree;
	private ArchiveRootNode archiveRootNode;
	private ArchiveNode programNode;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.getTool();
		env.showTool();
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		tool.addPlugin(DataTypeManagerPlugin.class.getName());

		program = buildProgram();
		ProgramManager pm = tool.getService(ProgramManager.class);
		pm.openProgram(program.getDomainFile());

		env.showTool();

		plugin = env.getPlugin(DataTypeManagerPlugin.class);
		provider = plugin.getProvider();
		conflictHandlerModesAction =
			(ConflictHandlerModesAction) getInstanceField("conflictHandlerModesAction", provider);
		assertNotNull("Did not find DataTypesProvider.conflictHandlerModesAction field",
			conflictHandlerModesAction);
		tree = provider.getGTree();
		waitForTree();
		archiveRootNode = (ArchiveRootNode) tree.getModelRoot();
		programNode = (ArchiveNode) archiveRootNode.getChild(PROGRAM_FILENAME);
		assertNotNull("Did not successfully wait for the program node to load", programNode);

		tool.showComponentProvider(provider, true);

		pasteAction = getAction(plugin, "Paste");
		treeContext = new DataTypesActionContext(provider, program, tree, null);
	}

	private ProgramDB buildProgram() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("notepad", ProgramBuilder._TOY, this);

		builder.createMemory(".text", "0x1001000", 0x6600);
		builder.createMemory(".data", "0x1008000", 0x600);
		builder.createMemory(".data", "0x1008600", 0x1344);
		builder.createMemory(".rsrc", "0x100a000", 0x5400);
		CategoryPath path = new CategoryPath("/MISC");
		builder.addCategory(path);
		StructureDataType struct = new StructureDataType("ArrayStruct", 4);
		struct.setCategoryPath(path);
		builder.addDataType(struct);
		UnionDataType union = new UnionDataType("ArrayUnion");
		union.setCategoryPath(path);
		union.add(new ByteDataType());
		builder.addDataType(union);

		path = new CategoryPath("/Category1");
		builder.addCategory(path);
		path = new CategoryPath(path, "Category2");
		builder.addCategory(path);
		path = new CategoryPath(path, "Category3");
		builder.addCategory(path);
		StructureDataType dt = new StructureDataType("IntStruct", 0);
		dt.add(new WordDataType());
		dt.setCategoryPath(path);
		builder.addDataType(dt);
		return builder.getProgram();
	}

	@After
	public void tearDown() throws Exception {
		executeOnSwingWithoutBlocking(() -> {
			ProgramManager pm = tool.getService(ProgramManager.class);
			pm.closeProgram();

		});

		// this handles the save changes dialog and potential analysis dialogs
		closeAllWindows();

		env.release(program);
		env.dispose();
	}

	private ActionState<DataTypeConflictHandler.ConflictResolutionPolicy> findConflictHandlerActionState(
			DataTypeConflictHandler.ConflictResolutionPolicy conflictMode) {
		for (ActionState<DataTypeConflictHandler.ConflictResolutionPolicy> actionState : conflictHandlerModesAction
				.getAllActionStates()) {
			if (actionState.getUserData() == conflictMode) {
				return actionState;
			}
		}
		Assert.fail("ActionState not found: ConflictResult=" + conflictMode);
		return null;
	}

	private void enableRenameConflictHandler() {
		conflictHandlerModesAction.setCurrentActionState(
			findConflictHandlerActionState(ConflictResolutionPolicy.RENAME_AND_ADD));
	}

	private void enableUseExistingConflictHandler() {
		conflictHandlerModesAction.setCurrentActionState(
			findConflictHandlerActionState(ConflictResolutionPolicy.USE_EXISTING));
	}

	private void enableReplaceExistingConflictHandler() {
		conflictHandlerModesAction.setCurrentActionState(
			findConflictHandlerActionState(ConflictResolutionPolicy.REPLACE_EXISTING));
	}

	@Test
	public void testCopyPasteToCategory_RenameConflictHandler() throws Exception {

		enableRenameConflictHandler();

		// cause a conflict
		// in the program, rename Category1/Category2/Category3/IntStruct to ArrayStruct
		String structName = "ArrayStruct";
		createAndSelectStructure(structName);

		String miscNodeName = "MISC";
		CategoryNode miscNode = copyPasteSelectedNodeToNode(miscNodeName);

		String conflictName = structName + DataType.CONFLICT_SUFFIX;
		DataTypeNode conflictNode = (DataTypeNode) miscNode.getChild(conflictName);
		assertNotNull(conflictNode);

		undo();

		miscNode = (CategoryNode) programNode.getChild(miscNodeName);
		conflictNode = (DataTypeNode) miscNode.getChild(conflictName);
		assertNull(conflictNode);

		redo();

		miscNode = (CategoryNode) programNode.getChild(miscNodeName);
		conflictNode = (DataTypeNode) miscNode.getChild(conflictName);
		assertNotNull(miscNode.getChild(conflictName));
	}

	@Test
	public void testCopyPasteToCategory_ReplaceExistingConflictHandler() throws Exception {

		enableReplaceExistingConflictHandler();

		// cause a conflict
		// in the program, rename Category1/Category2/Category3/IntStruct to ArrayStruct
		String structName = "ArrayStruct";
		DataTypeNode structureNode = createAndSelectStructure(structName);
		Structure structure = (Structure) structureNode.getDataType();

		String miscNodeName = "MISC";
		CategoryNode miscNode = copyPasteSelectedNodeToNode(miscNodeName);

		DataTypeNode node = (DataTypeNode) miscNode.getChild(structName);
		assertNotNull(node);
		assertTrue(structure.isEquivalent(node.getDataType()));
	}

	@Test
	public void testCopyPasteToCategory_UseExistingConflictHandler() throws Exception {

		enableUseExistingConflictHandler();

		// cause a conflict
		// in the program, rename Category1/Category2/Category3/IntStruct to ArrayStruct
		String structName = "ArrayStruct";
		DataTypeNode structureNode = createAndSelectStructure(structName);
		CategoryNode category3Node = (CategoryNode) structureNode.getParent();

		CategoryNode miscNode = (CategoryNode) programNode.getChild("MISC");
		structureNode = (DataTypeNode) miscNode.getChild(structName);
		DataType originalDataType = structureNode.getDataType();

		copyPasteSelectedNodeToNode("MISC");

		DataTypeNode newDataTypeNode = (DataTypeNode) miscNode.getChild(structName);
		assertNotNull(newDataTypeNode);
		assertEquals(originalDataType, newDataTypeNode.getDataType());

		structureNode = (DataTypeNode) category3Node.getChild(structName);
		assertFalse(originalDataType.isEquivalent(structureNode.getDataType()));
	}

	@Test
	public void testCutPasteToCategory_RenameConflictHandler() throws Exception {

		enableRenameConflictHandler();

		// cause a conflict
		// in the program, rename Category1/Category2/Category3/IntStruct to ArrayStruct
		String structName = "ArrayStruct";
		DataTypeNode structureNode = createAndSelectStructure(structName);
		CategoryNode category3Node = (CategoryNode) structureNode.getParent();

		CategoryNode miscNode = cutPasteSelectedNodeToNode("MISC");

		DataTypeNode node = (DataTypeNode) miscNode.getChild(structName + DataType.CONFLICT_SUFFIX);
		assertNotNull(node);
		assertNull(category3Node.getChild(structName));
	}

	@Test
	public void testDragMoveToCategory_RenameConflictHandler() throws Exception {

		enableRenameConflictHandler();

		// cause a conflict
		// in the program, rename Category1/Category2/Category3/IntStruct to ArrayStruct
		String structName = "ArrayStruct";
		DataTypeNode structureNode = createAndSelectStructure(structName);

		CategoryNode miscNode = (CategoryNode) programNode.getChild("MISC");
		expandNode(miscNode);

		// move/drag ArrayStruct to MISC
		moveDragNodeToNode(structureNode, miscNode);

		DataTypeNode node = (DataTypeNode) miscNode.getChild(structName + DataType.CONFLICT_SUFFIX);
		assertNotNull(node);
		assertNull(structureNode.getParent());
	}

	@Test
	public void testDragCopyToCategory_RenameConflictHandler() throws Exception {

		enableRenameConflictHandler();

		// cause a conflict
		// in the program, rename Category1/Category2/Category3/IntStruct to ArrayStruct
		String structName = "ArrayStruct";
		DataTypeNode structureNode = createAndSelectStructure(structName);
		CategoryNode category3Node = (CategoryNode) structureNode.getParent();

		CategoryNode miscNode = (CategoryNode) programNode.getChild("MISC");
		expandNode(miscNode);

		// copy/drag ArrayStruct to MISC
		copyDragNodeToNode(structureNode, miscNode);

		structureNode = (DataTypeNode) tree.getViewNode(structureNode);
		category3Node = (CategoryNode) tree.getViewNode(category3Node);
		miscNode = (CategoryNode) tree.getViewNode(miscNode);

		CategoryNode parent = miscNode;
		DataTypeNode node =
			waitFor(() -> (DataTypeNode) parent.getChild(structName + DataType.CONFLICT_SUFFIX));
		assertNotNull(node);
		assertEquals(category3Node, structureNode.getParent());
	}

	@Test
	public void testDragCopyToCategory_ReplaceExistingConflictHandler() throws Exception {

		enableReplaceExistingConflictHandler();

		// cause a conflict
		// in the program, rename Category1/Category2/Category3/IntStruct to ArrayStruct
		String structName = "ArrayStruct";
		DataTypeNode structureNode = createAndSelectStructure(structName);
		CategoryNode category3Node = (CategoryNode) structureNode.getParent();
		DataType originalDt = structureNode.getDataType();

		CategoryNode miscNode = (CategoryNode) programNode.getChild("MISC");
		expandNode(miscNode);

		// copy/drag ArrayStruct to MISC
		copyDragNodeToNode(structureNode, miscNode);

		structureNode = (DataTypeNode) tree.getViewNode(structureNode);
		category3Node = (CategoryNode) tree.getViewNode(category3Node);
		miscNode = (CategoryNode) tree.getViewNode(miscNode);

		DataTypeNode node = (DataTypeNode) miscNode.getChild(structName);
		assertNotNull(node);
		assertEquals(category3Node, structureNode.getParent());
		assertTrue(originalDt.isEquivalent(structureNode.getDataType()));
	}

	@Test
	public void testDragCopyToCategory_UseExistingConflictHandler() throws Exception {

		enableUseExistingConflictHandler();

		// cause a conflict
		// in the program, rename Category1/Category2/Category3/IntStruct to ArrayStruct
		String structName = "ArrayStruct";
		DataTypeNode structureNode = createAndSelectStructure(structName);
		DataType originalDt = structureNode.getDataType();

		CategoryNode miscNode = (CategoryNode) programNode.getChild("MISC");
		expandNode(miscNode);

		// copy/drag ArrayStruct to MISC
		copyDragNodeToNode(structureNode, miscNode);

		DataTypeNode node = (DataTypeNode) miscNode.getChild(structName);
		assertNotNull(node);
		structureNode = (DataTypeNode) miscNode.getChild(structName);
		assertNotNull(structureNode);
		assertFalse(originalDt.isEquivalent(structureNode.getDataType()));
	}

	@Test
	public void testCutPasteToCategory_ReplaceExistingConflictHandler() throws Exception {

		enableReplaceExistingConflictHandler();

		// cause a conflict
		// in the program, rename Category1/Category2/Category3/IntStruct to ArrayStruct
		String structName = "ArrayStruct";
		createAndSelectStructure(structName);

		CategoryNode miscNode = (CategoryNode) programNode.getChild("MISC");
		DataTypeNode node = (DataTypeNode) miscNode.getChild("ArrayStruct");
		DataType originalDt = node.getDataType();

		// move ArrayStruct to MISC
		cutPasteSelectedNodeToNode("MISC");

		node = (DataTypeNode) miscNode.getChild(structName);
		assertNotNull(node);
		assertFalse(originalDt.equals(node.getDataType()));
	}

	@Test
	public void testCutPasteToCategory_UseExistingConflictHandler() throws Exception {

		enableUseExistingConflictHandler();

		// cause a conflict
		// in the program, rename Category1/Category2/Category3/IntStruct to ArrayStruct
		String structName = "ArrayStruct";
		DataTypeNode structureNode = createAndSelectStructure(structName);

		CategoryNode miscNode = (CategoryNode) programNode.getChild("MISC");
		DataTypeNode node = (DataTypeNode) miscNode.getChild("ArrayStruct");
		DataType originalDt = node.getDataType();

		cutPasteSelectedNodeToNode("MISC");

		node = (DataTypeNode) miscNode.getChild(structName);
		assertNotNull(node);
		assertTrue(originalDt.equals(node.getDataType()));
		assertNull(structureNode.getParent());
	}

	@Test
	public void testDragMoveToCategory_ReplaceExistingConflictHandler() throws Exception {

		enableReplaceExistingConflictHandler();

		// cause a conflict
		// in the program, rename Category1/Category2/Category3/IntStruct to ArrayStruct
		String structName = "ArrayStruct";
		DataTypeNode structureNode = createAndSelectStructure(structName);

		CategoryNode miscNode = (CategoryNode) programNode.getChild("MISC");
		expandNode(miscNode);

		DataTypeNode node = (DataTypeNode) miscNode.getChild(structName);
		DataType originalDt = node.getDataType();

		// move/drag ArrayStruct to MISC
		moveDragNodeToNode(structureNode, miscNode);

		node = (DataTypeNode) miscNode.getChild(structName);
		assertNotNull(node);

		assertNull(structureNode.getParent());
		assertNotNull(node);
		assertFalse(originalDt.equals(node.getDataType()));
	}

	@Test
	public void testDragMoveToCategory_UseExistingConflictHandler() throws Exception {

		enableUseExistingConflictHandler();

		// cause a conflict
		// in the program, rename Category1/Category2/Category3/IntStruct to ArrayStruct
		String structName = "ArrayStruct";
		DataTypeNode structureNode = createAndSelectStructure(structName);

		CategoryNode miscNode = (CategoryNode) programNode.getChild("MISC");
		expandNode(miscNode);
		DataTypeNode node = (DataTypeNode) miscNode.getChild(structName);
		DataType originalDt = node.getDataType();

		// move/drag ArrayStruct to MISC
		moveDragNodeToNode(structureNode, miscNode);

		node = (DataTypeNode) miscNode.getChild(structName);
		assertNotNull(node);

		assertNull(structureNode.getParent());
		assertNotNull(node);
		assertTrue(originalDt.equals(node.getDataType()));
	}

	@Test
	public void testDragMoveToDataType_Replace() throws Exception {

		enableReplaceExistingConflictHandler();

		String structName = "ArrayStruct";
		DataTypeNode structureNode = createAndSelectStructure(structName);
		Structure structure = (Structure) structureNode.getDataType();
		CategoryNode category3Node = (CategoryNode) structureNode.getParent();

		CategoryNode miscNode = (CategoryNode) programNode.getChild("MISC");
		expandNode(miscNode);

		// drag/move ArrayStruct to MISC/ArrayStruct
		DataTypeNode miscStructureNode = (DataTypeNode) miscNode.getChild("ArrayStruct");
		moveDragNodeToNode(structureNode, miscStructureNode);

		assertNull(structureNode.getParent());
		assertNull(category3Node.getChild(structName));

		DataTypeNode node = (DataTypeNode) miscNode.getChild(structName);
		assertTrue(structure.isEquivalent(node.getDataType()));

		undo();

		CategoryNode category1Node = (CategoryNode) programNode.getChild("Category1");
		CategoryNode category2Node = (CategoryNode) category1Node.getChild("Category2");
		category3Node = (CategoryNode) category2Node.getChild("Category3");
		assertNotNull(category3Node.getChild(structName));

		redo();

		category1Node = (CategoryNode) programNode.getChild("Category1");
		category2Node = (CategoryNode) category1Node.getChild("Category2");
		category3Node = (CategoryNode) category2Node.getChild("Category3");
		assertNull(category3Node.getChild(structName));
	}

	@Test
	public void testDragMoveToDataType_SameParent() throws Exception {
		// drag/drop a data type onto another data type
		CategoryNode miscNode = (CategoryNode) programNode.getChild("MISC");
		expandNode(miscNode);

		DataTypeNode structureNode = (DataTypeNode) miscNode.getChild("ArrayStruct");
		DataTypeNode unionNode = (DataTypeNode) miscNode.getChild("ArrayUnion");

		setErrorsExpected(true);
		moveDragNodeToNode(unionNode, structureNode);
		setErrorsExpected(false);

		// can't move a data type into its same category
		waitForWindow("Encountered Errors Copying/Moving");
	}

	@Test
	public void testDragCopyToDataType() throws Exception {

		enableRenameConflictHandler();

		String structName = "ArrayStruct";
		DataTypeNode structureNode = createAndSelectStructure(structName);
		CategoryNode category3Node = (CategoryNode) structureNode.getParent();

		// drag/move ArrayStruct to MISC/ArrayStruct
		String miscName = "MISC";
		CategoryNode miscNode = (CategoryNode) programNode.getChild(miscName);
		expandNode(miscNode);

		DataTypeNode miscStructureNode = (DataTypeNode) miscNode.getChild("ArrayStruct");
		copyDragNodeToNode(structureNode, miscStructureNode);

		structureNode = (DataTypeNode) tree.getViewNode(structureNode);
		assertNotNull(structureNode.getParent());

		category3Node = (CategoryNode) tree.getViewNode(category3Node);
		assertNotNull(category3Node.getChild(structName));

		miscNode = (CategoryNode) tree.getViewNode(miscNode);
		DataTypeNode newNode =
			(DataTypeNode) miscNode.getChild(structName + DataType.CONFLICT_SUFFIX);
		assertNotNull(newNode);
		assertNotNull(structureNode.getParent());
	}

	@Test
	public void testCopyPasteToCategory() {

		String miscName = "MISC";
		CategoryNode miscNode = (CategoryNode) programNode.getChild(miscName);
		expandNode(miscNode);

		String dtName = "ArrayStruct";
		DataTypeNode miscStructureNode = (DataTypeNode) miscNode.getChild(dtName);
		selectNode(miscStructureNode);

		DockingActionIf copyAction = getAction(plugin, "Copy");
		assertTrue(copyAction.isEnabledForContext(treeContext));
		assertFalse(pasteAction.isEnabledForContext(treeContext));

		DataTypeTestUtils.performAction(copyAction, tree);

		selectNode(miscNode);
		assertTrue(pasteAction.isEnabledForContext(treeContext));
		DataTypeTestUtils.performAction(pasteAction, tree);
		GTreeNode newNode = miscNode.getChild("Copy_1_of_" + dtName);
		assertNotNull(newNode);

		selectNode(miscNode);
		assertTrue(pasteAction.isEnabledForContext(treeContext));
		DataTypeTestUtils.performAction(pasteAction, tree);
		newNode = miscNode.getChild("Copy_2_of_" + dtName);
		assertNotNull(newNode);
	}

	@Test
	public void testCopyPasteToDataType_SameType() throws Exception {

		String miscName = "MISC";
		CategoryNode miscNode = (CategoryNode) programNode.getChild(miscName);
		expandNode(miscNode);

		String dtName = "ArrayStruct";
		DataTypeNode miscStructureNode = (DataTypeNode) miscNode.getChild(dtName);
		selectNode(miscStructureNode);

		DockingActionIf copyAction = getAction(plugin, "Copy");
		assertTrue(copyAction.isEnabledForContext(treeContext));
		assertFalse(pasteAction.isEnabledForContext(treeContext));

		DataTypeTestUtils.performAction(copyAction, tree);

		selectNode(miscStructureNode);
		assertTrue(pasteAction.isEnabledForContext(treeContext));
		DataTypeTestUtils.performAction(pasteAction, tree);
		GTreeNode newNode = miscNode.getChild("Copy_1_of_" + dtName);
		assertNotNull(newNode);

		selectNode(miscStructureNode);
		assertTrue(pasteAction.isEnabledForContext(treeContext));

		DataTypeTestUtils.performAction(pasteAction, tree);

		newNode = miscNode.getChild("Copy_2_of_" + dtName);
		assertNotNull(newNode);
	}

	@Test
	public void testCopyPasteToDataType_DifferentType() throws Exception {

		String miscName = "MISC";
		CategoryNode miscNode = (CategoryNode) programNode.getChild(miscName);
		expandNode(miscNode);

		String dtName = "ArrayStruct";
		DataTypeNode miscStructureNode = (DataTypeNode) miscNode.getChild(dtName);
		selectNode(miscStructureNode);

		DockingActionIf copyAction = getAction(plugin, "Copy");
		assertTrue(copyAction.isEnabledForContext(treeContext));
		assertFalse(pasteAction.isEnabledForContext(treeContext));

		DataTypeTestUtils.performAction(copyAction, tree);

		DataTypeNode miscUnionNode = (DataTypeNode) miscNode.getChild("ArrayUnion");
		selectNode(miscUnionNode);
		assertTrue(pasteAction.isEnabledForContext(treeContext));

		DataTypeTestUtils.performAction(pasteAction, tree);

		GTreeNode newNode = miscNode.getChild("Copy_1_of_" + dtName);
		assertNotNull(newNode);
	}

	@Test
	public void testCopyPasteToDataType_DifferentType_SameName_RenameConflictHanlder()
			throws Exception {

		enableRenameConflictHandler();

		String existingDtName = "ArrayUnion";

		DataTypeNode intStructureNode =
			(DataTypeNode) getNotepadNode("Category1/Category2/Category3/IntStruct");
		rename(intStructureNode, existingDtName);
		intStructureNode =
			(DataTypeNode) getNotepadNode("Category1/Category2/Category3/" + existingDtName);
		selectNode(intStructureNode);

		DockingActionIf copyAction = getAction(plugin, "Copy");
		assertTrue(copyAction.isEnabledForContext(treeContext));
		assertFalse(pasteAction.isEnabledForContext(treeContext));

		DataTypeTestUtils.performAction(copyAction, tree);

		String miscName = "MISC";
		CategoryNode miscNode = (CategoryNode) programNode.getChild(miscName);
		expandNode(miscNode);
		DataTypeNode miscUnionNode = (DataTypeNode) miscNode.getChild(existingDtName);
		selectNode(miscUnionNode);
		assertTrue(pasteAction.isEnabledForContext(treeContext));

		DataTypeTestUtils.performAction(pasteAction, tree);
		waitForTree();

		GTreeNode newNode = miscNode.getChild(existingDtName + DataType.CONFLICT_SUFFIX);
		assertNotNull(newNode);
	}

	@Test
	public void testCopyPasteToDataType_FromDifferentCategory() throws Exception {

		String miscName = "MISC";
		CategoryNode miscNode = (CategoryNode) programNode.getChild(miscName);
		expandNode(miscNode);

		DataTypeNode intStructureNode =
			(DataTypeNode) getNotepadNode("Category1/Category2/Category3/IntStruct");
		selectNode(intStructureNode);

		DockingActionIf copyAction = getAction(plugin, "Copy");
		assertTrue(copyAction.isEnabledForContext(treeContext));
		assertFalse(pasteAction.isEnabledForContext(treeContext));

		DataTypeTestUtils.performAction(copyAction, tree);

		String dtName = "ArrayStruct";
		DataTypeNode miscStructureNode = (DataTypeNode) miscNode.getChild(dtName);
		selectNode(miscStructureNode);
		assertTrue(pasteAction.isEnabledForContext(treeContext));

		DataTypeTestUtils.performAction(pasteAction, tree);

		GTreeNode newNode = miscNode.getChild("IntStruct");
		assertNotNull(newNode);
	}

	@Test
	public void testCopyPasteToDataType_MultipleDataTypes() {

		String miscName = "MISC";
		CategoryNode miscNode = (CategoryNode) programNode.getChild(miscName);
		expandNode(miscNode);

		String dtName1 = "ArrayStruct";
		DataTypeNode miscStructureNode = (DataTypeNode) miscNode.getChild(dtName1);
		String dtName2 = "ArrayUnion";
		DataTypeNode miscUnionNode = (DataTypeNode) miscNode.getChild(dtName2);
		selectNodes(miscStructureNode, miscUnionNode);

		DockingActionIf copyAction = getAction(plugin, "Copy");
		assertTrue(copyAction.isEnabledForContext(treeContext));
		assertFalse(pasteAction.isEnabledForContext(treeContext));

		DataTypeTestUtils.performAction(copyAction, tree);

		DataTypeNode intStructureNode =
			(DataTypeNode) getNotepadNode("Category1/Category2/Category3/IntStruct");
		selectNode(intStructureNode);

		assertTrue(pasteAction.isEnabledForContext(treeContext));
		DataTypeTestUtils.performAction(pasteAction, tree);

		GTreeNode newNode = miscNode.getChild(dtName1);
		assertNotNull(newNode);
		newNode = miscNode.getChild(dtName2);
		assertNotNull(newNode);
	}

	@Test
	public void testReplaceAction() {

		String miscName = "MISC";
		CategoryNode miscNode = (CategoryNode) programNode.getChild(miscName);
		expandNode(miscNode);

		String originalDtName = "ArrayStruct";
		DataTypeNode miscStructureNode = (DataTypeNode) miscNode.getChild(originalDtName);
		selectNode(miscStructureNode);

		DockingActionIf replaceAction = getAction(plugin, "Replace Data Type");
		assertTrue(replaceAction.isEnabledForContext(treeContext));
		DataTypeTestUtils.performAction(replaceAction, tree, false);

		String newDtName = "IntStruct";
		chooseDataType(newDtName);

		DataTypeNode updatedNode = (DataTypeNode) miscNode.getChild(newDtName);
		assertNotNull(updatedNode);
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private void chooseDataType(String dtName) {

		DataTypeSelectionDialog chooser = waitForDialogComponent(DataTypeSelectionDialog.class);

		JTextField tf = findComponent(chooser, JTextField.class);
		triggerText(tf, dtName);

		pressButtonByText(chooser, "OK");
		waitForTasks();
	}

	private GTreeNode getNotepadNode(String path) {

		GTreeNode last = programNode;
		String[] names = path.split("/");
		for (String name : names) {
			last = last.getChild(name);
		}

		return last;
	}

	private void rename(DataTypeNode node, String newName) throws Exception {

		DataType dt = node.getDataType();
		tx(program, () -> dt.setName(newName));
		waitForProgram();
	}

	/**
	 * In the program, rename Category1/Category2/Category3/IntStruct to <structureName>
	 */
	private DataTypeNode createAndSelectStructure(String structureName)
			throws InvalidNameException, DuplicateNameException, Exception {
		CategoryNode category1Node = (CategoryNode) programNode.getChild("Category1");
		expandNode(category1Node);
		CategoryNode category2Node = (CategoryNode) category1Node.getChild("Category2");
		expandNode(category2Node);
		CategoryNode category3Node = (CategoryNode) category2Node.getChild("Category3");
		expandNode(category3Node);
		DataTypeNode structureNode = (DataTypeNode) category3Node.getChild("IntStruct");
		Structure structure = (Structure) structureNode.getDataType();

		tx(program, () -> structure.setName(structureName));
		waitForProgram();

		structureNode = (DataTypeNode) category3Node.getChild(structureName);
		selectNode(structureNode);
		return structureNode;
	}

	private CategoryNode copyPasteSelectedNodeToNode(String toNodeName) throws Exception {
		DockingActionIf copyAction = getAction(plugin, "Copy");
		assertTrue(copyAction.isEnabled());
		DataTypeTestUtils.performAction(copyAction, tree);

		CategoryNode miscNode = (CategoryNode) programNode.getChild(toNodeName);
		expandNode(miscNode);
		selectNode(miscNode);

		runSwing(() -> DataTypeTestUtils.performAction(pasteAction, tree), false);
		waitForTasks();
		return miscNode;
	}

	private CategoryNode cutPasteSelectedNodeToNode(String toNodeName) throws Exception {
		DockingActionIf cutAction = getAction(plugin, "Cut");
		DataTypeTestUtils.performAction(cutAction, tree);

		final CategoryNode miscNode = (CategoryNode) programNode.getChild(toNodeName);
		expandNode(miscNode);
		selectNode(miscNode);

		runSwing(() -> DataTypeTestUtils.performAction(pasteAction, tree), false);
		waitForTasks();
		return miscNode;
	}

	private void moveDragNodeToNode(GTreeNode fromNode, final GTreeNode toNode) {
		final GTreeDragNDropHandler dragNDropHandler = tree.getDragNDropHandler();
		List<GTreeNode> dropList = new ArrayList<>();
		dropList.add(fromNode);
		final Transferable transferable = new GTreeNodeTransferable(dragNDropHandler, dropList);

		runSwing(() -> dragNDropHandler.drop(toNode, transferable, DnDConstants.ACTION_MOVE),
			false);
		waitForTasks();
	}

	private void copyDragNodeToNode(GTreeNode fromNode, final GTreeNode toNode) throws Exception {
		final GTreeDragNDropHandler dragNDropHandler = tree.getDragNDropHandler();
		List<GTreeNode> dropList = new ArrayList<>();
		dropList.add(fromNode);
		Transferable transferable = new GTreeNodeTransferable(dragNDropHandler, dropList);
		runSwing(() -> dragNDropHandler.drop(toNode, transferable, DnDConstants.ACTION_COPY),
			false);
		waitForTasks();
	}

//==================================================================================================
// Private Helper Methods
//==================================================================================================
	private void expandNode(GTreeNode node) {
		tree.expandPath(node);
		waitForTree();
	}

	private void selectNode(GTreeNode node) {
		tree.setSelectedNode(node);
		waitForTree();
	}

	private void selectNodes(GTreeNode... nodes) {
		tree.setSelectedNodes(nodes);
		waitForTree();
	}

	private void waitForTree() {
		waitForTree(tree);
	}

	private void waitForProgram() throws Exception {
		waitForTasks();
		program.flushEvents();
		waitForTasks();
		waitForSwing();
	}

	private void undo() throws Exception {
		undo(program);
	}

	private void redo() throws Exception {
		redo(program);
	}
}
