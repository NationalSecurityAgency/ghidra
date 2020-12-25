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

import javax.swing.JButton;
import javax.swing.tree.TreePath;

import org.junit.*;

import docking.action.DockingActionIf;
import docking.menu.ActionState;
import docking.widgets.OptionDialog;
import docking.widgets.tree.GTreeNode;
import docking.widgets.tree.support.GTreeDragNDropHandler;
import docking.widgets.tree.support.GTreeNodeTransferable;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.datamgr.actions.ConflictHandlerModesAction;
import ghidra.app.plugin.core.datamgr.tree.*;
import ghidra.app.services.ProgramManager;
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
	private ConflictHandlerModesAction conflictHandlerModesAction;
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
	public void testConflictCopyInProgram() throws Exception {

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
	public void testConflictCopyReplace() throws Exception {

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
	public void testConflictCopyUseExisting() throws Exception {

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
		assertTrue(!originalDataType.isEquivalent(structureNode.getDataType()));
	}

	@Test
	public void testConflictPasteMoveRename() throws Exception {

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
	public void testConflictDragMoveRename() throws Exception {

		enableRenameConflictHandler();

		// cause a conflict
		// in the program, rename Category1/Category2/Category3/IntStruct to ArrayStruct
		String structName = "ArrayStruct";
		DataTypeNode structureNode = createAndSelectStructure(structName);

		CategoryNode miscNode = (CategoryNode) programNode.getChild("MISC");
		expandNode(miscNode);

		// move/drag ArrayStruct to MISC
		dragNodeToNode(structureNode, miscNode);

		DataTypeNode node = (DataTypeNode) miscNode.getChild(structName + DataType.CONFLICT_SUFFIX);
		assertNotNull(node);
		assertNull(structureNode.getParent());
	}

	@Test
	public void testConflictDragCopyRename() throws Exception {

		enableRenameConflictHandler();

		// cause a conflict
		// in the program, rename Category1/Category2/Category3/IntStruct to ArrayStruct
		String structName = "ArrayStruct";
		DataTypeNode structureNode = createAndSelectStructure(structName);
		CategoryNode category3Node = (CategoryNode) structureNode.getParent();

		CategoryNode miscNode = (CategoryNode) programNode.getChild("MISC");
		expandNode(miscNode);

		TreePath structureNodePath = structureNode.getTreePath();
		TreePath category3Path = category3Node.getTreePath();
		TreePath miscPath = miscNode.getTreePath();

		// copy/drag ArrayStruct to MISC
		copyNodeToNode(structureNode, miscNode);

		structureNode = (DataTypeNode) tree.getViewNodeForPath(structureNodePath);
		category3Node = (CategoryNode) tree.getViewNodeForPath(category3Path);
		miscNode = (CategoryNode) tree.getViewNodeForPath(miscPath);

		CategoryNode parent = miscNode;
		DataTypeNode node =
			waitFor(() -> (DataTypeNode) parent.getChild(structName + DataType.CONFLICT_SUFFIX));
		assertNotNull(node);
		assertEquals(category3Node, structureNode.getParent());
	}

	@Test
	public void testConflictDragCopyReplace() throws Exception {

		enableReplaceExistingConflictHandler();

		// cause a conflict
		// in the program, rename Category1/Category2/Category3/IntStruct to ArrayStruct
		String structName = "ArrayStruct";
		DataTypeNode structureNode = createAndSelectStructure(structName);
		CategoryNode category3Node = (CategoryNode) structureNode.getParent();
		DataType origDt = structureNode.getDataType();

		CategoryNode miscNode = (CategoryNode) programNode.getChild("MISC");
		expandNode(miscNode);

		TreePath structureNodePath = structureNode.getTreePath();
		TreePath category3Path = category3Node.getTreePath();
		TreePath miscPath = miscNode.getTreePath();

		// copy/drag ArrayStruct to MISC
		copyNodeToNode(structureNode, miscNode);

		structureNode = (DataTypeNode) tree.getViewNodeForPath(structureNodePath);
		category3Node = (CategoryNode) tree.getViewNodeForPath(category3Path);
		miscNode = (CategoryNode) tree.getViewNodeForPath(miscPath);

		DataTypeNode node = (DataTypeNode) miscNode.getChild(structName);
		assertNotNull(node);
		assertEquals(category3Node, structureNode.getParent());
		assertTrue(origDt.isEquivalent(structureNode.getDataType()));
	}

	@Test
	public void testConflictDragCopyUseExisting() throws Exception {

		enableUseExistingConflictHandler();

		// cause a conflict
		// in the program, rename Category1/Category2/Category3/IntStruct to ArrayStruct
		String structName = "ArrayStruct";
		DataTypeNode structureNode = createAndSelectStructure(structName);
		DataType origDt = structureNode.getDataType();

		CategoryNode miscNode = (CategoryNode) programNode.getChild("MISC");
		expandNode(miscNode);

		// copy/drag ArrayStruct to MISC
		copyNodeToNode(structureNode, miscNode);

		DataTypeNode node = (DataTypeNode) miscNode.getChild(structName);
		assertNotNull(node);
		structureNode = (DataTypeNode) miscNode.getChild(structName);
		assertNotNull(structureNode);
		assertTrue(!origDt.isEquivalent(structureNode.getDataType()));
	}

	@Test
	public void testConflictPasteMoveReplace() throws Exception {

		enableReplaceExistingConflictHandler();

		// cause a conflict
		// in the program, rename Category1/Category2/Category3/IntStruct to ArrayStruct
		String structName = "ArrayStruct";
		createAndSelectStructure(structName);

		CategoryNode miscNode = (CategoryNode) programNode.getChild("MISC");
		DataTypeNode node = (DataTypeNode) miscNode.getChild("ArrayStruct");
		DataType origDt = node.getDataType();

		// move ArrayStruct to MISC
		cutPasteSelectedNodeToNode("MISC");

		node = (DataTypeNode) miscNode.getChild(structName);
		assertNotNull(node);
		assertTrue(!origDt.equals(node.getDataType()));
	}

	@Test
	public void testConflictPasteMoveUseExisting() throws Exception {

		enableUseExistingConflictHandler();

		// cause a conflict
		// in the program, rename Category1/Category2/Category3/IntStruct to ArrayStruct
		String structName = "ArrayStruct";
		DataTypeNode structureNode = createAndSelectStructure(structName);

		CategoryNode miscNode = (CategoryNode) programNode.getChild("MISC");
		DataTypeNode node = (DataTypeNode) miscNode.getChild("ArrayStruct");
		DataType origDt = node.getDataType();

		cutPasteSelectedNodeToNode("MISC");

		node = (DataTypeNode) miscNode.getChild(structName);
		assertNotNull(node);
		assertTrue(origDt.equals(node.getDataType()));
		assertNull(structureNode.getParent());
	}

	@Test
	public void testConflictDragMoveReplace() throws Exception {

		enableReplaceExistingConflictHandler();

		// cause a conflict
		// in the program, rename Category1/Category2/Category3/IntStruct to ArrayStruct
		String structName = "ArrayStruct";
		DataTypeNode structureNode = createAndSelectStructure(structName);

		CategoryNode miscNode = (CategoryNode) programNode.getChild("MISC");
		expandNode(miscNode);

		DataTypeNode node = (DataTypeNode) miscNode.getChild(structName);
		DataType origDt = node.getDataType();

		// move/drag ArrayStruct to MISC
		dragNodeToNode(structureNode, miscNode);

		node = (DataTypeNode) miscNode.getChild(structName);
		assertNotNull(node);

		assertNull(structureNode.getParent());
		assertNotNull(node);
		assertTrue(!origDt.equals(node.getDataType()));
	}

	@Test
	public void testConflictDragMoveUseExisting() throws Exception {

		enableUseExistingConflictHandler();

		// cause a conflict
		// in the program, rename Category1/Category2/Category3/IntStruct to ArrayStruct
		String structName = "ArrayStruct";
		DataTypeNode structureNode = createAndSelectStructure(structName);

		CategoryNode miscNode = (CategoryNode) programNode.getChild("MISC");
		expandNode(miscNode);
		DataTypeNode node = (DataTypeNode) miscNode.getChild(structName);
		DataType origDt = node.getDataType();

		// move/drag ArrayStruct to MISC
		dragNodeToNode(structureNode, miscNode);

		node = (DataTypeNode) miscNode.getChild(structName);
		assertNotNull(node);

		assertNull(structureNode.getParent());
		assertNotNull(node);
		assertTrue(origDt.equals(node.getDataType()));
	}

	@Test
	public void testReplaceDataTypeYes() throws Exception {
		String structName = "ArrayStruct";
		DataTypeNode structureNode = createAndSelectStructure(structName);
		Structure structure = (Structure) structureNode.getDataType();
		CategoryNode category3Node = (CategoryNode) structureNode.getParent();

		CategoryNode miscNode = (CategoryNode) programNode.getChild("MISC");
		expandNode(miscNode);

		// drag/move ArrayStruct to MISC/ArrayStruct
		DataTypeNode miscStructureNode = (DataTypeNode) miscNode.getChild("ArrayStruct");
		dragNodeToNode(structureNode, miscStructureNode);

		pressButtonOnOptionDialog("Yes");

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
	public void testReplaceDataTypeNo() throws Exception {
		String structName = "ArrayStruct";
		DataTypeNode structureNode = createAndSelectStructure(structName);
		Structure structure = (Structure) structureNode.getDataType();
		CategoryNode category3Node = (CategoryNode) structureNode.getParent();

		CategoryNode miscNode = (CategoryNode) programNode.getChild("MISC");
		expandNode(miscNode);

		TreePath structureNodePath = structureNode.getTreePath();
		TreePath category3Path = category3Node.getTreePath();
		TreePath miscPath = miscNode.getTreePath();

		// drag/move ArrayStruct to MISC/ArrayStruct
		DataTypeNode miscStructureNode = (DataTypeNode) miscNode.getChild("ArrayStruct");
		dragNodeToNode(structureNode, miscStructureNode);

		pressButtonOnOptionDialog("No");

		structureNode = (DataTypeNode) tree.getViewNodeForPath(structureNodePath);
		assertNotNull(structureNode.getParent());

		category3Node = (CategoryNode) tree.getViewNodeForPath(category3Path);
		assertNotNull(category3Node.getChild("ArrayStruct"));

		miscNode = (CategoryNode) tree.getViewNodeForPath(miscPath);
		DataTypeNode node = (DataTypeNode) miscNode.getChild("ArrayStruct");
		assertTrue(!structure.isEquivalent(node.getDataType()));
	}

	@Test
	public void testReplaceDTSameParentYes() throws Exception {
		// drag/drop a data type onto another data type
		// get Option dialog, and choose "Yes"
		CategoryNode miscNode = (CategoryNode) programNode.getChild("MISC");
		expandNode(miscNode);

		DataTypeNode structureNode = (DataTypeNode) miscNode.getChild("ArrayStruct");
		DataTypeNode unionNode = (DataTypeNode) miscNode.getChild("ArrayUnion");

		dragNodeToNode(unionNode, structureNode);

		pressButtonOnOptionDialog("Yes");

		assertNotNull(miscNode.getChild("ArrayUnion"));
		assertNull(miscNode.getChild("ArrayStruct"));
	}

	@Test
	public void testReplaceDTSameParentNo() throws Exception {
		// drag/drop a data type onto another data type
		// get Option dialog, and choose "Yes"
		CategoryNode miscNode = (CategoryNode) programNode.getChild("MISC");
		expandNode(miscNode);

		DataTypeNode structureNode = (DataTypeNode) miscNode.getChild("ArrayStruct");
		DataTypeNode unionNode = (DataTypeNode) miscNode.getChild("ArrayUnion");

		dragNodeToNode(unionNode, structureNode);

		pressButtonOnOptionDialog("No");

		assertNotNull(miscNode.getChild("ArrayUnion"));
		assertNotNull(miscNode.getChild("ArrayStruct"));
	}

	@Test
	public void testCopyReplaceDataTypeNo() throws Exception {
		// drag/copy a data type onto another data type
		// get Option dialog, and choose "No"
		// cause a conflict
		// in the program, rename Category1/Category2/Category3/IntStruct to ArrayStruct
		String structName = "ArrayStruct";
		DataTypeNode structureNode = createAndSelectStructure(structName);
		CategoryNode category3Node = (CategoryNode) structureNode.getParent();

		// drag/move ArrayStruct to MISC/ArrayStruct
		CategoryNode miscNode = (CategoryNode) programNode.getChild("MISC");
		expandNode(miscNode);

		DataTypeNode miscStructureNode = (DataTypeNode) miscNode.getChild("ArrayStruct");
		DataType origDt = miscStructureNode.getDataType();

		TreePath structureNodePath = structureNode.getTreePath();
		TreePath category3Path = category3Node.getTreePath();
		TreePath miscPath = miscNode.getTreePath();

		copyNodeToNode(structureNode, miscStructureNode);

		pressButtonOnOptionDialog("No");

		structureNode = (DataTypeNode) tree.getViewNodeForPath(structureNodePath);
		assertNotNull(structureNode.getParent());

		category3Node = (CategoryNode) tree.getViewNodeForPath(category3Path);
		assertNotNull(category3Node.getChild("ArrayStruct"));

		miscNode = (CategoryNode) tree.getViewNodeForPath(miscPath);
		DataTypeNode node = (DataTypeNode) miscNode.getChild(structName);
		assertEquals(origDt, node.getDataType());
	}

	@Test
	public void testCopyReplaceDataTypeYes() throws Exception {
		// drag/copy a data type onto another data type
		// get Option dialog, and choose "Yes"
		// cause a conflict
		// in the program, rename Category1/Category2/Category3/IntStruct to ArrayStruct
		String structName = "ArrayStruct";
		DataTypeNode structureNode = createAndSelectStructure(structName);
		Structure structure = (Structure) structureNode.getDataType();
		CategoryNode category3Node = (CategoryNode) structureNode.getParent();

		// drag/move ArrayStruct to MISC/ArrayStruct
		String miscName = "MISC";
		CategoryNode miscNode = (CategoryNode) programNode.getChild(miscName);
		expandNode(miscNode);

		DataTypeNode miscStructureNode = (DataTypeNode) miscNode.getChild("ArrayStruct");
		DataType miscStructure = miscStructureNode.getDataType();

		TreePath structureNodePath = structureNode.getTreePath();
		TreePath category3Path = category3Node.getTreePath();
		TreePath miscPath = miscNode.getTreePath();

		copyNodeToNode(structureNode, miscStructureNode);

		pressButtonOnOptionDialog("Yes");

		structureNode = (DataTypeNode) tree.getViewNodeForPath(structureNodePath);
		assertNotNull(structureNode.getParent());

		category3Node = (CategoryNode) tree.getViewNodeForPath(category3Path);
		assertNotNull(category3Node.getChild(structName));

		miscNode = (CategoryNode) tree.getViewNodeForPath(miscPath);
		DataTypeNode node = (DataTypeNode) miscNode.getChild(structName);
		assertTrue(structure.isEquivalent(node.getDataType()));

		undo();

		miscNode = (CategoryNode) programNode.getChild(miscName);
		node = (DataTypeNode) miscNode.getChild(structName);
		assertTrue(miscStructure.isEquivalent(node.getDataType()));

		redo();

		miscNode = (CategoryNode) programNode.getChild(miscName);
		node = (DataTypeNode) miscNode.getChild(structName);
		assertTrue(structure.isEquivalent(node.getDataType()));
	}

//==================================================================================================
// Private Refactored Methods
//==================================================================================================

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

		int transactionID = program.startTransaction("test");
		structure.setName(structureName);
		program.endTransaction(transactionID, true);
		waitForProgram();

		structureNode = (DataTypeNode) category3Node.getChild(structureName);
		selectNode(structureNode);
		return structureNode;
	}

	/**
	 * Copies the currently selected node to the node by the given name.
	 */
	private CategoryNode copyPasteSelectedNodeToNode(String toNodeName) throws Exception {
		DockingActionIf copyAction = getAction(plugin, "Copy");
		assertTrue(copyAction.isEnabled());
		DataTypeTestUtils.performAction(copyAction, tree);

		CategoryNode miscNode = (CategoryNode) programNode.getChild(toNodeName);
		expandNode(miscNode);
		selectNode(miscNode);

		executeOnSwingWithoutBlocking(() -> {
			DockingActionIf pasteAction = getAction(plugin, "Paste");
			DataTypeTestUtils.performAction(pasteAction, tree);
		});
		return miscNode;
	}

	private CategoryNode cutPasteSelectedNodeToNode(String toNodeName) throws Exception {
		DockingActionIf cutAction = getAction(plugin, "Cut");
		DataTypeTestUtils.performAction(cutAction, tree);

		final CategoryNode miscNode = (CategoryNode) programNode.getChild(toNodeName);
		expandNode(miscNode);
		selectNode(miscNode);

		executeOnSwingWithoutBlocking(() -> {
			DockingActionIf pasteAction = getAction(plugin, "Paste");
			DataTypeTestUtils.performAction(pasteAction, tree);
		});
		return miscNode;
	}

	private void pressButtonOnOptionDialog(String buttonName) throws Exception {
		OptionDialog d = waitForDialogComponent(OptionDialog.class);
		JButton button = findButtonByText(d, buttonName);
		assertNotNull(button);
		pressButton(button);
		waitForProgram();
	}

	private void dragNodeToNode(GTreeNode fromNode, final GTreeNode toNode) {
		final GTreeDragNDropHandler dragNDropHandler = tree.getDragNDropHandler();
		List<GTreeNode> dropList = new ArrayList<>();
		dropList.add(fromNode);
		final Transferable transferable = new GTreeNodeTransferable(dragNDropHandler, dropList);

		runSwing(
			() -> dragNDropHandler.drop(toNode, transferable, DnDConstants.ACTION_MOVE), false);
		waitForSwing();
	}

	private void copyNodeToNode(GTreeNode fromNode, final GTreeNode toNode) throws Exception {
		final GTreeDragNDropHandler dragNDropHandler = tree.getDragNDropHandler();
		List<GTreeNode> dropList = new ArrayList<>();
		dropList.add(fromNode);
		final Transferable transferable = new GTreeNodeTransferable(dragNDropHandler, dropList);

		runSwing(
			() -> dragNDropHandler.drop(toNode, transferable, DnDConstants.ACTION_COPY), false);
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
