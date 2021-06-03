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

import java.util.ArrayList;
import java.util.List;

import javax.swing.JButton;
import javax.swing.tree.TreePath;

import org.junit.*;

import docking.ActionContext;
import docking.action.*;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import ghidra.app.plugin.core.datamgr.tree.*;
import ghidra.app.plugin.core.datamgr.util.DataTypeChooserDialog;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;

/**
 * Test the favorites and data manager services.
 */
public class FavoritesAndMiscTest extends AbstractGhidraHeadedIntegrationTest {

	private static final String PROGRAM_NAME = "notepad";

	private TestEnv env;
	private PluginTool tool;
	private ProgramDB program;
	private DataTypeManagerPlugin plugin;
	private DataTypesProvider provider;
	private DataTypeArchiveGTree tree;
	private ArchiveRootNode archiveRootNode;
	private ArchiveNode builtInNode;
	private ToggleDockingAction favoritesAction;
	private ArchiveNode programNode;

	@Before
	public void setUp() throws Exception {
		clearFavorites();// tool will initialize defaults
		env = new TestEnv();

		program = buildProgram();
		tool = env.launchDefaultTool(program);

		plugin = env.getPlugin(DataTypeManagerPlugin.class);
		provider = plugin.getProvider();
		tree = provider.getGTree();
		waitForTree();

		archiveRootNode = (ArchiveRootNode) tree.getModelRoot();
		builtInNode = (ArchiveNode) archiveRootNode.getChild("BuiltInTypes");
		programNode = (ArchiveNode) archiveRootNode.getChild(PROGRAM_NAME);

		tool.showComponentProvider(provider, true);
		favoritesAction = (ToggleDockingAction) getAction(plugin, "Set Favorite Data Type");
	}

	private ProgramDB buildProgram() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("notepad", ProgramBuilder._TOY, this);

		builder.createMemory(".text", "0x1001000", 0x100);
		CategoryPath miscPath = new CategoryPath("/MISC");
		builder.addCategory(miscPath);
		StructureDataType struct = new StructureDataType("ArrayStruct", 4);
		struct.setCategoryPath(miscPath);
		builder.addDataType(struct);
		CategoryPath cat1Path = new CategoryPath("/Category1");
		builder.addCategory(cat1Path);
		CategoryPath cat2Path = new CategoryPath(cat1Path, "Category2");
		builder.addCategory(cat2Path);
		CategoryPath cat4Path = new CategoryPath(cat2Path, "Category4");
		builder.addCategory(cat4Path);
		builder.addCategory(new CategoryPath(cat2Path, "Category5"));

		CategoryPath cat3Path = new CategoryPath(cat2Path, "Category3");
		builder.addCategory(cat3Path);
		return builder.getProgram();
	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

	@Test
	public void testSetFavorites1() throws Exception {
		tree.expandPath(builtInNode);
		waitForTree();
		DataTypeNode node = (DataTypeNode) builtInNode.getChild("undefined1");
		assertTrue(!node.isFavorite());

		tree.setSelectedNode(node);
		waitForTree();

		favoritesAction.isEnabledForContext(createContext(node));
		assertTrue(favoritesAction.isEnabled());
		assertTrue(!favoritesAction.isSelected());

		performToggleAction(favoritesAction, true);
		assertTrue(node.isFavorite());
	}

	@Test
	public void testSetFavorites2() throws Exception {
		tree.expandPath(builtInNode);
		waitForTree();
		DataTypeNode node = (DataTypeNode) builtInNode.getChild("byte");
		assertTrue(node.isFavorite());

		tree.setSelectedNode(node);
		waitForTree();

		favoritesAction.isEnabledForContext(createContext(node));
		assertTrue(favoritesAction.isEnabled());
		assertTrue(favoritesAction.isSelected());

		performToggleAction(favoritesAction, false);
		assertTrue(!node.isFavorite());
	}

	@Test
	public void testSetFavorites3() throws Exception {
		env.showTool();

		tree.expandPath(builtInNode);
		waitForTree();
		DataTypeNode node = (DataTypeNode) builtInNode.getChild("byte");
		assertTrue(node.isFavorite());

		tree.setSelectedNode(node);
		waitForTree();

		favoritesAction.isEnabledForContext(createContext(node));
		assertTrue(favoritesAction.isEnabled());
		assertTrue(favoritesAction.isSelected());

		performToggleAction(favoritesAction, false);
		assertTrue(!node.isFavorite());

		performToggleAction(favoritesAction, true);
		assertTrue(node.isFavorite());

	}

	@Test
	public void testListeners() throws Exception {
		MyChangeListener changeListener = new MyChangeListener();
		plugin.addDataTypeManagerChangeListener(changeListener);

		tree.expandPath(builtInNode);
		waitForTree();
		DataTypeNode node = (DataTypeNode) builtInNode.getChild("PascalUnicode");

		tree.setSelectedNode(node);
		waitForTree();

		performToggleAction(favoritesAction, true);
		waitForSwing();

		List<DataType> dts = changeListener.getFavoriteDts();
		boolean found = false;
		for (int i = 0; i < dts.size(); i++) {
			if (dts.get(i).getName().equals("PascalUnicode")) {
				found = true;
				break;
			}
		}
		if (!found) {
			Assert.fail("Did not find MBCString as a favorite!");
		}

		// turn off favorite
		tree.setSelectedNode(node);

		performToggleAction(favoritesAction, false);
		waitForSwing();

		dts = changeListener.getFavoriteDts();
		for (int i = 0; i < dts.size(); i++) {
			if (dts.get(i).getName().equals("MBCString")) {
				Assert.fail("Should not have found MBCString as a favorite!");
			}
		}
	}

	@Test
	public void testMultiSelectionFavorites() throws Exception {
		// select some favorites and some not favorites
		// favorites action should be disabled
		tree.expandPath(builtInNode);
		waitForTree();
		DataTypeNode node1 = (DataTypeNode) builtInNode.getChild("PascalUnicode");
		DataTypeNode node2 = (DataTypeNode) builtInNode.getChild("undefined1");
		DataTypeNode node3 = (DataTypeNode) builtInNode.getChild("byte");

		tree.setSelectionPaths(new TreePath[] { node1.getTreePath(), node2.getTreePath() });
		waitForTree();

		assertTrue(favoritesAction.isEnabledForContext(createContext(node2)));

		// Invalid selection - mixed favorite and non-favorite
		tree.setSelectionPaths(
			new TreePath[] { node1.getTreePath(), node2.getTreePath(), node3.getTreePath() });
		waitForTree();

		assertTrue(!favoritesAction.isEnabledForContext(createContext(node3)));

		// Valid
		tree.setSelectionPaths(new TreePath[] { node1.getTreePath(), node2.getTreePath() });
		waitForTree();

		assertTrue(favoritesAction.isEnabledForContext(createContext(node2)));

		// now make sure that a mixture of node types is not a valid context
		tree.setSelectionPaths(
			new TreePath[] { node1.getTreePath(), node2.getTreePath(), builtInNode.getTreePath() });
		waitForTree();

		assertTrue(!favoritesAction.isEnabledForContext(createContext(node2)));
	}

	@Test
	public void testMultiSelectionAddAndRemoveFavorites() throws Exception {
		tree.expandPath(builtInNode);
		waitForTree();
		DataTypeNode node = (DataTypeNode) builtInNode.getChild("PascalUnicode");
		DataTypeNode node2 = (DataTypeNode) builtInNode.getChild("undefined1");
		DataTypeNode node3 = (DataTypeNode) builtInNode.getChild("undefined2");
		DataTypeNode node4 = (DataTypeNode) builtInNode.getChild("undefined4");

		tree.setSelectionPaths(new TreePath[] { node.getTreePath(), node2.getTreePath(),
			node3.getTreePath(), node4.getTreePath() });
		waitForTree();

		assertTrue(favoritesAction.isEnabledForContext(createContext(node2)));

		performToggleAction(favoritesAction, true);

		assertTrue(node.isFavorite());
		assertTrue(node2.isFavorite());
		assertTrue(node3.isFavorite());
		assertTrue(node4.isFavorite());

		performToggleAction(favoritesAction, false);

		assertTrue(!node.isFavorite());
		assertTrue(!node2.isFavorite());
		assertTrue(!node3.isFavorite());
		assertTrue(!node4.isFavorite());

	}

	@Test
	public void testSaveRestoreFavorites() throws Exception {
		env.showTool();

		tree.expandPath(builtInNode);
		waitForTree();
		DataTypeNode node = (DataTypeNode) builtInNode.getChild("PascalUnicode");
		DataTypeNode node2 = (DataTypeNode) builtInNode.getChild("undefined1");
		DataTypeNode node3 = (DataTypeNode) builtInNode.getChild("undefined2");
		DataTypeNode node4 = (DataTypeNode) builtInNode.getChild("undefined4");

		tree.setSelectionPaths(new TreePath[] { node.getTreePath(), node2.getTreePath(),
			node3.getTreePath(), node4.getTreePath() });
		waitForTree();

		assertTrue(favoritesAction.isEnabledForContext(createContext(node4)));

		performToggleAction(favoritesAction, true);

		List<DataType> dts = plugin.getFavorites();

		env.saveRestoreToolState();

		plugin = getPlugin(tool, DataTypeManagerPlugin.class);
		List<DataType> newdts = plugin.getFavorites();
		assertEquals(dts.size(), newdts.size());
		for (int i = 0; i < dts.size(); i++) {
			assertTrue(dts.get(i).isEquivalent(newdts.get(i)));
		}
	}

	@Test
	public void testGetSetMostRecentlyUsed() throws Exception {
		DataType dt = new ByteDataType();
		plugin.setRecentlyUsed(dt);
		assertTrue(dt.isEquivalent(plugin.getRecentlyUsed()));

		ArrayList<DataType> list = new ArrayList<>();
		program.getListing().getDataTypeManager().findDataTypes("ArrayStruct", list);
		dt = list.get(0);
		plugin.setRecentlyUsed(dt);
		assertTrue(dt.isEquivalent(plugin.getRecentlyUsed()));
	}

	@Test
	public void testGetChosenDataType() throws Exception {
		env.showTool();
		expandNode(programNode);
		CategoryNode cat1Node = (CategoryNode) programNode.getChild("Category1");
		expandNode(cat1Node);
		CategoryNode cat2Node = (CategoryNode) cat1Node.getChild("Category2");
		expandNode(cat2Node);
		CategoryNode cat3Node = (CategoryNode) cat2Node.getChild("Category3");
		expandNode(cat3Node);

		Structure struct = new StructureDataType("ArrayStruct", 0);
		struct.add(new ByteDataType());
		struct.add(new WordDataType());

		int transactionID = program.startTransaction("test");
		Category c = cat3Node.getCategory();
		c.addDataType(struct, null);
		program.endTransaction(transactionID, true);

		program.flushEvents();
		waitForSwing();

		runSwing(() -> plugin.getDataType("ArrayStruct"), false);

		DataTypeChooserDialog d =
			waitForDialogComponent(tool.getToolFrame(), DataTypeChooserDialog.class, 2000);

		assertNotNull(d);

		GTree gtree = (GTree) getInstanceField("tree", d);
		waitForTree(gtree);

		ArchiveRootNode root = (ArchiveRootNode) gtree.getModelRoot();
		ArchiveNode programNode1 = (ArchiveNode) root.getChild(PROGRAM_NAME);

		assertNotNull("could not find " + PROGRAM_NAME + " in " + root, programNode1);
		expandNode(programNode1);
		cat1Node = (CategoryNode) programNode1.getChild("Category1");
		expandNode(cat1Node);
		cat2Node = (CategoryNode) cat1Node.getChild("Category2");
		expandNode(cat2Node);
		cat3Node = (CategoryNode) cat2Node.getChild("Category3");
		expandNode(cat3Node);

		DataTypeNode structNode = (DataTypeNode) cat3Node.getChild("ArrayStruct");
		DataType s = structNode.getDataType();

		gtree.setSelectedNode(structNode);
		waitForTree(gtree);

		JButton okButton = (JButton) getInstanceField("okButton", d);
		assertTrue(okButton.isEnabled());
		runSwing(() -> okButton.doClick());

		DataType selectedDataType = d.getSelectedDataType();
		assertEquals(selectedDataType, s);
	}

	@Test
	public void testCollapseAllDtms() {
		env.showTool();

		List<GTreeNode> children = archiveRootNode.getChildren();
		for (GTreeNode node : children) {
			expandNode(node);
		}

		DockingActionIf collapseAllAction = getAction(plugin, "Collapse All");
		assertNotNull(collapseAllAction);
		assertTrue(collapseAllAction.isEnabled());
		runSwing(() -> {
			ActionContext context = new DataTypesActionContext(null, null, tree, null, true);
			collapseAllAction.actionPerformed(context);
		}, true);
		waitForTree();

		for (GTreeNode node : children) {
			assertTrue(!tree.isExpanded(node.getTreePath()));
		}
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private class MyChangeListener extends DataTypeManagerChangeListenerAdapter {
		private List<DataType> favoriteDts;

		@Override
		public void favoritesChanged(DataTypeManager dtm, DataTypePath path, boolean isFavorite) {
			favoriteDts = plugin.getFavorites();
		}

		List<DataType> getFavoriteDts() {
			return favoriteDts;
		}
	}

	private ActionContext createContext(GTreeNode node) {
		return new DataTypesActionContext(provider, program, tree, node);
	}

	private void performToggleAction(ToggleDockingActionIf action, boolean selected) {
		ActionContext context = createContext(null);
		runSwing(() -> {
			action.setSelected(selected);
			action.actionPerformed(context);
		});

	}

	private void waitForTree() {
		waitForTree(tree);
	}

	private void expandNode(GTreeNode node) {
		tree.expandPath(node);
		waitForTree();
	}

	private void clearFavorites() {
		BuiltInDataTypeManager dataTypeManager = BuiltInDataTypeManager.getDataTypeManager();
		for (DataType dt : dataTypeManager.getFavorites()) {
			dataTypeManager.setFavorite(dt, false);
		}
	}

}
