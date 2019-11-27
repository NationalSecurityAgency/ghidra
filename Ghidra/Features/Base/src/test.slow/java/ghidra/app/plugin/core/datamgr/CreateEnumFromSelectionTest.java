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

import java.awt.Window;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JTextField;
import javax.swing.tree.TreePath;

import org.junit.*;

import docking.action.DockingActionIf;
import docking.widgets.tree.GTreeNode;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.datamgr.tree.*;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;

/**
 * Tests for the 'make enum from a selection' action
 */
public class CreateEnumFromSelectionTest extends AbstractGhidraHeadedIntegrationTest {
	private static final String PROGRAM_FILENAME = "notepad";

	private PluginTool tool;
	private ProgramDB program;
	private TestEnv env;
	private DataTypeManagerPlugin plugin;
	private DataTypesProvider provider;
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
		tree = provider.getGTree();
		waitForTree();
		archiveRootNode = (ArchiveRootNode) tree.getModelRoot();
		programNode = (ArchiveNode) archiveRootNode.getChild(PROGRAM_FILENAME);
		assertNotNull("Did not successfully wait for the program node to load", programNode);

		tool.showComponentProvider(provider, true);
	}

	private ProgramDB buildProgram() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("notepad", ProgramBuilder._TOY, this);
		builder.createMemory("mem", "0x100", 100);

		return builder.getProgram();
	}

	@After
	public void tearDown() throws Exception {

		plugin.getEditorManager().dismissEditors(null);// Close all editors that might be open.
		executeOnSwingWithoutBlocking(new Runnable() {
			@Override
			public void run() {
				ProgramManager pm = tool.getService(ProgramManager.class);
				pm.closeProgram();
			}
		});

		// this handles the save changes dialog and potential analysis dialogs
		closeAllWindows();
		env.dispose();
	}

	@Test
	public void testCreateEnumFromSelection() throws Exception {

		// make two test enums in the program name folder

		Category category = programNode.getCategory();
		DataTypeManager dataTypeManager = category.getDataTypeManager();

		int id = dataTypeManager.startTransaction("new enum 1");
		Enum enumm = new EnumDataType("Colors", 1);
		enumm.add("Red", 0);
		enumm.add("Green", 0x10);
		enumm.add("Blue", 0x20);

		category.addDataType(enumm, null);
		dataTypeManager.endTransaction(id, true);
		waitForTree();

		int id2 = dataTypeManager.startTransaction("new enum 2");
		Enum enumm2 = new EnumDataType("MoreColors", 1);
		enumm2.add("Purple", 0x30);
		enumm2.add("White", 0x40);
		enumm2.add("Yellow", 0x50);

		category.addDataType(enumm2, null);
		dataTypeManager.endTransaction(id2, true);
		waitForTree();

		program.flushEvents();
		waitForPostedSwingRunnables();

		DataTypeNode testEnumNode1 = (DataTypeNode) programNode.getChild("Colors");
		assertNotNull(testEnumNode1);

		DataTypeNode testEnumNode2 = (DataTypeNode) programNode.getChild("MoreColors");
		assertNotNull(testEnumNode2);

		expandNode(programNode);
		selectNodes(testEnumNode1, testEnumNode2);
		waitForTree();

		final DockingActionIf action = getAction(plugin, "Enum from Selection");
		assertNotNull(action);
		assertTrue(action.isEnabledForContext(provider.getActionContext(null)));
		assertTrue(action.isAddToPopup(provider.getActionContext(null)));

		executeOnSwingWithoutBlocking(new Runnable() {
			@Override
			public void run() {
				DataTypeTestUtils.performAction(action, tree);
			}
		});

		Window window = waitForWindow("Name new ENUM");
		assertNotNull(window);

		final JTextField tf = findComponent(window, JTextField.class);
		assertNotNull(tf);

		tf.setText("myNewEnum");
		pressButtonByText(window, "OK");
		assertTrue(!window.isShowing());
		waitForPostedSwingRunnables();
		waitForTree();

		DataTypeNode newEnumNode = (DataTypeNode) programNode.getChild("myNewEnum");
		waitForTree();

		assertNotNull(newEnumNode);

		Enum newEnum = (Enum) newEnumNode.getDataType();
		long values[] = newEnum.getValues();

		assertEquals(values.length, 6);

		assertEquals(newEnum.getName(0x00L), "Red");
		assertEquals(newEnum.getName(0x10L), "Green");
		assertEquals(newEnum.getName(0x20L), "Blue");
		assertEquals(newEnum.getName(0x30L), "Purple");
		assertEquals(newEnum.getName(0x40L), "White");
		assertEquals(newEnum.getName(0x50L), "Yellow");

		assertEquals(newEnum.getValue("Red"), 0x00L);
		assertEquals(newEnum.getValue("Green"), 0x10L);
		assertEquals(newEnum.getValue("Blue"), 0x20L);
		assertEquals(newEnum.getValue("Purple"), 0x30L);
		assertEquals(newEnum.getValue("White"), 0x40L);
		assertEquals(newEnum.getValue("Yellow"), 0x50L);

	}

	@Test
	public void testCreateEnumFromSelectionDupe() throws Exception {

		// make two test enums in the program name folder

		Category category = programNode.getCategory();
		DataTypeManager dataTypeManager = category.getDataTypeManager();

		int id = dataTypeManager.startTransaction("new enum 1");
		Enum enumm = new EnumDataType("Colors", 1);
		enumm.add("Red", 0);
		enumm.add("Green", 0x10);
		enumm.add("Blue", 0x20);

		category.addDataType(enumm, null);
		dataTypeManager.endTransaction(id, true);
		waitForTree();

		int id2 = dataTypeManager.startTransaction("new enum 2");
		Enum enumm2 = new EnumDataType("MoreColors", 1);
		enumm2.add("Purple", 0x30);
		enumm2.add("White", 0x40);
		enumm2.add("Yellow", 0x50);

		category.addDataType(enumm2, null);
		dataTypeManager.endTransaction(id2, true);
		waitForTree();

		int id3 = dataTypeManager.startTransaction("new enum 3");
		Enum enumm3 = new EnumDataType("myNewEnum", 1);
		enumm3.add("Purple", 0x30);
		enumm3.add("White", 0x40);
		enumm3.add("Yellow", 0x50);

		category.addDataType(enumm3, null);
		dataTypeManager.endTransaction(id3, true);
		waitForTree();

		program.flushEvents();
		waitForPostedSwingRunnables();

		DataTypeNode testEnumNode1 = (DataTypeNode) programNode.getChild("Colors");
		assertNotNull(testEnumNode1);

		DataTypeNode testEnumNode2 = (DataTypeNode) programNode.getChild("MoreColors");
		assertNotNull(testEnumNode2);

		expandNode(programNode);
		selectNodes(testEnumNode1, testEnumNode2);

		final DockingActionIf action = getAction(plugin, "Enum from Selection");
		assertNotNull(action);
		assertTrue(action.isEnabledForContext(provider.getActionContext(null)));
		assertTrue(action.isAddToPopup(provider.getActionContext(null)));

		executeOnSwingWithoutBlocking(new Runnable() {
			@Override
			public void run() {
				DataTypeTestUtils.performAction(action, tree);
			}
		});

		Window window = waitForWindow("Name new ENUM");
		assertNotNull(window);

		final JTextField tf = findComponent(window, JTextField.class);
		assertNotNull(tf);

		tf.setText("myNewEnum");
		pressButtonByText(window, "OK");

		Window window2 = waitForWindow("Duplicate ENUM Name");
		assertNotNull(window2);

		final JTextField tf2 = findComponent(window2, JTextField.class);
		assertNotNull(tf2);

		tf2.setText("myNewEnum2");
		pressButtonByText(window2, "OK");

		assertTrue(!window2.isShowing());
		waitForPostedSwingRunnables();

		DataTypeNode newEnumNode = (DataTypeNode) programNode.getChild("myNewEnum2");
		assertNotNull(newEnumNode);

	}

	@Test
	public void testDontCreateEnumFromSingleSelection() throws Exception {

		// make two test enums in the program name folder

		Category category = programNode.getCategory();
		DataTypeManager dataTypeManager = category.getDataTypeManager();

		int id = dataTypeManager.startTransaction("new enum 1");
		Enum enumm = new EnumDataType("Colors", 1);
		enumm.add("Red", 0);
		enumm.add("Green", 0x10);
		enumm.add("Blue", 0x20);

		category.addDataType(enumm, null);
		dataTypeManager.endTransaction(id, true);
		waitForTree();

		program.flushEvents();
		waitForPostedSwingRunnables();

		DataTypeNode testEnumNode1 = (DataTypeNode) programNode.getChild("Colors");
		assertNotNull(testEnumNode1);

		expandNode(programNode);
		selectNodes(testEnumNode1);

		final DockingActionIf action = getAction(plugin, "Enum from Selection");
		assertNotNull(action);
		assertFalse(action.isEnabledForContext(provider.getActionContext(null)));
		assertFalse(action.isAddToPopup(provider.getActionContext(null)));

	}

	private void expandNode(GTreeNode node) {
		tree.expandPath(node);
		waitForTree();
	}

	private void selectNodes(GTreeNode... nodes) {
		List<TreePath> paths = new ArrayList<TreePath>(nodes.length);
		for (GTreeNode node : nodes) {
			paths.add(node.getTreePath());
		}

		tree.setSelectionPaths(paths);
		waitForTree();
	}

	private void waitForTree() {
		waitForTree(tree);
	}
}
