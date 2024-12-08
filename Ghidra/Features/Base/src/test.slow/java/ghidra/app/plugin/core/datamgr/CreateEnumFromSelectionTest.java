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
import ghidra.app.plugin.core.datamgr.tree.*;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import utility.function.ExceptionalCallback;

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

	private DockingActionIf action;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		program = buildProgram();
		tool = env.launchDefaultTool(program);

		plugin = env.getPlugin(DataTypeManagerPlugin.class);
		provider = plugin.getProvider();
		tree = provider.getGTree();
		waitForTree();
		archiveRootNode = (ArchiveRootNode) tree.getModelRoot();
		programNode = (ArchiveNode) archiveRootNode.getChild(PROGRAM_FILENAME);
		assertNotNull("Did not successfully wait for the program node to load", programNode);

		tool.showComponentProvider(provider, true);

		action = getAction(plugin, "Enum From Selection");
		assertNotNull(action);
	}

	private ProgramDB buildProgram() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("notepad", ProgramBuilder._TOY, this);
		builder.createMemory("mem", "0x100", 100);
		return builder.getProgram();
	}

	@After
	public void tearDown() throws Exception {

		plugin.getEditorManager().dismissEditors(null);// Close all editors that might be open.
		executeOnSwingWithoutBlocking(() -> {
			ProgramManager pm = tool.getService(ProgramManager.class);
			pm.closeProgram();
		});

		// this handles the save changes dialog and potential analysis dialogs
		closeAllWindows();
		env.dispose();
	}

	@Test
	public void testCreateEnumFromSelection() throws Exception {

		// This test tests basic functionality of the 'create enum from selection' action

		createTwoUniqueEnums();

		selectAndMergeTwoEnums("Colors", "MoreColors");

		Window window = waitForWindow("Enter Enum Name");
		JTextField tf = findComponent(window, JTextField.class);
		setText(tf, "myNewEnum");
		pressButtonByText(window, "OK");
		assertFalse(window.isShowing());

		Enum newEnum = getEnum("myNewEnum");
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
	public void testCreateEnumFromSelection_DuplicateName() throws Exception {

		// This test tests enum name collisions are handled correctly

		createTwoUniqueEnums();

		// create an enum that we will use to trigger a name conflict
		String existingEnumName = "myNewEnum";
		tx(() -> {
			Enum e = new EnumDataType(existingEnumName, 1);
			e.add("Purple", 0x30);
			e.add("White", 0x40);
			e.add("Yellow", 0x50);

			programNode.getCategory().addDataType(e, null);
		});

		selectAndMergeTwoEnums("Colors", "MoreColors");

		Window window = waitForWindow("Enter Enum Name");
		JTextField tf = findComponent(window, JTextField.class);
		setText(tf, existingEnumName);
		pressButtonByText(window, "OK");

		//
		// We used an existing name; handle the new dialog
		//
		Window window2 = waitForWindow("Duplicate Enum Name");
		JTextField tf2 = findComponent(window2, JTextField.class);

		String validName = "myNewEnum2";
		setText(tf2, validName);
		pressButtonByText(window2, "OK");
		assertFalse(window2.isShowing());

		assertNotNull(getEnum(validName));
	}

	@Test
	public void testCreateEnumFromSelectionDupeEntryNameOrValue() throws Exception {

		// This test tests handing of duplicate entry names and values
		// duplicate value different name - add both
		// duplicate name and value - just add one entry with that combo
		// duplicate name different value - add second name with _ appended and a comment to
		// indicate change

		createTwoEnumsWithDuplicateNamesAndValues();

		createEnumFromSelection();

		Window window = waitForWindow("Enter Enum Name");
		JTextField tf = findComponent(window, JTextField.class);
		assertNotNull(tf);

		String newEnumName = "myNewEnum";
		setText(tf, newEnumName);
		pressButtonByText(window, "OK");
		assertFalse(window.isShowing());
		waitForTree();

		Window dialog = waitForWindowByTitleContaining("Duplicate Entry");
		close(dialog);

		Enum newEnum = getEnum(newEnumName);
		long values[] = newEnum.getValues();
		assertEquals(values.length, 7);
		String names[] = newEnum.getNames();
		assertEquals(names.length, 8);

		assertEquals(newEnum.getName(0x00L), "Red");
		assertEquals(newEnum.getName(0x5L), "Green_"); // underscore for name conflict
		assertEquals(newEnum.getName(0x10L), "Black"); // getName() return first alphabetically
		assertEquals(newEnum.getName(0x20L), "Blue");
		assertEquals(newEnum.getName(0x30L), "Purple");
		assertEquals(newEnum.getName(0x40L), "White");
		assertEquals(newEnum.getName(0x50L), "Yellow");

		String[] namesfor10 = newEnum.getNames(0x10);
		assertEquals(namesfor10.length, 2);
		assertEquals(namesfor10[0], "Black");
		assertEquals(namesfor10[1], "Green");

		assertEquals(newEnum.getValue("Red"), 0x00L);
		assertEquals(newEnum.getValue("Green_"), 0x5L); // underscore for name conflict
		assertEquals(newEnum.getValue("Green"), 0x10L);
		assertEquals(newEnum.getValue("Black"), 0x10L);
		assertEquals(newEnum.getValue("Blue"), 0x20L);
		assertEquals(newEnum.getValue("Purple"), 0x30L);
		assertEquals(newEnum.getValue("White"), 0x40L);
		assertEquals(newEnum.getValue("Yellow"), 0x50L);
	}

	@Test
	public void testActionEnablementOnSingleSelection() throws Exception {

		createTwoUniqueEnums();

		selectEnum("Colors");

		// action not enabled when a single enum is selected
		assertFalse(action.isEnabledForContext(provider.getActionContext(null)));
		assertFalse(action.isAddToPopup(provider.getActionContext(null)));
	}

	private <E extends Exception> void tx(ExceptionalCallback<E> c) {
		Category category = programNode.getCategory();
		DataTypeManager dtm = category.getDataTypeManager();
		int txId = dtm.startTransaction("Test - Data Type Manager Transaction");
		boolean commit = true;
		try {
			c.call();
		}
		catch (Exception e) {
			commit = false;
			failWithException("Exception modifying program '" + dtm.getName() + "'", e);
		}
		finally {
			dtm.endTransaction(txId, commit);
		}

		dtm.flushEvents();
		program.flushEvents();
		waitForTree();
	}

	private void expandNode(GTreeNode node) {
		tree.expandPath(node);
		waitForTree();
	}

	private void selectNodes(GTreeNode... nodes) {
		List<TreePath> paths = new ArrayList<>(nodes.length);
		for (GTreeNode node : nodes) {
			paths.add(node.getTreePath());
		}

		tree.setSelectionPaths(paths);
		waitForTree();
	}

	private void waitForTree() {
		waitForTree(tree);
	}

	private void performEnumFromSelectionAction() {
		executeOnSwingWithoutBlocking(new Runnable() {
			@Override
			public void run() {
				DataTypeTestUtils.performAction(action, tree);
			}
		});
	}

	private void createEnumFromSelection() {

		DataTypeNode testEnumNode1 = (DataTypeNode) programNode.getChild("Colors");
		assertNotNull(testEnumNode1);

		DataTypeNode testEnumNode2 = (DataTypeNode) programNode.getChild("MoreColors");
		assertNotNull(testEnumNode2);

		expandNode(programNode);
		selectNodes(testEnumNode1, testEnumNode2);
		waitForTree();

		performEnumFromSelectionAction();
	}

	private void createTwoEnumsWithDuplicateNamesAndValues() {

		Category category = programNode.getCategory();
		DataTypeManager dtm = category.getDataTypeManager();

		tx(() -> {
			Enum enumm = new EnumDataType("Colors", 1);
			enumm.add("Red", 0);
			enumm.add("Green", 0x10);
			enumm.add("Blue", 0x20);

			category.addDataType(enumm, null);
		});

		waitForTree();

		tx(() -> {
			Enum enumm2 = new EnumDataType("MoreColors", 1);
			enumm2.add("Red", 0); // add dup name same value
			enumm2.add("Green", 0x5); // add dup name different value
			enumm2.add("Black", 0x10); // add dup value different name
			enumm2.add("Purple", 0x30);
			enumm2.add("White", 0x40);
			enumm2.add("Yellow", 0x50);

			category.addDataType(enumm2, null);
		});

		dtm.flushEvents();
		waitForTree();
	}

	private void createTwoUniqueEnums() {
		Category category = programNode.getCategory();
		DataTypeManager dtm = category.getDataTypeManager();

		int id = dtm.startTransaction("new enum 1");
		Enum enumm = new EnumDataType("Colors", 1);
		enumm.add("Red", 0);
		enumm.add("Green", 0x10);
		enumm.add("Blue", 0x20);

		category.addDataType(enumm, null);
		dtm.endTransaction(id, true);
		waitForTree();

		int id2 = dtm.startTransaction("new enum 2");
		Enum enumm2 = new EnumDataType("MoreColors", 1);
		enumm2.add("Purple", 0x30);
		enumm2.add("White", 0x40);
		enumm2.add("Yellow", 0x50);

		category.addDataType(enumm2, null);
		dtm.endTransaction(id2, true);
		waitForTree();

	}

	private void selectAndMergeTwoEnums(String name1, String name2) {
		DataTypeNode colorsNode = (DataTypeNode) programNode.getChild(name1);
		assertNotNull(colorsNode);

		DataTypeNode moreColorsNode = (DataTypeNode) programNode.getChild(name2);
		assertNotNull(moreColorsNode);

		expandNode(programNode);
		selectNodes(colorsNode, moreColorsNode);

		performEnumFromSelectionAction();
	}

	private void selectEnum(String name) {
		DataTypeNode node = (DataTypeNode) programNode.getChild(name);
		assertNotNull(node);
		expandNode(programNode);
		selectNodes(node);
	}

	private Enum getEnum(String name) {
		waitForTree();
		DataTypeNode newEnumNode = (DataTypeNode) programNode.getChild(name);
		assertNotNull(newEnumNode);
		return (Enum) newEnumNode.getDataType();
	}
}
