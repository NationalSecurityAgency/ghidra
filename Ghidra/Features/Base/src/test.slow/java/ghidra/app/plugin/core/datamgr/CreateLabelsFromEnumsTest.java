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

import javax.swing.JLabel;
import javax.swing.tree.TreePath;

import org.junit.*;

import docking.DockingWindowManager;
import docking.StatusBar;
import docking.action.DockingActionIf;
import docking.widgets.tree.GTreeNode;
import generic.test.TestUtils;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.datamgr.tree.*;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;

/**
 * Tests for the action that creates labels from the names and values in a selection of enum
 * data types.
 */
public class CreateLabelsFromEnumsTest extends AbstractGhidraHeadedIntegrationTest {
	private static final String COLOR_STRUCT_NAME = "ColorStruct";
	private static final String EVEN_MORE_COLORS_NAME = "EvenMoreColors";
	private static final String MORE_COLORS_NAME = "MoreColors";
	private static final String COLORS_NAME = "Colors";
	private static final String NO_STATUS_MESSAGE = " ";

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

		ProgramBuilder builder = new ProgramBuilder(testName.getMethodName(), ProgramBuilder._TOY);
		builder.createMemory("mem", "0x100", 100);
		program = builder.getProgram();

		ProgramManager pm = tool.getService(ProgramManager.class);
		pm.openProgram(program);

		env.showTool();

		plugin = env.getPlugin(DataTypeManagerPlugin.class);
		provider = plugin.getProvider();
		tree = provider.getGTree();
		waitForTree();
		archiveRootNode = (ArchiveRootNode) tree.getModelRoot();
		programNode = (ArchiveNode) archiveRootNode.getChild(testName.getMethodName());
		assertNotNull("Did not successfully wait for the program node to load", programNode);

		tool.showComponentProvider(provider, true);
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
		env.release(program);
		env.dispose();
	}

	@Test
	public void testCreateLabelsWhenNoSelection() throws Exception {

		Category category = programNode.getCategory();
		DataTypeManager dataTypeManager = category.getDataTypeManager();

		createStruct_ColorStruct(category, dataTypeManager);
		createEnum_Colors(category, dataTypeManager);
		createEnum_MoreColors(category, dataTypeManager);
		createEnum_EvenMoreColors(category, dataTypeManager);

		clearSelection();

		checkLabelExists(false, "Red", "0x110");
		checkLabelExists(false, "Green", "0x120");
		checkLabelExists(false, "Blue", "0x230");
		checkLabelExists(false, "Purple", "0x140");
		checkLabelExists(false, "Yellow", "0x4");
		checkLabelExists(false, "Violet", "0x2");
		checkLabelExists(false, "Black", null);
		checkLabelExists(false, "White", null);

		final DockingActionIf action = getAction(plugin, "Create Labels From Enums");
		assertNotNull(action);
		assertFalse(action.isEnabledForContext(provider.getActionContext(null)));
		assertFalse(action.isAddToPopup(provider.getActionContext(null)));

		checkStatusMessage(NO_STATUS_MESSAGE);
	}

	@Test
	public void testCreateLabelsWhenStructureSelection() throws Exception {

		Category category = programNode.getCategory();
		DataTypeManager dataTypeManager = category.getDataTypeManager();

		createStruct_ColorStruct(category, dataTypeManager);
		createEnum_Colors(category, dataTypeManager);
		createEnum_MoreColors(category, dataTypeManager);
		createEnum_EvenMoreColors(category, dataTypeManager);

		selectNodes(COLOR_STRUCT_NAME);

		checkLabelExists(false, "Red", "0x110");
		checkLabelExists(false, "Green", "0x120");
		checkLabelExists(false, "Blue", "0x230");
		checkLabelExists(false, "Purple", "0x140");
		checkLabelExists(false, "Yellow", "0x4");
		checkLabelExists(false, "Violet", "0x2");
		checkLabelExists(false, "Black", null);
		checkLabelExists(false, "White", null);

		DockingActionIf action = getAction(plugin, "Create Labels From Enums");
		assertNotNull(action);
		assertFalse(action.isEnabledForContext(provider.getActionContext(null)));
		assertFalse(action.isAddToPopup(provider.getActionContext(null)));

		checkStatusMessage(NO_STATUS_MESSAGE);
	}

	@Test
	public void testCreateLabelsWhenOnlyEnumSelection() throws Exception {

		Category category = programNode.getCategory();
		DataTypeManager dataTypeManager = category.getDataTypeManager();

		createStruct_ColorStruct(category, dataTypeManager);
		createEnum_Colors(category, dataTypeManager);
		createEnum_MoreColors(category, dataTypeManager);
		createEnum_EvenMoreColors(category, dataTypeManager);

		selectNodes(COLORS_NAME, MORE_COLORS_NAME, EVEN_MORE_COLORS_NAME);
		waitForTree();

		checkLabelExists(false, "Red", "0x110");
		checkLabelExists(false, "Green", "0x120");
		checkLabelExists(false, "Blue", "0x230");
		checkLabelExists(false, "Purple", "0x140");
		checkLabelExists(false, "Yellow", "0x4");
		checkLabelExists(false, "Violet", "0x2");
		checkLabelExists(false, "Black", null);
		checkLabelExists(false, "White", null);

		checkStatusMessage(NO_STATUS_MESSAGE);

		final DockingActionIf action = getAction(plugin, "Create Labels From Enums");
		assertNotNull(action);
		assertTrue(action.isEnabledForContext(provider.getActionContext(null)));
		assertTrue(action.isAddToPopup(provider.getActionContext(null)));

		createLabels(action);

		// Check the Listing or Symbol Table to verify the expected labels were created.
		checkLabelExists(true, "Red", "0x110");
		checkLabelExists(true, "Green", "0x120");
		checkLabelExists(false, "Blue", "0x230");
		checkLabelExists(true, "Purple", "0x140");
		checkLabelExists(false, "Yellow", "0x4");
		checkLabelExists(false, "Violet", "0x2");
		checkLabelExists(false, "Black", null);
		checkLabelExists(false, "White", null);

		checkStatusMessage("Labels created: 3.");
	}

	@Test
	public void testCreateLabelsWhenSingleEnumSelection() throws Exception {

		Category category = programNode.getCategory();
		DataTypeManager dataTypeManager = category.getDataTypeManager();

		createStruct_ColorStruct(category, dataTypeManager);

		createEnum_Colors(category, dataTypeManager);
		createEnum_MoreColors(category, dataTypeManager);
		createEnum_EvenMoreColors(category, dataTypeManager);

		selectNodes(MORE_COLORS_NAME);

		checkLabelExists(false, "Red", "0x110");
		checkLabelExists(false, "Green", "0x120");
		checkLabelExists(false, "Blue", "0x230");
		checkLabelExists(false, "Purple", "0x140");
		checkLabelExists(false, "Yellow", "0x4");
		checkLabelExists(false, "Violet", "0x2");
		checkLabelExists(false, "Black", null);
		checkLabelExists(false, "White", null);

		checkStatusMessage(NO_STATUS_MESSAGE);

		final DockingActionIf action = getAction(plugin, "Create Labels From Enums");
		assertNotNull(action);
		assertTrue(action.isEnabledForContext(provider.getActionContext(null)));
		assertTrue(action.isAddToPopup(provider.getActionContext(null)));

		createLabels(action);

		// Check the Listing or Symbol Table to verify the expected labels were created.
		checkLabelExists(false, "Red", "0x110");
		checkLabelExists(false, "Green", "0x120");
		checkLabelExists(false, "Blue", "0x230");
		checkLabelExists(true, "Purple", "0x140");
		checkLabelExists(false, "Yellow", "0x4");
		checkLabelExists(false, "Violet", "0x2");
		checkLabelExists(false, "Black", null);
		checkLabelExists(false, "White", null);

		checkStatusMessage("Labels created: 1.");

		createLabels(action);

		// Check the Listing or Symbol Table to verify the expected labels were created.
		checkLabelExists(false, "Red", "0x110");
		checkLabelExists(false, "Green", "0x120");
		checkLabelExists(false, "Blue", "0x230");
		checkLabelExists(true, "Purple", "0x140");
		checkLabelExists(false, "Yellow", "0x4");
		checkLabelExists(false, "Violet", "0x2");
		checkLabelExists(false, "Black", null);
		checkLabelExists(false, "White", null);

		checkStatusMessage("Couldn't create any labels for the selected data types. " +
			"Some labels already exist.");
	}

	@Test
	public void testCreateLabelsWhenMixedSelection() throws Exception {

		Category category = programNode.getCategory();
		DataTypeManager dataTypeManager = category.getDataTypeManager();

		createStruct_ColorStruct(category, dataTypeManager);
		createEnum_Colors(category, dataTypeManager);
		createEnum_MoreColors(category, dataTypeManager);
		createEnum_EvenMoreColors(category, dataTypeManager);

		selectNodes(COLOR_STRUCT_NAME, COLORS_NAME, MORE_COLORS_NAME, EVEN_MORE_COLORS_NAME);

		checkLabelExists(false, "Red", "0x110");
		checkLabelExists(false, "Green", "0x120");
		checkLabelExists(false, "Blue", "0x230");
		checkLabelExists(false, "Purple", "0x140");
		checkLabelExists(false, "Yellow", "0x4");
		checkLabelExists(false, "Violet", "0x2");
		checkLabelExists(false, "Black", null);
		checkLabelExists(false, "White", null);

		checkStatusMessage(NO_STATUS_MESSAGE);

		final DockingActionIf action = getAction(plugin, "Create Labels From Enums");
		assertNotNull(action);
		assertTrue(action.isEnabledForContext(provider.getActionContext(null)));
		assertTrue(action.isAddToPopup(provider.getActionContext(null)));

		createLabels(action);

		// Check the Listing or Symbol Table to verify the expected labels were created.
		checkLabelExists(true, "Red", "0x110");
		checkLabelExists(true, "Green", "0x120");
		checkLabelExists(false, "Blue", "0x230");
		checkLabelExists(true, "Purple", "0x140");
		checkLabelExists(false, "Yellow", "0x4");
		checkLabelExists(false, "Violet", "0x2");
		checkLabelExists(false, "Black", null);
		checkLabelExists(false, "White", null);

		checkStatusMessage("Labels created: 3.");
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private void createStruct_ColorStruct(Category category, DataTypeManager dataTypeManager) {
		int id0 = dataTypeManager.startTransaction("new structure 1");
		Structure struct0 = new StructureDataType(COLOR_STRUCT_NAME, 12);
		struct0.insert(0, new FloatDataType(), 0x4, "Black", null);
		struct0.add(new ByteDataType(), "White", null);

		category.addDataType(struct0, null);
		dataTypeManager.endTransaction(id0, true);
		waitForTree();
	}

	private void createEnum_EvenMoreColors(Category category, DataTypeManager dataTypeManager) {
		int id3 = dataTypeManager.startTransaction("new enum 3");
		EnumDataType enumm3 = new EnumDataType(EVEN_MORE_COLORS_NAME, 1);
		enumm3.setLength(1);
		enumm3.add("Violet", 0x2);

		category.addDataType(enumm3, null);
		dataTypeManager.endTransaction(id3, true);
		waitForTree();
	}

	private void createEnum_MoreColors(Category category, DataTypeManager dataTypeManager) {
		int id2 = dataTypeManager.startTransaction("new enum 2");
		EnumDataType enumm2 = new EnumDataType(MORE_COLORS_NAME, 1);
		enumm2.setLength(4);
		enumm2.add("Purple", 0x140);
		enumm2.add("Yellow", 0x4);

		category.addDataType(enumm2, null);
		dataTypeManager.endTransaction(id2, true);
		waitForTree();
	}

	private void createEnum_Colors(Category category, DataTypeManager dataTypeManager) {
		int id = dataTypeManager.startTransaction("new enum 1");
		EnumDataType enumm = new EnumDataType(COLORS_NAME, 1);
		enumm.setLength(4);
		enumm.add("Red", 0x110);
		enumm.add("Green", 0x120);
		enumm.add("Blue", 0x230);

		category.addDataType(enumm, null);
		dataTypeManager.endTransaction(id, true);
		waitForTree();
	}

	private void checkStatusMessage(String expectedMessage) {

		waitForSwing();

		PluginTool pluginTool = plugin.getTool();
		DockingWindowManager windowManager = pluginTool.getWindowManager();
		Object rootNode = TestUtils.invokeInstanceMethod("getRootNode", windowManager);
		StatusBar statusBar = (StatusBar) TestUtils.getInstanceField("statusBar", rootNode);
		JLabel statusLabel = (JLabel) TestUtils.getInstanceField("statusLabel", statusBar);
		String statusMessage = statusLabel.getText();
		assertEquals(expectedMessage, statusMessage);
	}

	private void expandNode(GTreeNode node) {
		tree.expandPath(node);
		waitForTree();
	}

	private void selectNodes(String... names) {

		// make sure things have settled down
		program.flushEvents();
		waitForSwing();

		List<GTreeNode> nodes = new ArrayList<>();
		for (String name : names) {
			DataTypeNode node = (DataTypeNode) programNode.getChild(name);
			assertNotNull("Unable to find node: " + name, node);
			nodes.add(node);
		}

		expandNode(programNode);
		selectNodes(nodes);
		waitForTree();
	}

	private void selectNodes(List<GTreeNode> nodes) {
		List<TreePath> paths = new ArrayList<>(nodes.size());
		for (GTreeNode node : nodes) {
			paths.add(node.getTreePath());
		}
		tree.setSelectionPaths(paths);
		waitForTree();
	}

	private void clearSelection() {
		tree.setSelectionPaths(new ArrayList<TreePath>());
		waitForTree();
	}

	private void waitForTree() {
		waitForTree(tree);
	}

	private void checkLabelExists(boolean shouldExist, String labelString, String addressString) {
		SymbolTable symbolTable = program.getSymbolTable();
		Symbol symbol;
		if (addressString != null) {
			symbol = symbolTable.getGlobalSymbol(labelString, addr(addressString));
		}
		else {
			symbol = getUniqueSymbol(program, labelString);
		}
		assertEquals(shouldExist, (symbol != null));
	}

	private Address addr(String addressString) {
		return program.getAddressFactory().getAddress(addressString);
	}

	private void createLabels(final DockingActionIf action) {
		executeOnSwingWithoutBlocking(new Runnable() {
			@Override
			public void run() {
				DataTypeTestUtils.performAction(action, program, tree);
			}
		});

		waitForSwing();
		waitForTree();
	}

}
