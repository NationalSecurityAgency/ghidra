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
package ghidra.app.plugin.core.data;

import static org.hamcrest.core.StringContains.*;
import static org.junit.Assert.*;

import javax.swing.*;

import org.apache.commons.lang3.StringUtils;
import org.junit.*;

import docking.*;
import docking.action.DockingActionIf;
import generic.test.TestUtils;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.plugin.core.codebrowser.*;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.plugin.core.datamgr.DataTypesProvider;
import ghidra.app.plugin.core.datamgr.actions.ConflictHandlerModesAction;
import ghidra.app.plugin.core.datamgr.tree.*;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.ProgramDropProvider;
import ghidra.app.util.datatype.DataTypeSelectionDialog;
import ghidra.app.util.viewer.listingpanel.ListingPanel;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.data.ProgramDataTypeManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;
import ghidra.program.util.ProgramLocation;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;

public class ApplyDataTypeToBrowserTest extends AbstractGhidraHeadedIntegrationTest {
	private static final String PROGRAM_FILENAME = "WallaceSrc";
	private static final String CYCLE_BYTE_WORD_DWORD_QWORD = "Cycle: byte,word,dword,qword";

	private TestEnv env;
	private PluginTool tool;
	private ProgramDB program;
	private DataTypeManagerPlugin plugin;
	private DataPlugin dataPlugin;
	private DataTypesProvider provider;
	private ConflictHandlerModesAction conflictHandlerModesAction;
	private DataTypeArchiveGTree tree;
	private ArchiveRootNode archiveRootNode;
	private ArchiveNode programNode;
	private CodeViewerProvider codeViewerProvider;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.getTool();
		env.showTool();
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		tool.addPlugin(DataTypeManagerPlugin.class.getName());
		tool.addPlugin(DataPlugin.class.getName());

		program = buildWallaceSrcProgram();
		ProgramManager pm = tool.getService(ProgramManager.class);
		pm.openProgram(program.getDomainFile());

		env.showTool();

		plugin = env.getPlugin(DataTypeManagerPlugin.class);
		dataPlugin = env.getPlugin(DataPlugin.class);
		assertNotNull(dataPlugin);
		provider = plugin.getProvider();
		conflictHandlerModesAction =
			(ConflictHandlerModesAction) getInstanceField("conflictHandlerModesAction", provider);
		assertNotNull("Did not find DataTypesProvider.conflictHandlerModesAction field",
			conflictHandlerModesAction);
		tree = provider.getGTree();
		waitForTree();
		archiveRootNode = (ArchiveRootNode) tree.getViewRoot();
		programNode = (ArchiveNode) archiveRootNode.getChild(PROGRAM_FILENAME);
		assertNotNull("Did not successfully wait for the program node to load", programNode);

		tool.showComponentProvider(provider, true);

		CodeBrowserPlugin codeBrowserPlugin = env.getPlugin(CodeBrowserPlugin.class);
		codeViewerProvider = codeBrowserPlugin.getProvider();
	}

	private ProgramDB buildWallaceSrcProgram() throws Exception {

		ProgramBuilder builder = new ProgramBuilder("WallaceSrc", ProgramBuilder._X86, this);

		builder.createMemory(".text", "0x401000", 0xc00);
		builder.createMemory(".rdata", "0x402000", 0x800);
		builder.createMemory(".data", "0x403000", 0x200);
		builder.createMemory(".data", "0x403200", 0x190);

		program = builder.getProgram();
		StructureDataType dt = new StructureDataType("_person", 0);
		dt.add(new IntegerDataType(), "id", null);
		dt.add(new ArrayDataType(new CharDataType(), 32, 1), "name", null);
		dt.add(new BooleanDataType(), "likesCheese", null);
		dt.add(new PointerDataType(dt), "next", null);
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

		env.dispose();
	}

	@Test
	public void testChooseDataTypeOnDefaultDts() throws Exception {
		goTo("004027d0");

		showDataTypeChooser();

		chooseInDialog("_person");

		Data data = program.getListing().getDataAt(addr("004027d0"));
		ProgramDataTypeManager dataTypeManager = program.getDataTypeManager();
		DataType dataType = dataTypeManager.getDataType(new CategoryPath("/"), "_person");
		assertEquals(dataType, data.getDataType());
		assertEquals(addr("004027f8"), data.getMaxAddress());
	}

	@Test
	public void testChooseDataTypeOnUndefinedDts() throws Exception {
		createData("004027d2", new Undefined4DataType());
		goTo("004027d0");

		showDataTypeChooser();

		chooseInDialog("_person");

		Data data = program.getListing().getDataAt(addr("004027d0"));
		ProgramDataTypeManager dataTypeManager = program.getDataTypeManager();
		DataType dataType = dataTypeManager.getDataType(new CategoryPath("/"), "_person");
		assertEquals(dataType, data.getDataType());
		assertEquals(addr("004027f8"), data.getMaxAddress());
	}

	@Test
	public void testChooseDataTypeOnDefinedDts() throws Exception {

		//
		// Test that apply data on an existing type will offer to clear that type
		//

		createData("004027d1", new ByteDataType());
		goTo("004027d0");

		showDataTypeChooser();

		chooseInDialog("_person");

		pressConflictingDataDialog("Yes");

		Data data = program.getListing().getDataAt(addr("004027d0"));
		ProgramDataTypeManager dataTypeManager = program.getDataTypeManager();
		DataType dataType = dataTypeManager.getDataType(new CategoryPath("/"), "_person");
		assertEquals(dataType, data.getDataType());
		assertEquals(addr("004027f8"), data.getMaxAddress());
	}

	@Test
	public void testChooseDataTypeOnDefinedAndUndefinedDts() throws Exception {
		createData("004027d1", new ByteDataType());
		createData("004027d2", new Undefined4DataType());
		goTo("004027d0");

		showDataTypeChooser();
		chooseInDialog("_person");
		pressConflictingDataDialog("No");

		Data data = program.getListing().getDataAt(addr("004027d0"));
		assertEquals(DataType.DEFAULT, data.getDataType());
		assertEquals(addr("004027d0"), data.getMaxAddress());
	}

	@Test
	public void testChooseDataTypeWhereDoesNotFit() throws Exception {
		goTo("004027e0");

		showDataTypeChooser();
		chooseInDialog("_person");

		assertToolStatus("Not enough room in memory block containing address");
		Data data = program.getListing().getDataAt(addr("004027d0"));
		assertEquals(DataType.DEFAULT, data.getDataType());
		assertEquals(addr("004027d0"), data.getMaxAddress());
	}

	@Test
	public void testCreateArrayOnDefaultDts() throws Exception {
		goTo("004027d0");

		DockingActionIf chooseDataTypeAction = getAction(dataPlugin, "Define Array");
		performAction(chooseDataTypeAction, codeViewerProvider, false);

		waitForSwing();

		JDialog dialog = waitForJDialog("Create undefined[]");
		JTextField tf = findComponent(dialog, JTextField.class);
		triggerText(tf, "48");
		waitForSwing();

		pressButtonByText(dialog, "OK");
		waitForSwing();

		Data data = program.getListing().getDataAt(addr("004027d0"));
		ProgramDataTypeManager dataTypeManager = program.getDataTypeManager();
		DataType dataType = dataTypeManager.getDataType(new CategoryPath("/"), "undefined[48]");
		assertEquals(dataType, data.getDataType());
		assertEquals(addr("004027ff"), data.getMaxAddress());
	}

	@Test
	public void testCreateArrayOnUndefinedDts() throws Exception {
		createData("004027d2", new Undefined4DataType());
		goTo("004027d0");

		DockingActionIf chooseDataTypeAction = getAction(dataPlugin, "Define Array");
		assertNotNull(chooseDataTypeAction);
		performAction(chooseDataTypeAction, codeViewerProvider, false);

		waitForSwing();

		JDialog dialog = waitForJDialog("Create undefined[]");

		JTextField tf = findComponent(dialog, JTextField.class);
		triggerText(tf, "48");

		pressButtonByText(dialog, "OK");
		waitForSwing();

		Data data = program.getListing().getDataAt(addr("004027d0"));
		ProgramDataTypeManager dataTypeManager = program.getDataTypeManager();
		DataType dataType = dataTypeManager.getDataType(new CategoryPath("/"), "undefined[48]");
		assertEquals(dataType, data.getDataType());
		assertEquals(addr("004027ff"), data.getMaxAddress());
	}

	@Test
	public void testCreateArrayFailureOnDefinedDts() throws Exception {
		createData("004027d4", new ByteDataType());
		goTo("004027d0");

		DockingActionIf chooseDataTypeAction = getAction(dataPlugin, "Define Array");
		assertNotNull(chooseDataTypeAction);
		performAction(chooseDataTypeAction, codeViewerProvider, false);

		waitForSwing();

		JDialog dialog = waitForJDialog("Create undefined[]");

		checkStatus((DockingDialog) dialog, "Entering more than 4 will overwrite existing data");

		JTextField tf = findComponent(dialog, JTextField.class);
		triggerText(tf, "100");
		waitForSwing();

		checkStatus((DockingDialog) dialog, "Value must be between 1 and 48");

		JButton button = findButtonByText(dialog, "OK");
		assertFalse(button.isEnabled());
		waitForSwing();

		Data data = program.getListing().getDataAt(addr("004027d0"));
		assertEquals(DataType.DEFAULT, data.getDataType());
		assertEquals(addr("004027d0"), data.getMaxAddress());

		pressButtonByText(dialog, "Cancel");
		waitForSwing();

	}

	@Test
	public void testCreateArrayFailureOnInstr() throws Exception {

		createCode("004027d4", 1);

		goTo("004027d0");

		DockingActionIf chooseDataTypeAction = getAction(dataPlugin, "Define Array");
		assertNotNull(chooseDataTypeAction);
		performAction(chooseDataTypeAction, codeViewerProvider, false);

		waitForSwing();

		JDialog dialog = waitForJDialog("Create undefined[]");

		checkStatus((DockingDialog) dialog, " ");

		JTextField tf = findComponent(dialog, JTextField.class);
		triggerText(tf, "48");
		waitForSwing();

		checkStatus((DockingDialog) dialog, "Value must be between 1 and 4");

		JButton button = findButtonByText(dialog, "OK");
		assertFalse(button.isEnabled());
		waitForSwing();

		Data data = program.getListing().getDataAt(addr("004027d0"));
		assertEquals(DataType.DEFAULT, data.getDataType());
		assertEquals(addr("004027d0"), data.getMaxAddress());

		pressButtonByText(dialog, "Cancel");
		waitForSwing();

	}

	@Test
	public void testCreateArrayUptoInstr() throws Exception {

		createCode("004027d4", 1);

		goTo("004027d0");

		DockingActionIf chooseDataTypeAction = getAction(dataPlugin, "Define Array");
		assertNotNull(chooseDataTypeAction);
		performAction(chooseDataTypeAction, codeViewerProvider, false);

		waitForSwing();

		JDialog dialog = waitForJDialog("Create undefined[]");

		checkStatus((DockingDialog) dialog, " ");

		JTextField tf = findComponent(dialog, JTextField.class);
		triggerText(tf, "4");
		waitForSwing();

		checkStatus((DockingDialog) dialog, " ");

		pressButtonByName(dialog, "OK");
		waitForSwing();

		Data data = program.getListing().getDataAt(addr("004027d0"));
		assertTrue(new ArrayDataType(DataType.DEFAULT, 4, 1).isEquivalent(data.getDataType()));
		assertEquals(addr("004027d3"), data.getMaxAddress());

	}

	@Test
	public void testCreateArrayOverwriteOnDefinedDts() throws Exception {
		createData("004027d4", new ByteDataType());
		goTo("004027d0");

		DockingActionIf chooseDataTypeAction = getAction(dataPlugin, "Define Array");
		assertNotNull(chooseDataTypeAction);
		performAction(chooseDataTypeAction, codeViewerProvider, false);

		waitForSwing();

		JDialog dialog = waitForJDialog("Create undefined[]");

		JTextField tf = findComponent(dialog, JTextField.class);
		triggerText(tf, "48");
		waitForSwing();

		JButton button = findButtonByText(dialog, "OK");
		assertTrue(button.isEnabled());

		pressButtonByText(dialog, "OK");
		waitForSwing();

		dialog = waitForJDialog("Overwrite Existing Data?");

		pressButtonByText(dialog, "Yes");
		waitForSwing();

		Data data = program.getListing().getDataAt(addr("004027d0"));
		assertTrue(new ArrayDataType(DataType.DEFAULT, 48, 1).isEquivalent(data.getDataType()));
		assertEquals(addr("004027ff"), data.getMaxAddress());
	}

	@Test
	public void testLastUsedOnDefaultDts() throws Exception {
		ProgramDataTypeManager dataTypeManager = program.getDataTypeManager();
		DataType dataType = dataTypeManager.getDataType(new CategoryPath("/"), "_person");
		plugin.setRecentlyUsed(dataType);

		goTo("004027d0");

		DockingActionIf chooseDataTypeAction = getAction(dataPlugin, "Recently Used");
		assertNotNull(chooseDataTypeAction);
		performAction(chooseDataTypeAction, codeViewerProvider, false);

		waitForSwing();

		Data data = program.getListing().getDataAt(addr("004027d0"));
		assertEquals(dataType, data.getDataType());
		assertEquals(addr("004027f8"), data.getMaxAddress());
	}

	@Test
	public void testLastUsedOnUndefinedDts() throws Exception {
		ProgramDataTypeManager dataTypeManager = program.getDataTypeManager();
		DataType dataType = dataTypeManager.getDataType(new CategoryPath("/"), "_person");
		plugin.setRecentlyUsed(dataType);

		createData("004027d2", new Undefined4DataType());
		goTo("004027d0");

		DockingActionIf chooseDataTypeAction = getAction(dataPlugin, "Recently Used");
		assertNotNull(chooseDataTypeAction);
		performAction(chooseDataTypeAction, codeViewerProvider, false);

		waitForSwing();

		Data data = program.getListing().getDataAt(addr("004027d0"));
		assertEquals(dataType, data.getDataType());
		assertEquals(addr("004027f8"), data.getMaxAddress());
	}

	@Test
	public void testLastUsedOnDefinedDtsAnswerYes() throws Exception {
		ProgramDataTypeManager dataTypeManager = program.getDataTypeManager();
		DataType dataType = dataTypeManager.getDataType(new CategoryPath("/"), "_person");
		plugin.setRecentlyUsed(dataType);

		createData("004027d1", new ByteDataType());
		goTo("004027d0");

		DockingActionIf chooseDataTypeAction = getAction(dataPlugin, "Recently Used");
		performAction(chooseDataTypeAction, codeViewerProvider, false);

		pressConflictingDataDialog("Yes");

		Data data = program.getListing().getDataAt(addr("004027d0"));
		assertEquals(dataType, data.getDataType());
		assertEquals(addr("004027f8"), data.getMaxAddress());
	}

	@Test
	public void testLastUsedOnDefinedDtsAnswerNo() throws Exception {
		ProgramDataTypeManager dataTypeManager = program.getDataTypeManager();
		DataType dataType = dataTypeManager.getDataType(new CategoryPath("/"), "_person");
		plugin.setRecentlyUsed(dataType);

		createData("004027d1", new ByteDataType());
		goTo("004027d0");

		DockingActionIf chooseDataTypeAction = getAction(dataPlugin, "Recently Used");
		assertNotNull(chooseDataTypeAction);
		performAction(chooseDataTypeAction, codeViewerProvider, false);

		pressConflictingDataDialog("No");

		Data data = program.getListing().getDataAt(addr("004027d0"));
		assertEquals(DataType.DEFAULT, data.getDataType());
		assertEquals(addr("004027d0"), data.getMaxAddress());
	}

	@Test
	public void testFavoriteOnDefaultDts() throws Exception {
		goTo("004027d0");

		ProgramDataTypeManager dataTypeManager = program.getDataTypeManager();
		DataType dataType = dataTypeManager.getDataType(new CategoryPath("/"), "_person");

		// Set _person as a favorite
		runSwing(() -> dataTypeManager.setFavorite(dataType, true), false);
		waitForSwing();

		// Choose favorite
		DockingActionIf favoriteAction = getAction(dataPlugin, "Define _person");
		performAction(favoriteAction, codeViewerProvider, true);
		waitForSwing();

		Data data = program.getListing().getDataAt(addr("004027d0"));
		assertEquals(dataType, data.getDataType());
		assertEquals(addr("004027f8"), data.getMaxAddress());
	}

	@Test
	public void testFavoriteOnUndefinedDts() throws Exception {
		createData("004027d2", new Undefined4DataType());
		goTo("004027d0");

		ProgramDataTypeManager dataTypeManager = program.getDataTypeManager();
		DataType dataType = dataTypeManager.getDataType(new CategoryPath("/"), "_person");

		// Set _person as a favorite
		runSwing(() -> dataTypeManager.setFavorite(dataType, true), false);
		waitForSwing();

		// Choose favorite.
		DockingActionIf favoriteAction = getAction(dataPlugin, "Define _person");
		performAction(favoriteAction, codeViewerProvider, true);
		waitForSwing();

		Data data = program.getListing().getDataAt(addr("004027d0"));
		assertEquals(dataType, data.getDataType());
		assertEquals(addr("004027f8"), data.getMaxAddress());
	}

	@Test
	public void testFavoriteOnDefinedDtsAnswerYes() throws Exception {
		createData("004027d1", new ByteDataType());
		goTo("004027d0");

		ProgramDataTypeManager dataTypeManager = program.getDataTypeManager();
		DataType dataType = dataTypeManager.getDataType(new CategoryPath("/"), "_person");

		// Set _person as a favorite
		runSwing(() -> dataTypeManager.setFavorite(dataType, true), false);
		waitForSwing();

		// Choose favorite
		DockingActionIf favoriteAction = getAction(dataPlugin, "Define _person");
		performAction(favoriteAction, codeViewerProvider, false);

		pressConflictingDataDialog("Yes");

		Data data = program.getListing().getDataAt(addr("004027d0"));
		assertEquals(dataType, data.getDataType());
		assertEquals(addr("004027f8"), data.getMaxAddress());
	}

	@Test
	public void testFavoriteOnDefinedDtsAnswerNo() throws Exception {
		createData("004027d1", new ByteDataType());
		goTo("004027d0");

		ProgramDataTypeManager dataTypeManager = program.getDataTypeManager();
		DataType dataType = dataTypeManager.getDataType(new CategoryPath("/"), "_person");

		// Set _person as a favorite
		runSwing(() -> dataTypeManager.setFavorite(dataType, true), false);
		waitForSwing();

		// Choose favorite.
		DockingActionIf favoriteAction = getAction(dataPlugin, "Define _person");
		performAction(favoriteAction, codeViewerProvider, false);

		pressConflictingDataDialog("No");

		Data data = program.getListing().getDataAt(addr("004027d0"));
		assertEquals(DataType.DEFAULT, data.getDataType());
		assertEquals(addr("004027d0"), data.getMaxAddress());
	}

	@Test
	public void testCycleOnDefaultDts() throws Exception {
		goTo("004027d0");

		showDataTypeChooser();

		chooseInDialog("_person");

		Data data = program.getListing().getDataAt(addr("004027d0"));
		ProgramDataTypeManager dataTypeManager = program.getDataTypeManager();
		DataType dataType = dataTypeManager.getDataType(new CategoryPath("/"), "_person");
		assertEquals(dataType, data.getDataType());
		assertEquals(addr("004027f8"), data.getMaxAddress());
	}

	@Test
	public void testCycleOnUndefinedDts() throws Exception {
		createData("004027d2", new Undefined4DataType());
		goTo("004027d0");

		Data data = program.getListing().getDataAt(addr("004027d0"));
		ProgramDataTypeManager dataTypeManager = program.getDataTypeManager();
		DataType dataType = dataTypeManager.getDataType(new CategoryPath("/"), "undefined");
		assertEquals(dataType, data.getDataType());
		assertEquals(addr("004027d0"), data.getMaxAddress());

		doAction(dataPlugin, CYCLE_BYTE_WORD_DWORD_QWORD, true);

		data = program.getListing().getDataAt(addr("004027d0"));
		dataType = dataTypeManager.getDataType(new CategoryPath("/"), "byte");
		assertEquals(dataType, data.getDataType());
		assertEquals(addr("004027d0"), data.getMaxAddress());

		doAction(dataPlugin, CYCLE_BYTE_WORD_DWORD_QWORD, true);

		data = program.getListing().getDataAt(addr("004027d0"));
		dataType = dataTypeManager.getDataType(new CategoryPath("/"), "word");
		assertEquals(dataType, data.getDataType());
		assertEquals(addr("004027d1"), data.getMaxAddress());

		doAction(dataPlugin, CYCLE_BYTE_WORD_DWORD_QWORD, true);

		data = program.getListing().getDataAt(addr("004027d0"));
		dataType = dataTypeManager.getDataType(new CategoryPath("/"), "undefined");
		assertEquals(dataType, data.getDataType());
		assertEquals(addr("004027d0"), data.getMaxAddress());
	}

	@Test
	public void testCycleOnDefinedDts() throws Exception {
		createData("004027d3", new ByteDataType());
		goTo("004027d0");

		Data data = program.getListing().getDataAt(addr("004027d0"));
		ProgramDataTypeManager dataTypeManager = program.getDataTypeManager();
		DataType dataType = dataTypeManager.getDataType(new CategoryPath("/"), "undefined");
		assertEquals(dataType, data.getDataType());
		assertEquals(addr("004027d0"), data.getMaxAddress());

		doAction(dataPlugin, CYCLE_BYTE_WORD_DWORD_QWORD, true);

		data = program.getListing().getDataAt(addr("004027d0"));
		dataType = dataTypeManager.getDataType(new CategoryPath("/"), "byte");
		assertEquals(dataType, data.getDataType());
		assertEquals(addr("004027d0"), data.getMaxAddress());

		doAction(dataPlugin, CYCLE_BYTE_WORD_DWORD_QWORD, true);

		data = program.getListing().getDataAt(addr("004027d0"));
		dataType = dataTypeManager.getDataType(new CategoryPath("/"), "word");
		assertEquals(dataType, data.getDataType());
		assertEquals(addr("004027d1"), data.getMaxAddress());

		doAction(dataPlugin, CYCLE_BYTE_WORD_DWORD_QWORD, true);

		data = program.getListing().getDataAt(addr("004027d0"));
		dataType = dataTypeManager.getDataType(new CategoryPath("/"), "undefined");
		assertEquals(dataType, data.getDataType());
		assertEquals(addr("004027d0"), data.getMaxAddress());
	}

	@Test
	public void testDragNDropOnDefaultDts() throws Exception {
		goTo("004027d0");

		ProgramDataTypeManager dataTypeManager = program.getDataTypeManager();
		DataType dataType = dataTypeManager.getDataType(new CategoryPath("/"), "_person");

		dragNDropDataTypeToCurrentBrowserLocation(dataType);

		Data data = program.getListing().getDataAt(addr("004027d0"));
		assertEquals(dataType, data.getDataType());
		assertEquals(addr("004027f8"), data.getMaxAddress());
	}

	@Test
	public void testDragNDropOnUndefinedDts() throws Exception {
		createData("004027d2", new Undefined4DataType());
		goTo("004027d0");

		ProgramDataTypeManager dataTypeManager = program.getDataTypeManager();
		DataType dataType = dataTypeManager.getDataType(new CategoryPath("/"), "_person");

		dragNDropDataTypeToCurrentBrowserLocation(dataType);

		Data data = program.getListing().getDataAt(addr("004027d0"));
		assertEquals(dataType, data.getDataType());
		assertEquals(addr("004027f8"), data.getMaxAddress());
	}

	@Test
	public void testDragNDropYesOnDefinedDts() throws Exception {
		createData("004027d3", new ByteDataType());
		goTo("004027d0");

		ProgramDataTypeManager dataTypeManager = program.getDataTypeManager();
		DataType dataType = dataTypeManager.getDataType(new CategoryPath("/"), "_person");

		dragNDropDataTypeToCurrentBrowserLocation(dataType);

		pressConflictingDataDialog("Yes");

		Data data = program.getListing().getDataAt(addr("004027d0"));
		assertEquals(dataType, data.getDataType());
		assertEquals(addr("004027f8"), data.getMaxAddress());
	}

	@Test
	public void testDragNDropNoOnDefinedDts() throws Exception {
		createData("004027d3", new ByteDataType());
		goTo("004027d0");

		ProgramDataTypeManager dataTypeManager = program.getDataTypeManager();
		DataType dataType = dataTypeManager.getDataType(new CategoryPath("/"), "_person");

		dragNDropDataTypeToCurrentBrowserLocation(dataType);

		pressConflictingDataDialog("No");

		Data data = program.getListing().getDataAt(addr("004027d0"));
		assertEquals(DataType.DEFAULT, data.getDataType());
		assertEquals(addr("004027d0"), data.getMaxAddress());
	}

	@Test
	public void testDragNDropWhereDoesNotFit() throws Exception {
		goTo("004027e0");

		ProgramDataTypeManager dataTypeManager = program.getDataTypeManager();
		DataType dataType = dataTypeManager.getDataType(new CategoryPath("/"), "_person");

		dragNDropDataTypeToCurrentBrowserLocation(dataType);

		Data data = program.getListing().getDataAt(addr("004027e0"));
		assertEquals(DataType.DEFAULT, data.getDataType());
		assertEquals(addr("004027e0"), data.getMaxAddress());
	}

//==================================================================================================
// Private Helper Methods
//==================================================================================================

	private void assertToolStatus(String expectedMessage) {

		waitForSwing();
		PluginTool pluginTool = plugin.getTool();
		DockingWindowManager windowManager = pluginTool.getWindowManager();
		Object rootNode = TestUtils.invokeInstanceMethod("getRootNode", windowManager);
		StatusBar statusBar = (StatusBar) TestUtils.getInstanceField("statusBar", rootNode);
		String actualMessage = runSwing(() -> statusBar.getStatusText());
		assertThat("The tool's status text was not set", actualMessage,
			containsString(expectedMessage));
	}

	private void showDataTypeChooser() {
		DockingActionIf chooseDataTypeAction = getAction(dataPlugin, "Choose Data Type");
		performAction(chooseDataTypeAction, codeViewerProvider, false);
	}

	private void pressConflictingDataDialog(String button) {
		DialogComponentProvider dialog = waitForDialogComponent("Data Conflict");
		pressButtonByText(dialog, button);
		waitForTasks();
	}

	private DialogComponentProvider chooseInDialog(String typeName) {
		return chooseInDialog(typeName, null);
	}

	private DialogComponentProvider chooseInDialog(String typeName, String errorStatus) {

		DataTypeSelectionDialog dialog = waitForDialogComponent(DataTypeSelectionDialog.class);
		JTextField tf = findComponent(dialog, JTextField.class);
		triggerText(tf, "_person");
		waitForSwing();

		pressButtonByText(dialog, "OK");
		waitForSwing();

		if (errorStatus != null) {
			checkStatus(dialog, errorStatus);
		}

		return dialog;
	}

	private void checkStatus(DockingDialog dialog, String expectedText) {

		checkStatus(dialog.getDialogComponent(), expectedText);
	}

	private void checkStatus(DialogComponentProvider dialog, String expectedText) {

		String statusText = dialog.getStatusText();
		if (StringUtils.isBlank(expectedText) && StringUtils.isBlank(statusText)) {
			return;
		}

		assertEquals(expectedText, statusText);
	}

	private void dragNDropDataTypeToCurrentBrowserLocation(final DataType dataType) {
		executeOnSwingWithoutBlocking(() -> {
			// Simulate the drag-n-drop of the data type onto the location.
			ProgramLocation programLocation = codeViewerProvider.getLocation();
			ProgramDropProvider[] dropProviders =
				(ProgramDropProvider[]) getInstanceField("dropProviders", codeViewerProvider);
			setInstanceField("curDropProvider", codeViewerProvider, dropProviders[0]);
			CodeViewerActionContext context =
				new CodeViewerActionContext(codeViewerProvider, programLocation);
			ProgramDropProvider curDropProvider =
				(ProgramDropProvider) getInstanceField("curDropProvider", codeViewerProvider);
			setInstanceField("curService", curDropProvider, dataPlugin);
			curDropProvider.add(context, dataType, DataTypeTransferable.localDataTypeFlavor);
		});
		waitForSwing();
	}

	private void doAction(Plugin pluginForAction, String name, boolean waitForCompletion) {
		CodeViewerActionContext codeViewerContext = new CodeViewerActionContext(codeViewerProvider);

		DockingActionIf action = getAction(pluginForAction, name);
		assertNotNull("Action was not found: " + name, action);
		if (!action.isEnabledForContext(codeViewerContext)) {
			Assert.fail("Action is not valid: " + name);
		}

		try {
			performAction(action, codeViewerProvider, waitForCompletion);
		}
		catch (Throwable t) {
			failWithException("Action '" + name + "' failed: ", t);
		}

	}

	private void goTo(String addressString) {
		CodeBrowserPlugin codeBrowser = env.getPlugin(CodeBrowserPlugin.class);
		Address address = program.getAddressFactory().getAddress(addressString);
		codeBrowser.goToField(address, "Address", 0, 0);
		assertEquals(addressString, codeBrowser.getCurrentAddress().toString());
		CodeViewerProvider connectedProvider =
			(CodeViewerProvider) getInstanceField("connectedProvider", codeBrowser);
		assertNotNull(connectedProvider);
		ListingPanel listingPanel =
			(ListingPanel) getInstanceField("listingPanel", connectedProvider);
		assertNotNull(listingPanel);
		waitForSwing();
	}

	private void createData(String addressString, DataType dataType) throws Exception {
		boolean success = false;
		int transactionID = program.startTransaction("test");
		try {
			program.getListing().createData(addr(addressString), dataType);
			success = true;
		}
		finally {
			program.endTransaction(transactionID, success);
		}
		waitForProgram(program);
	}

	private void createCode(String addressString, int len) throws Exception {
		boolean success = false;
		int transactionID = program.startTransaction("test");
		try {
			Address min = addr(addressString);
			Address max = min.add(len - 1);
			AddressSet set = new AddressSet(min, max);
			DisassembleCommand cmd = new DisassembleCommand(set, set, false);
			cmd.applyTo(program);
			success = true;
		}
		finally {
			program.endTransaction(transactionID, success);
		}
		waitForProgram(program);
	}

	private Address addr(String addressString) {
		return program.getAddressFactory().getAddress(addressString);
	}

	private void waitForTree() {
		waitForTree(tree);
	}
}
