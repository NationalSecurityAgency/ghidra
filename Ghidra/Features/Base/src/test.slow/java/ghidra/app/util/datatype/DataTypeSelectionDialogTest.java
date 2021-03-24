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
package ghidra.app.util.datatype;

import static org.junit.Assert.*;

import java.awt.*;
import java.awt.event.*;
import java.awt.image.BufferedImage;
import java.awt.image.RenderedImage;
import java.io.File;
import java.io.IOException;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.*;
import javax.swing.text.DefaultHighlighter;
import javax.swing.text.Highlighter;

import org.junit.*;

import docking.DialogComponentProvider;
import docking.DockingDialog;
import docking.options.editor.ButtonPanelFactory;
import docking.widgets.DropDownSelectionTextField;
import docking.widgets.DropDownTextField;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import generic.test.AbstractGTest;
import generic.util.WindowUtilities;
import generic.util.image.ImageUtils;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.plugin.core.datamgr.archive.Archive;
import ghidra.app.plugin.core.datamgr.archive.DataTypeManagerHandler;
import ghidra.app.plugin.core.datamgr.tree.DataTypeArchiveGTree;
import ghidra.app.plugin.core.datamgr.tree.DataTypeNode;
import ghidra.app.plugin.core.datamgr.util.DataTypeChooserDialog;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.data.ProgramDataTypeManager;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.Msg;
import ghidra.util.data.DataTypeParser.AllowedDataTypes;
import ghidra.util.task.TaskMonitorAdapter;
import mockit.Mock;
import mockit.MockUp;

public class DataTypeSelectionDialogTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private Program program;
	private PluginTool tool;

	private DataTypeSelectionDialog dialog;

	private ReportingDataListener reportingListener = new ReportingDataListener();

	private Set<Archive> archivesToClose = new HashSet<>();

	private SpyDropDownSelectionTextField<?> spyTextField;

	@Before
	public void setUp() throws Exception {
		System.err.println("\n\nsetUp() - " + testName.getMethodName());

		setErrorGUIEnabled(false);

		UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());

		// trigger the mock to load
		spyTextField = new SpyDropDownSelectionTextField<>();

		env = new TestEnv();

		tool = env.getTool();
		tool.addPlugin(DataTypeManagerPlugin.class.getName());

		ProgramBuilder builder = new ProgramBuilder(testName.getMethodName(), ProgramBuilder._TOY);
		program = builder.getProgram();

		ProgramManager pm = tool.getService(ProgramManager.class);
		pm.openProgram(program.getDomainFile());

		DataTypeManagerService service = tool.getService(DataTypeManagerService.class);
		service.addDataTypeManagerChangeListener(reportingListener);

		waitForSwing();
		waitForBusyTool(tool);

		closeUndesiredArchives();

		runSwing(() -> {
			dialog = new DataTypeSelectionDialog(tool, program.getDataTypeManager(), -1,
				AllowedDataTypes.ALL);
			DropDownSelectionTextField<?> field = getEditorTextField(dialog);
			removeFocusIssues(field);
		});

		assertNotNull(dialog);

		System.err.println("\tend setUp()");
	}

	private void removeFocusIssues(DropDownSelectionTextField<?> field) {
		FocusListener[] focusListeners = field.getFocusListeners();
		for (FocusListener listener : focusListeners) {
			field.removeFocusListener(listener);
		}
	}

	// close all archives but the builtin and the program archive
	private void closeUndesiredArchives() {
		DataTypeManagerPlugin plugin = env.getPlugin(DataTypeManagerPlugin.class);
		DataTypeManagerHandler dataTypeManagerHandler = plugin.getDataTypeManagerHandler();
		List<Archive> archives = dataTypeManagerHandler.getAllFileOrProjectArchives();
		for (Archive archive : archives) {
			dataTypeManagerHandler.closeArchive(archive);
		}
	}

	@After
	public void tearDown() throws Exception {
		System.err.println("tearDown() - " + testName.getMethodName() + "\n");

		for (Archive archive : archivesToClose) {
			closeArchive(archive);
		}

		tool.setConfigChanged(false);// we don't want a save dialog to show

		DataTypeManagerService service = tool.getService(DataTypeManagerService.class);
		service.removeDataTypeManagerChangeListener(reportingListener);

		// close any windows that may have been left open in error, like a data type chooser
		closeAllWindows();

		env.dispose();
	}

	@Test
	public void testShowHideDialog() {
		runShowHideDialog("double", true);
		runShowHideDialog("byte", true);
		runShowHideDialog("kitty", false);
		runShowHideDialog("dword", true);
		runShowHideDialog("goodtimes", false);
	}

	@Test
	public void testDataTypeSelectionTree() {
		showDialogWithoutBlocking(tool, dialog);

		assertTrue("The dialog was not made visible when tool.showDialog() was called.",
			dialog.isVisible());

		final JButton browseButton = findButtonByIcon(dialog, ButtonPanelFactory.BROWSE_ICON);
		pressButton(browseButton);

		Window window = waitForWindow("Data Type Chooser");

		assertTrue("The data type selection tree was not shown after pressing the browse button",
			(window instanceof DockingDialog));

		DockingDialog dockingDialog = (DockingDialog) window;
		DialogComponentProvider provider =
			(DialogComponentProvider) getInstanceField("component", dockingDialog);

		assertTrue("Did not find the data type chooser tree",
			(provider instanceof DataTypeChooserDialog));
		GTree gTree = (GTree) getInstanceField("tree", provider);
		GTreeNode rootNode = gTree.getModelRoot();
		waitForTree(gTree);
		final GTreeNode builtInNode = rootNode.getChild("BuiltInTypes");
		final DataTypeNode doubleNode = (DataTypeNode) builtInNode.getChild("double");

		assertNotNull("Unable to find a default data type.", doubleNode);

		final JTree tree = (JTree) getInstanceField("tree", gTree);

		// select the node
		runSwing(() -> {
			tree.expandPath(builtInNode.getTreePath());
			tree.setSelectionPath(doubleNode.getTreePath());
		});

		// close the dialog
		JButton okButton = (JButton) getInstanceField("okButton", provider);
		pressButton(okButton);

		waitForDialogToClose(dockingDialog);

		assertTrue("The data type selection tree dialog was not closed after pressing OK.",
			!dockingDialog.isValid());

		// make sure that the selected node can be retrieved
		DataType dataType = (DataType) getInstanceField("selectedDataType", provider);
		assertNotNull("Expected a datatype after pressing OK on the chooser tree", dataType);
		assertEquals(
			"The selected data type was not returned from data type selection " + "dialog.",
			doubleNode.getDataType().getName(), dataType.getName());

		// show the dialog again and cancel and make sure that the user selection is null
		pressButton(browseButton);
		window = waitForWindow("Data Type Chooser");
		assertTrue("The data type selection tree was not shown after pressing the browse button",
			(window instanceof DockingDialog));
		dockingDialog = (DockingDialog) window;
		provider = (DialogComponentProvider) getInstanceField("component", dockingDialog);
		JButton cancelButton = (JButton) getInstanceField("cancelButton", provider);

		pressButton(cancelButton);
		waitForDialogToClose(dockingDialog);

		assertTrue("The data type selection tree dialog was not closed after pressing cancel.",
			!dockingDialog.isValid());

		assertTrue("Did not find the data type chooser tree",
			(provider instanceof DataTypeChooserDialog));
		dataType = (DataType) getInstanceField("selectedDataType", provider);
		assertNull("There is a selection value in the data type selection tree dialog even " +
			"though cancel was pressed.", dataType);
	}

	private void waitForDialogToClose(DockingDialog dockingDialog) {
		int count = 0;
		while (dockingDialog.isShowing() && count < 500) {
			sleep(50);
		}
		assertTrue("Dialog did not close!", !dockingDialog.isShowing());
		waitForSwing();
	}

	@Test
	public void testMultipleShowWindowWithCompletion() {
		showDialogWithoutBlocking(tool, dialog);
		assertTrue("The dialog was not made visible when tool.showDialog() was called.",
			dialog.isVisible());

		JButton cancelButton = (JButton) getInstanceField("cancelButton", dialog);
		pressButton(cancelButton);

		assertTrue("The dialog did not close when the cancel button was pressed.",
			!dialog.isVisible());

		showDialogWithoutBlocking(tool, dialog);
		assertTrue("The dialog was not made visible when tool.showDialog() was called.",
			dialog.isVisible());

		JButton okButton = (JButton) getInstanceField("okButton", dialog);
		pressButton(okButton);

		assertTrue(
			"The dialog was closed without having a valid datatype entered in the text field.",
			dialog.isVisible());

		// force the completion window to be opened and closed a couple times
		runEnterCompletionText("d");
		runEnterCompletionText("b");

		// now submit the selection
		typeCompletionText("double");

		pressOKButtonToSelectChoice(okButton);

		assertTrue(
			"The dialog was not closed after pressing the 'OK' button with a valid " +
				"data type in the selection field.  Status text: " + dialog.getStatusText(),
			!dialog.isVisible());
	}

	// the completion field within the dialog also uses the ESCAPE key, so we must make sure
	// the we still work with the key when that field does not use it
	@Test
	public void testEscapeKey() {
		showDialogWithoutBlocking(tool, dialog);

		assertTrue("The dialog was not made visible when tool.showDialog() was called.",
			dialog.isVisible());

		typeCompletionText("double");

		Window completionWindow = getCompletionWindow(dialog);
		assertTrue("The completion dialog was not shown after entering valid matching text.",
			completionWindow.isVisible());

		int hideId = spyTextField.getHideId();

		// fire the first escape key and make sure the completion window closes
		typeEscape();

		// Ugh: due to focus issues, we can't rely on the window being visible and hidden, so
		//      we prevent it from being hidden and rely on the callback upon which we are spying
		//      to know if the correct behavior happened.
		int newHideId = spyTextField.getHideId();
		assertTrue("The completion window is visible after pressing the escape key.",
			hideId < newHideId);
		assertTrue("The data type selection dialog was closed when only the completion window " +
			"should have been closed.", dialog.isVisible());

		// fire the second escape key and make sure the dialog closes
		manuallyCloseCompletionWindow();
		typeEscape();
		assertFalse("The data type selection dialog was not closed after pressing escape " +
			"with no completion window open.", dialog.isVisible());
	}

	private void manuallyCloseCompletionWindow() {
		Window completionWindow = getCompletionWindow(dialog);
		runSwing(() -> completionWindow.setVisible(false));
	}

	// the completion field within the dialog also uses the Enter key, so we must make sure
	// the we still work with the key when that field does not use it
	@Test
	public void testEnterKey() {
		showDialogWithoutBlocking(tool, dialog);

		assertTrue("The dialog was not made visible when tool.showDialog() was called.",
			dialog.isVisible());

		typeCompletionText("double");

		Window completionWindow = getCompletionWindow(dialog);
		assertTrue("The completion dialog was not shown after entering valid matching text.",
			completionWindow.isVisible());

		// fire the first enter key and make sure the completion window closes
		triggerActionKey(getEditorTextField(dialog), 0, KeyEvent.VK_ENTER);

// UPDATE - SCR 7176 - Enter key now closes the dialog, even if the selection window was open       
//        assertTrue( "The completion window is visible after pressing the enter key.",
//            !completionWindow.isVisible() );
//        assertTrue( "The data type selection dialog was closed when only the completion window " +
//            "should have been closed.", dialog.isVisible() );
//
//        // fire the second enter key and make sure the dialog closes
//        typeActionKey( 0, KeyEvent.VK_ENTER );

		assertTrue("The data type selection dialog was not closed after pressing enter " +
			"with no completion window open.", !dialog.isVisible());
	}

	@Test
	public void testMultipleSelectionDialog() throws Exception {
		// this test creates Categories and adds new DataTypes
		int id = program.startTransaction("TEST");

		showDialogWithoutBlocking(tool, dialog);

		assertTrue("The dialog was not made visible when tool.showDialog() was called.",
			isVisible(dialog));

		DataTypeManagerService dataTypeService = tool.getService(DataTypeManagerService.class);

		// not shown when no matches
		String crazyName = "crazyName";
		typeCompletionText(crazyName);

		JButton okButton = (JButton) getInstanceField("okButton", dialog);
		pressButton(okButton);

		assertTrue("The dialog is not visible after entering an invalid data type name.",
			isVisible(dialog));

		assertDataTypeChooserNotShown();

		DataTypeManager[] dataTypeManagers = dataTypeService.getDataTypeManagers();
		Category rootCategory = getProgramDataTypeManagerRootCategory(dataTypeManagers);
		Category category = rootCategory.createCategory("testCategory");

		// not shown when single match
		DataType dataType = new CustomDataType(category.getCategoryPath(), crazyName, 1);
		addDataType(category, dataType);
		pressButton(okButton);

		assertDialogNotVisible("The dialog is visible after entering an valid data type name.");

		assertDataTypeChooserNotShown();

		// shown when multiple non-equivalent matches
		dataType = new CustomDataType(rootCategory.getCategoryPath(), crazyName, 100);
		addDataType(rootCategory, dataType);

		showDialogWithoutBlocking(tool, dialog);

		assertTrue("The dialog was not made visible when tool.showDialog() was called.",
			isVisible(dialog));

		//
		// This name will match the 2 data types created above, triggering a new window that
		// contains a data type tree for choosing from the best result.
		//
		typeCompletionText(crazyName);
		pressButton(okButton);

		assertTrue("The dialog should still be visible after entering data type name " +
			"with multiple matches.", isVisible(dialog));

		DataTypeChooserDialog dataTypeChooserDialog = getDataTypeChooserDialog();
		assertNotNull("The data type chooser dialog was not shown when there are multiple " +
			"matching data types.", dataTypeChooserDialog);

		closeDataTypeChooserTreeDialog(dataTypeChooserDialog);
		clearText(getEditorTextField(dialog));

		//
		// Check that the tree chooser dialog is not shown when there are multiple matches, but 
		// each data type is equivalent.  In this case we just pick the program's DT.
		//
		dataType = new CustomDataType(category.getCategoryPath(), crazyName, 100);
		addDataType(category, dataType);

		typeCompletionText(crazyName);
		pressButton(okButton);

		assertDialogNotVisible(
			"The dialog is visible when it should have been closed after making a choice " +
				"from multiple equivalent data types.");

		//
		// Check that more than 2 non-equivalent data types trigger the dialog to appear. 
		//
		Category secondCategory = rootCategory.createCategory("testCategory2");
		dataType = new CustomDataType(secondCategory.getCategoryPath(), crazyName, 2,
			getProgramDataTypeManager(dataTypeManagers));
		addDataType(secondCategory, dataType);

		showDialogWithoutBlocking(tool, dialog);

		assertTrue("The dialog was not made visible when tool.showDialog() was called.",
			isVisible(dialog));

		typeCompletionText(crazyName);
		pressButton(okButton);

		assertTrue("The dialog is not visible after entering an invalid data type name.",
			isVisible(dialog));

		dataTypeChooserDialog = getDataTypeChooserDialog();
		assertNotNull(
			"The data type chooser dialog was shown when there are no matching data " + "types.",
			dataTypeChooserDialog);

		closeDataTypeChooserTreeDialog(dataTypeChooserDialog);

		clearText(getEditorTextField(dialog));
		secondCategory.remove(dataType, new TaskMonitorAdapter());

		// 
		// After deleting the previous type, we have more than 2 multiple matches, all equivalent.
		// (We tested this case above already)
		//
		dataType = new CustomDataType(secondCategory.getCategoryPath(), crazyName, 100);
		addDataType(secondCategory, dataType);

		typeCompletionText(crazyName);
		pressButton(okButton);

		assertDialogNotVisible(
			"The dialog is visible when it should have been closed after making a choice " +
				"from multiple equivalent data types.");

		program.endTransaction(id, false);
		program.flushEvents();
		waitForSwing();
	}

	private void assertDataTypeChooserNotShown() {

		waitForSwing();
		DataTypeChooserDialog dtcd = getDialogComponent(DataTypeChooserDialog.class);
		assertNull(
			"The data type chooser dialog was shown when there are no matching data " + "types.",
			dtcd);
	}

	private void assertDialogNotVisible(String message) {
		if (isVisible(dialog)) {

			String statusText = dialog.getStatusText();
			captureScreen();
			fail(message + " (dialog status was '" + statusText + "')");
		}
	}

	private void captureScreen() {
		try {
			Robot robot = new Robot();
			Rectangle bounds = WindowUtilities.getVirtualScreenBounds();
			BufferedImage image = robot.createScreenCapture(bounds);
			writeToFile(image);
		}
		catch (AWTException e) {
			Msg.error(this, "Unable to create Robot to capture the screen");
		}
	}

	protected void writeToFile(Image image) {

		String temp = AbstractGTest.getTestDirectoryPath();
		String name = testName.getMethodName();
		File imageFile = new File(temp, name + ".img.png");
		try {
			ImageUtils.writeFile((RenderedImage) image, imageFile);
			Msg.info(this, "Captured screenshot to " + imageFile.getCanonicalPath());
		}
		catch (Exception e) {
			Msg.error(this, "Unable to write debug image");
		}
	}

	private boolean isVisible(final DataTypeSelectionDialog theDialog) {
		AtomicBoolean bool = new AtomicBoolean();
		runSwing(() -> bool.set(theDialog.isVisible()));
		waitForSwing();
		return bool.get();
	}

	@Test
	public void testPickFromListThenAddPointerChar() {
		Archive archive = createTestFileArchive();

		String structureName = "foo";
		Structure structure = createStructure(archive, structureName);
		addType(archive, structure);

		showSelectionDialog(null);

		typeCompletionText(structureName);

		Window completionWindow = getCompletionWindow(dialog);
		assertTrue("The completion dialog was not shown after entering valid matching text.",
			completionWindow.isVisible());

		//
		// Hacky Smacky: it seems like too much work to double-click the list entry we want, so
		//               we will call the same method that a double-click triggers under the hood.
		//
		chooseSelectedItemInList();

		typeCompletionText(" *");

		pressOK();

		assertFalse("The dialog is visible when it should have been closed after making a choice " +
			"from the list and then adding a pointer character", dialog.isVisible());

		DataType dt = dialog.getUserChosenDataType();
		assertEquals(structureName + " *", dt.getName());
	}

	// SCR 9511
	@Test
	public void testHandDeleteExistingEntryLeavingPointerCharOn_DataTypeInOtherArchive_Single() {
		//
		// We are trying to test that the user can type the name of a type (not pick it from the
		// list) that exists in an open archive *that is not set on the dialog*.  The intent is
		// that if we have to parse the text provided by the user, that we don't automatically
		// pick one when it is an an archive that we didn't specify (like the program archive).
		//
		// To test this, start with 3 types in a file archive: foo and a typedef to foo
		// (foo_typedef) and a pointer to the typedef.
		// Then, pick the typedef * as the initial type of the dialog.  After that, delete the
		// ending text to turn the typedef in to the foo type, leaving the pointer char in the 
		// text field.  Pressing OK should show you a chooser to pick the type found.
		//
		//
		//

		Archive archive = createTestFileArchive();

		String structureName = "foo";
		Structure structure = createStructure(archive, structureName);

		String typeDefSuffix = "_typedef";
		TypeDef typedef = createTypeDef(archive, structure, "foo" + typeDefSuffix);

		Pointer pointer = createPointer(archive, typedef);

		showSelectionDialog(pointer);

		deleteTypeDefTextBeforePointer(typeDefSuffix);

		pressOK();

		DataTypeChooserDialog chooserDialog = getDataTypeChooserDialog();
		assertNotNull(chooserDialog);

		pickSingleDataType(chooserDialog);

		pressOK(chooserDialog);// this will be on 'dialog'
		pressOK();
		assertFalse(
			"The dialog is visible when it should have been closed after " +
				"changing the type by typing and then picking a type from a non-default archive",
			dialog.isVisible());
		DataType dt = dialog.getUserChosenDataType();
		assertEquals(structureName + " *", dt.getName());
	}

	@Test
	public void testHandDeleteExistingEntryLeavingPointerCharOn_DataTypeInOtherArchive_Multiple() {
		//
		// Same as the above test, but with multiple archives form which to choose
		//
		Archive archive1 = createTestFileArchive();
		Archive archive2 = createTestFileArchive();

		String structureName = "foo";
		Structure structure = createStructure(archive1, structureName);
		addType(archive2, structure);// add to second archive too

		String typeDefSuffix = "_typedef";
		TypeDef typedef = createTypeDef(archive1, structure, "foo" + typeDefSuffix);
		addType(archive2, typedef);// add to second archive too

		Pointer pointer = createPointer(archive1, typedef);
		addType(archive2, pointer);// add to second archive too

		showSelectionDialog(pointer);

		deleteTypeDefTextBeforePointer(typeDefSuffix);

		pressOK();

		DataTypeChooserDialog chooserDialog = getDataTypeChooserDialog();
		assertNotNull(chooserDialog);

		pickFromMultipleDataTypes(chooserDialog);

		pressOK(chooserDialog);// this will be on 'dialog'
		pressOK();
		assertFalse(
			"The dialog is visible when it should have been closed after " +
				"changing the type by typing and then picking a type from a non-default archive",
			dialog.isVisible());
		DataType dt = dialog.getUserChosenDataType();
		assertEquals(structureName + " *", dt.getName());
	}

//==================================================================================================
// Support methods
//==================================================================================================

	private void addType(final Archive archive, final DataType dt) {
		runSwing(() -> {
			DataTypeManager dtm = archive.getDataTypeManager();
			int txID = dtm.startTransaction("Test Add Data Type");
			try {
				dtm.addDataType(dt, DataTypeConflictHandler.REPLACE_HANDLER);
			}
			finally {
				dtm.endTransaction(txID, true);
			}
		});
	}

	private Structure createStructure(Archive archive, String name) {
		StructureDataType structure = new StructureDataType(name, 0);
		structure.add(IntegerDataType.dataType, "field1", "Comment 1");
		structure.add(IntegerDataType.dataType, "field2", "Comment 2");
		structure.add(IntegerDataType.dataType, "field3", "Comment 3");

		addType(archive, structure);

		return structure;
	}

	private TypeDef createTypeDef(Archive archive, Structure structure, String name) {
		TypedefDataType dt = new TypedefDataType(name, structure);
		addType(archive, dt);
		return dt;
	}

	private Pointer createPointer(Archive archive, DataType dt) {
		PointerDataType pointer = new PointerDataType(dt);
		addType(archive, pointer);
		return pointer;
	}

	private Archive createTestFileArchive() {
		final AtomicReference<Archive> ref = new AtomicReference<>();
		runSwing(() -> {
			DataTypeManagerPlugin plugin = env.getPlugin(DataTypeManagerPlugin.class);
			DataTypeManagerHandler dataTypeManagerHandler = plugin.getDataTypeManagerHandler();
			File tempArchiveFile;
			try {
				tempArchiveFile = File.createTempFile("TestFileArchive", ".gdt");
			}
			catch (IOException e) {
				e.printStackTrace();
				return;
			}

			if (tempArchiveFile.exists()) {
				tempArchiveFile.delete();
			}
			tempArchiveFile.deleteOnExit();
			Archive archive = dataTypeManagerHandler.createArchive(tempArchiveFile);
			ref.set(archive);
		});

		Archive archive = ref.get();
		assertNotNull(archive);
		archivesToClose.add(archive);
		return archive;
	}

	private void closeArchive(final Archive archive) {
		runSwing(() -> {
			DataTypeManagerPlugin plugin = env.getPlugin(DataTypeManagerPlugin.class);
			DataTypeManagerHandler dataTypeManagerHandler = plugin.getDataTypeManagerHandler();
			dataTypeManagerHandler.closeArchive(archive);
		});
	}

	private void deleteTypeDefTextBeforePointer(String typeDefText) {
		DropDownSelectionTextField<?> editorTextField = getEditorTextField(dialog);
		String text = getText(editorTextField);
		text = text.replace(typeDefText, "");
		setText(editorTextField, text);
	}

	private void pickSingleDataType(DataTypeChooserDialog chooserDialog) {
		GTree gTree = (GTree) getInstanceField("tree", chooserDialog);
		GTreeNode rootNode = gTree.getViewRoot();
		waitForTree(gTree);
		List<GTreeNode> children = rootNode.getChildren();
		assertEquals(1, children.size());// one archive

		final GTreeNode tempArchiveNode = children.get(0);
		children = tempArchiveNode.getChildren();
		assertEquals(1, children.size());// one DT

		final GTreeNode dtNode = children.get(0);
		final JTree tree = (JTree) getInstanceField("tree", gTree);

		// select the node
		runSwing(() -> {
			tree.expandPath(tempArchiveNode.getTreePath());
			tree.setSelectionPath(dtNode.getTreePath());
		});
	}

	private void pickFromMultipleDataTypes(DataTypeChooserDialog chooserDialog) {
		GTree gTree = (GTree) getInstanceField("tree", chooserDialog);
		GTreeNode rootNode = gTree.getViewRoot();
		waitForTree(gTree);
		List<GTreeNode> children = rootNode.getChildren();
		assertEquals(2, children.size());// two archives

		final GTreeNode tempArchiveNode = children.get(1);// second one--why not?
		children = tempArchiveNode.getChildren();
		assertEquals(1, children.size());// one DT

		final GTreeNode dtNode = children.get(0);
		final JTree tree = (JTree) getInstanceField("tree", gTree);

		// select the node
		runSwing(() -> {
			tree.expandPath(tempArchiveNode.getTreePath());
			tree.setSelectionPath(dtNode.getTreePath());
		});
	}

	private void pressOK() {
		JButton okButton = (JButton) getInstanceField("okButton", dialog);
		pressButton(okButton);
	}

	private void pressOK(DataTypeChooserDialog chooserDialog) {
		JButton okButton = (JButton) getInstanceField("okButton", chooserDialog);
		pressButton(okButton);
	}

	private void showSelectionDialog(DataType dt) {
		dialog.setInitialDataType(dt);
		waitForSwing();
		showDialogWithoutBlocking(tool, dialog);
	}

	private void chooseSelectedItemInList() {
		final DropDownSelectionTextField<?> editorTextField = getEditorTextField(dialog);
		runSwing(() -> invokeInstanceMethod("setTextFromList", editorTextField));

		Window completionWindow = getCompletionWindow(dialog);
		assertNull("The completion window is visible double-clicking an entry", completionWindow);
	}

	private void closeDataTypeChooserTreeDialog(final DataTypeChooserDialog d) {
		// make sure there are no pending notifications from previous data changes 
		// before we close the dialog, as this could lead to a disposed worker being used
		waitForSwing();
		program.flushEvents();
		waitForSwing();

		runSwing(() -> d.close());

		waitForSwing();
	}

	private DataTypeManager getProgramDataTypeManager(final DataTypeManager[] dataTypeManagers) {
		for (DataTypeManager dataTypeManager : dataTypeManagers) {
			if (dataTypeManager instanceof ProgramDataTypeManager) {
				return dataTypeManager;
			}
		}
		Assert.fail("Unable to locate the program data type manager.");
		return null;// no-op because of failure above
	}

	private Category getProgramDataTypeManagerRootCategory(
			final DataTypeManager[] dataTypeManagers) {
		for (DataTypeManager dataTypeManager : dataTypeManagers) {
			if (dataTypeManager instanceof ProgramDataTypeManager) {
				return dataTypeManager.getRootCategory();
			}
		}
		Assert.fail("Unable to locate the program data type manager.");
		return null;// no-op because of failure above
	}

	private void runEnterCompletionText(String text) {
		// enter a known type so that the dialog can be closed with the OK button
		typeCompletionText("d");

		Window completionWindow = getCompletionWindow(dialog);
		assertTrue("The completion dialog was not shown after entering valid matching text.",
			completionWindow.isVisible());

		int hideId = spyTextField.getHideId();

		clearText(getEditorTextField(dialog));

		// Ugh: due to focus issues, we can't rely on the window being visible and hidden, so
		//      we prevent it from being hidden and rely on the callback upon which we are spying
		//      to know if the correct behavior happened.
		int newHideId = spyTextField.getHideId();
		assertTrue("The completion window is visible with no text in the text field.",
			hideId < newHideId);
	}

	private void clearText(final DropDownSelectionTextField<?> textField) {
		runSwing(() -> {
			textField.setSelectionStart(0);
			textField.setSelectionEnd(textField.getText().length());
			textField.requestFocus();
		});

		triggerActionKey(textField, 0, KeyEvent.VK_DELETE);
		waitForSwing();

		String currentText = getText(textField);
		if (!currentText.isEmpty()) {
			// the key typing didn't work; try manually updating the text (we could probably just
			// use this call instead of typing text, but the typing will execute a slightly 
			// different path in the code).
			Msg.debug(this, "Clearing the text by typing DELETE did not work--manually clearing");
			setText(textField, "");
		}
	}

	private DropDownSelectionTextField<?> getEditorTextField(
			DataTypeSelectionDialog selectionDialog) {
		DataTypeSelectionEditor editor =
			(DataTypeSelectionEditor) getInstanceField("editor", selectionDialog);
		return (DropDownSelectionTextField<?>) getInstanceField("selectionField", editor);
	}

	private Window getCompletionWindow(DataTypeSelectionDialog selectionDialog) {

		return (Window) getInstanceField("matchingWindow", getEditorTextField(selectionDialog));
	}

	// shows the dialog, cancels it, shows it again, types the given text and presses OK
	private void runShowHideDialog(String text, boolean hasMatches) {
		showDialogWithoutBlocking(tool, dialog);

		assertTrue("The dialog was not made visible when tool.showDialog() was called.",
			dialog.isVisible());

		JButton cancelButton = (JButton) getInstanceField("cancelButton", dialog);
		pressButton(cancelButton);

		assertTrue("The dialog did not close when the cancel button was pressed.",
			!dialog.isVisible());

		showDialogWithoutBlocking(tool, dialog);

		assertTrue("The dialog was not made visible when tool.showDialog() was called.",
			dialog.isVisible());

		JButton okButton = (JButton) getInstanceField("okButton", dialog);
		pressButton(okButton);

		assertTrue(
			"The dialog was closed without having a valid datatype entered in the text " + "field.",
			dialog.isVisible());

		// enter a know type so that the dialog can be closed with the OK button
		typeCompletionText(text);

		if (hasMatches) {
			Window completionWindow = getCompletionWindow(dialog);
			boolean isShowing = completionWindow.isShowing();
			assertTrue("The completion dialog was not shown after entering valid matching text.",
				isShowing);
		}

		pressOKButtonToSelectChoice(okButton);

		if (hasMatches) {
			String editorText = getEditorTextField(dialog).getText();
			String statusText = dialog.getStatusText();
			assertTrue("The dialog was not closed after pressing the 'OK' button with a valid " +
				"data type in the selection field (" + text + ")." + "\nThe status text: " +
				statusText + "\nEditor text: " + editorText, !dialog.isVisible());
		}
		else {
			pressButton(cancelButton);
		}
	}

	private void addDataType(final Category category, final DataType dataType) {

		runSwing(() -> category.addDataType(dataType, DataTypeConflictHandler.REPLACE_HANDLER));

		program.flushEvents();
		waitForSwing();

		waitForChooserTreeUpdate();
	}

	private void waitForChooserTreeUpdate() {
		waitForSwing();

		// only have to wait for the tree if it is visible
		DataTypeChooserDialog chooser = getDialogComponent(DataTypeChooserDialog.class);
		if (chooser != null) {
			DataTypeArchiveGTree tree = (DataTypeArchiveGTree) getInstanceField("tree", chooser);
			waitForTree(tree);
		}
	}

	private DataTypeChooserDialog getDataTypeChooserDialog() {
		waitForSwing();
		DataTypeChooserDialog d = waitForDialogComponent(DataTypeChooserDialog.class);
		return d;
	}

	private void pressOKButtonToSelectChoice(JButton okButton) {
		pressButton(okButton);
	}

	private void pressButton(final JButton button) {
		assertNotNull(button);
		executeOnSwingWithoutBlocking(() -> button.doClick());
		waitForSwing();
	}

	private void typeCompletionText(String text) {

		DropDownSelectionTextField<?> field = runSwing(() -> {
			DropDownSelectionTextField<?> editorTextField = getEditorTextField(dialog);
			String oldText = editorTextField.getText();
			editorTextField.setCaretPosition(oldText.length());
			editorTextField.requestFocus();

			return editorTextField;
		});

		triggerText(field, text);
		waitForSwing();
	}

	private void typeEscape() {
		triggerActionKey(getEditorTextField(dialog), 0, KeyEvent.VK_ESCAPE);
	}

//==================================================================================================
// Inner Classes
//==================================================================================================	

	/*
	 * A spy that allows us to track when the text field under test will trigger its window to
	 * be hidden.  We need this due to focus issues encountered in parallel mode.  Once we removed
	 * the focus-sensitive issues, we have to track being hidden using this mock method.
	 */
	private class SpyDropDownSelectionTextField<T extends DropDownTextField<T>> extends MockUp<T> {

		private volatile int hideId;

		@Mock
		protected void hideMatchingWindow() {
			++hideId;
		}

		int getHideId() {
			return hideId;
		}
	}

	private class ReportingDataListener implements DataTypeManagerChangeListener {

		@Override
		public void categoryAdded(DataTypeManager dtm, CategoryPath path) {
			// don't care for now
		}

		@Override
		public void categoryRemoved(DataTypeManager dtm, CategoryPath path) {
			// don't care for now
		}

		@Override
		public void categoryRenamed(DataTypeManager dtm, CategoryPath oldPath,
				CategoryPath newPath) {
			// don't care for now
		}

		@Override
		public void categoryMoved(DataTypeManager dtm, CategoryPath oldPath, CategoryPath newPath) {
			// don't care for now
		}

		@Override
		public void dataTypeAdded(DataTypeManager dtm, DataTypePath path) {
			Msg.debug(this, "listener - dt added: " + path);
		}

		@Override
		public void dataTypeRemoved(DataTypeManager dtm, DataTypePath path) {
			// don't care for now
		}

		@Override
		public void dataTypeRenamed(DataTypeManager dtm, DataTypePath oldPath,
				DataTypePath newPath) {
			// don't care for now
		}

		@Override
		public void dataTypeMoved(DataTypeManager dtm, DataTypePath oldPath, DataTypePath newPath) {
			// don't care for now
		}

		@Override
		public void dataTypeChanged(DataTypeManager dtm, DataTypePath path) {
			// don't care for now
		}

		@Override
		public void dataTypeReplaced(DataTypeManager dtm, DataTypePath oldPath,
				DataTypePath newPath, DataType newDataType) {
			// don't care for now
		}

		@Override
		public void favoritesChanged(DataTypeManager dtm, DataTypePath path, boolean isFavorite) {
			// don't care for now
		}

		@Override
		public void sourceArchiveChanged(DataTypeManager dataTypeManager,
				SourceArchive sourceArchive) {
			// don't care for now
		}

		@Override
		public void sourceArchiveAdded(DataTypeManager dataTypeManager,
				SourceArchive sourceArchive) {
			// don't care for now
		}
	}

	private class CustomDataType extends StructureDataType {
		public CustomDataType(CategoryPath path, String name, int length, DataTypeManager dtm) {
			super(path, name, length, dtm);
		}

		public CustomDataType(CategoryPath path, String name, int length) {
			super(path, name, length);
		}

		@Override
		public boolean isEquivalent(DataType dt) {
			return false;
		}
	}

//==================================================================================================
// Main method for manual testing
//==================================================================================================

	public static void main(String[] args) throws Exception {

		try {
			UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
		}
		catch (Exception e) {
			e.printStackTrace();
		}

		JFrame frame = new JFrame(DropDownSelectionTextField.class.getName());
		frame.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);

		TestEnv env = new TestEnv();

		ProgramBuilder builder = new ProgramBuilder("Bob", ProgramBuilder._TOY);
		Program program = builder.getProgram();
		final PluginTool tool = env.launchDefaultTool(program);

		JPanel panel = new JPanel();
		panel.setLayout(new BorderLayout());
		final DataTypeSelectionDialog editorDialog = new DataTypeSelectionDialog(tool,
			program.getDataTypeManager(), -1, AllowedDataTypes.ALL);

		final JTextField updateField = new JTextField();
		JButton launchButton = new JButton("Show Data Type Chooser Dialog");
		launchButton.addActionListener(new ActionListener() {
			DataType lastDataType;

			@Override
			public void actionPerformed(ActionEvent e) {

				if (lastDataType != null) {
					editorDialog.setInitialDataType(lastDataType);
				}
				tool.showDialog(editorDialog);

				DataType dt = editorDialog.getUserChosenDataType();
				if (dt != null) {
					lastDataType = dt;
					String name = dt.getName();
					DataTypeManager manager = dt.getDataTypeManager();
					String managerName = "";
					if (manager != null) {
						managerName = manager.getName();
					}
					String pathName = dt.getPathName();
					updateField.setText(name + " - " + managerName + pathName);
				}
				else {
					lastDataType = null;
					updateField.setText("[Dialog Cancelled]");
				}
			}
		});

		// check this highlighting biz out
		final JTextField panelUpdateField = new JTextField("Hey Mom");
		Highlighter highlighter = panelUpdateField.getHighlighter();
		highlighter.addHighlight(0, 2,
			new DefaultHighlighter.DefaultHighlightPainter(Color.YELLOW));

		JPanel editorPanel = new JPanel(new BorderLayout());
		DataTypeSelectionEditor editor =
			new DataTypeSelectionEditor(tool, AllowedDataTypes.ALL);
		editor.setPreferredDataTypeManager(program.getDataTypeManager());

		editorPanel.add(panelUpdateField, BorderLayout.SOUTH);
		editorPanel.add(editor.getEditorComponent(), BorderLayout.NORTH);

		panel.add(updateField, BorderLayout.SOUTH);
		panel.add(editorPanel, BorderLayout.CENTER);
		panel.add(launchButton, BorderLayout.NORTH);

		frame.getContentPane().add(panel);
		frame.setSize(300, 300);
		frame.setVisible(true);
	}
}
