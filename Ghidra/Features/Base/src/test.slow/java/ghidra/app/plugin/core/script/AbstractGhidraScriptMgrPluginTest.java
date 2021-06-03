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
package ghidra.app.plugin.core.script;

import static org.junit.Assert.*;

import java.awt.Window;
import java.io.*;
import java.lang.reflect.InvocationTargetException;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

import javax.swing.*;
import javax.swing.table.TableModel;
import javax.swing.text.JTextComponent;
import javax.swing.tree.TreePath;
import javax.swing.undo.UndoableEdit;

import org.junit.*;

import docking.ActionContext;
import docking.action.DockingActionIf;
import docking.widgets.OptionDialog;
import docking.widgets.filter.FilterTextField;
import docking.widgets.table.GDynamicColumnTableModel;
import docking.widgets.table.RowObjectTableModel;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import generic.jar.ResourceFile;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.console.ConsoleComponentProvider;
import ghidra.app.plugin.core.osgi.GhidraSourceBundle;
import ghidra.app.script.*;
import ghidra.app.services.ConsoleService;
import ghidra.framework.Application;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.test.*;
import ghidra.util.*;
import ghidra.util.datastruct.FixedSizeStack;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.GhidraTableFilterPanel;
import ghidra.util.task.*;
import util.CollectionUtils;
import utilities.util.FileUtilities;

public abstract class AbstractGhidraScriptMgrPluginTest
		extends AbstractGhidraHeadedIntegrationTest {
	// timeout for scripts run by invoking RunScriptTask directly
	protected static final int TASK_RUN_SCRIPT_TIMEOUT_SECS = 5;
	// timeout for scripts run indirectly through the GUI
	protected static final int GUI_RUN_SCRIPT_TIMEOUT_MSECS = 6 * DEFAULT_WAIT_TIMEOUT;
	protected TestEnv env;
	protected CodeBrowserPlugin browser;
	protected GhidraScriptMgrPlugin plugin;

	protected ConsoleService console;

	protected Program program;
	protected DraggableScriptTable scriptTable;
	protected JTextPane consoleTextPane;
	protected GhidraScriptEditorComponentProvider editor;
	protected JTextArea editorTextArea;
	protected ResourceFile testScriptFile;
	protected StringBuffer buffer;
	protected GhidraScriptComponentProvider provider;
	protected ToyProgramBuilder builder;

	@Before
	public void setUp() throws Exception {
		setErrorGUIEnabled(false);

		// change the eclipse port so that Eclipse doesn't try to edit the script when
		// testing locally
		System.setProperty("eclipse.launcher.port", "12345");

		program = buildProgram();

		env = new TestEnv();
		env.showTool(program);
		env.getTool().addPlugin(CodeBrowserPlugin.class.getName());
		Path userScriptDir = java.nio.file.Paths.get(GhidraScriptUtil.USER_SCRIPTS_DIR);
		if (Files.notExists(userScriptDir)) {
			Files.createDirectories(userScriptDir);
		}

		env.getTool().addPlugin(GhidraScriptMgrPlugin.class.getName());

		browser = env.getPlugin(CodeBrowserPlugin.class);
		assertNotNull(browser);

		plugin = env.getPlugin(GhidraScriptMgrPlugin.class);
		assertNotNull(plugin);

		console = env.getTool().getService(ConsoleService.class);
		assertNotNull(console);

		provider = plugin.getProvider();
		env.getTool().showComponentProvider(provider, true);

		ConsoleComponentProvider consoleProvider =
			waitForComponentProvider(ConsoleComponentProvider.class);
		consoleTextPane =
			(JTextPane) findComponentByName(consoleProvider.getComponent(), "CONSOLE");
		assertNotNull(consoleTextPane);

		scriptTable =
			(DraggableScriptTable) findComponentByName(provider.getComponent(), "SCRIPT_TABLE");
		assertNotNull(scriptTable);

		clearConsole();

		cleanupOldTestFiles();

		// synchronize GhidraScriptUtil static metadata with GUI metadata
		runSwing(() -> provider.refresh());

		waitForSwing();

	}

	protected Program buildProgram() throws Exception {
		//Default Tree
		builder = new ToyProgramBuilder("Test", false, this);

		builder.createMemory(".text", "0x1001000", 0xb000);

		program = builder.getProgram();

		//make some functions
		makeFunctionAt("0x010018a0");
		makeFunctionAt("0x010018cf");
		makeFunctionAt("0x0100194b");
		makeFunctionAt("0x01001978");
		makeFunctionAt("0x01001ae3");
		makeFunctionAt("0x0100219c");

		byte[] bytes = { (byte) 0x99, (byte) 0x66, (byte) 0x33, (byte) 0x00 };

		builder.setBytes("0x100b684", bytes);

		return builder.getProgram();
	}

	@After
	public void tearDown() throws Exception {
		closeAllWindows();
		waitForSwing();

		if (testScriptFile != null && testScriptFile.exists()) {
			deleteFile(testScriptFile);
			testScriptFile = null;
		}
		deleteUserScripts();

		env.dispose();
	}

	protected static void delete(Path path) {
		FileUtilities.deleteDir(path);
	}

	protected void deleteUserScripts() throws IOException {

		Path userScriptDir = Paths.get(GhidraScriptUtil.USER_SCRIPTS_DIR);
		FileUtilities.forEachFile(userScriptDir, paths -> paths.forEach(p -> delete(p)));
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	protected void assertScriptCategory(ResourceFile newScript, String category) throws Exception {

		try {
			BufferedReader reader =
				new BufferedReader(new InputStreamReader(newScript.getInputStream()));
			try {
				reader.readLine(); // header comment
				reader.readLine(); //@author
				String line = reader.readLine(); //@category
				assertEquals("//@category " + category, line);
			}
			finally {
				reader.close();
			}
		}
		finally {
			newScript.delete();
		}
	}

	protected void selectCategory(String category) {

		GTree categoryTree = (GTree) findComponentByName(provider.getComponent(), "CATEGORY_TREE");
		waitForTree(categoryTree);
		JTree jTree = (JTree) invokeInstanceMethod("getJTree", categoryTree);
		assertNotNull(jTree);
		GTreeNode child = categoryTree.getModelRoot().getChild(category);
		categoryTree.setSelectedNode(child);
		waitForTree(categoryTree);
		TreePath path = child.getTreePath();
		assertNotNull(path);
		assertEquals(category, path.getLastPathComponent().toString());
	}

	protected void assertScriptManagerKnowsAbout(ResourceFile script) {
		assertTrue(provider.getInfoManager().containsMetadata(script));
		assertNull(provider.getActionManager().get(script));
	}

	protected void assertScriptManagerForgotAbout(ResourceFile script) {
		assertFalse(provider.getInfoManager().containsMetadata(script));
		assertNull(provider.getActionManager().get(script));
		assertNull(provider.getEditorMap().get(script));
	}

	protected void assertScriptSelected(ResourceFile newScript) {
		assertEquals(newScript, provider.getScriptAt(getSelectedRow()));
	}

	protected int getScriptTableRow(ResourceFile script) {
		AtomicInteger ref = new AtomicInteger();
		runSwing(() -> ref.set(provider.getScriptIndex(script)));
		return ref.get();
	}

	protected ResourceFile finishNewScriptDialog() {

		ResourceFile script = finishNewScriptDialog(null);
		return script;
	}

	protected ResourceFile finishNewScriptDialog(String newScriptName) {

		SaveDialog saveDialog = waitForDialogComponent(SaveDialog.class);
		if (newScriptName != null) {
			setNewScriptName(saveDialog, newScriptName);
		}

		pressButtonByText(saveDialog, "OK");
		waitForSwing();

		ResourceFile newFile = (ResourceFile) invokeInstanceMethod("getFile", saveDialog);
		assertNotNull(newFile);

		JTextField textField = (JTextField) getInstanceField("nameField", saveDialog);
		assertTrue("New script dialog did not close.  Message: " + saveDialog.getStatusText() +
			" - text: " + textField.getText(), !saveDialog.isShowing());

		return newFile;
	}

	protected FilterTextField getTableFilterField() {

		@SuppressWarnings("unchecked")
		GhidraTableFilterPanel<File> filterPanel =
			(GhidraTableFilterPanel<File>) getInstanceField("tableFilterPanel", provider);
		assertNotNull(filterPanel);
		FilterTextField filterField =
			(FilterTextField) getInstanceField("filterField", filterPanel);
		assertNotNull(filterField);

		return filterField;
	}

	protected void assertContainsText(String piece, String fullText) {
		assertContainsText("Did not find \"" + piece + "\" inside of text\n[\n" + fullText + "\n]",
			piece, fullText);
	}

	protected void assertContainsText(String message, String piece, String fullText) {
		assertTrue(message, fullText.contains(piece));
	}

	private DockingActionIf getRunLastScriptAction() {
		// note: this provider adds 2 versions of the same action--pick either
		Set<DockingActionIf> actions =
			getActionsByOwnerAndName(plugin.getTool(), plugin.getName(), "Rerun Last Script");
		assertFalse(actions.isEmpty());
		DockingActionIf runLastAction = CollectionUtils.any(actions);
		return runLastAction;
	}

	protected void assertRunLastActionEnabled(boolean enabled) {

		DockingActionIf runLastAction = getRunLastScriptAction();
		final AtomicReference<Boolean> ref = new AtomicReference<>();
		runSwing(() -> ref.set(runLastAction.isEnabledForContext(new ActionContext())));
		assertEquals("Run Last Action not enabled as expected", enabled, ref.get());
	}

	protected void clearConsole() throws InterruptedException, InvocationTargetException {
		SwingUtilities.invokeAndWait(() -> console.clearMessages());
		waitForSwing();
	}

	protected ResourceFile selectScript(ResourceFile script) throws Exception {

		selectScript(script.getName());
		return script;
	}

	protected int indexOfColumn(String columnName) {
		TableModel tableModel = scriptTable.getModel();
		GDynamicColumnTableModel<?, ?> model =
			(GDynamicColumnTableModel<?, ?>) RowObjectTableModel.unwrap(tableModel);

		int columnCount = model.getColumnCount();
		for (int i = 0; i < columnCount; i++) {
			String name = model.getColumnName(i);
			if (columnName.equals(name)) {
				return i;
			}
		}
		fail("Unable to find column '" + columnName + "'");
		return -1;
	}

	protected ResourceFile selectScript(final String scriptName) throws Exception {

		int columnIndex = indexOfColumn("Name");
		final AtomicReference<Integer> ref = new AtomicReference<>();
		runSwing(() -> {
			TableModel model = scriptTable.getModel();
			for (int i = 0; i < model.getRowCount(); i++) {
				if (model.getValueAt(i, columnIndex).equals(scriptName)) {
					ref.set(i);
					break;
				}
			}
		});

		Integer row = ref.get();
		assertTrue(row != null && row >= 0);
		final int selectedRow = row;
		SwingUtilities.invokeAndWait(() -> {
			console.clearMessages();
			scriptTable.setRowSelectionInterval(selectedRow, selectedRow);
		});
		waitForSwing();

		ResourceFile scriptFile = provider.getScriptAt(row);
		return scriptFile;
	}

	protected ResourceFile loadTempScriptIntoEditor() throws IOException {
		ResourceFile newScriptFile = createTempScriptFile();

		openInEditor(newScriptFile);

		testScriptFile = newScriptFile;
		return newScriptFile;
	}

	/**
	 * This call will:
	 * -open the file in an editor
	 * -update the text area and buffer fields of this test
	 * @param file the file to open
	 */
	protected void openInEditor(final ResourceFile file) {
		runSwing(() -> editor = provider.editScriptInGhidra(file));

		assertNotNull(editor);

		editorTextArea = (JTextArea) findComponentByName(editor.getComponent(),
			GhidraScriptEditorComponentProvider.EDITOR_COMPONENT_NAME);
		assertNotNull(editorTextArea);

		buffer = new StringBuffer(editorTextArea.getText());
	}

	protected ResourceFile createNewScriptUsingGUI()
			throws InterruptedException, InvocationTargetException {

		pressNewButton();

		chooseJavaProvider();

		SaveDialog saveDialog = waitForDialogComponent(SaveDialog.class);
		pressButtonByText(saveDialog, "OK");
		waitForSwing();

		// initialize our editor variable to the newly opened editor
		editor = waitForComponentProvider(GhidraScriptEditorComponentProvider.class);
		editorTextArea = (JTextArea) findComponentByName(editor.getComponent(),
			GhidraScriptEditorComponentProvider.EDITOR_COMPONENT_NAME);

		waitForSwing();

		return saveDialog.getFile();
	}

	protected void assertCannotCreateNewScriptByName(final String name) throws Exception {

		pressNewButton();

		chooseJavaProvider();

		final SaveDialog saveDialog = waitForDialogComponent(SaveDialog.class);
		final JTextField nameField = (JTextField) getInstanceField("nameField", saveDialog);
		runSwing(() -> {
			nameField.setText(name);
			saveDialog.okCallback();
		});

		String statusText = saveDialog.getStatusText();
		boolean foundExpectedMessage = "Duplicate script name.".equals(statusText) ||
			"File already exists on disk.".equals(statusText);

		// cancel to prevent residual file creation after the test closes open dialogs
		runSwing(() -> saveDialog.cancelCallback());

		assertTrue("Did not get expected error message when attempting " +
			"to create new script.  Found: " + statusText, foundExpectedMessage);
	}

	protected void assertCannotPerformSaveAsByName(final String name) {
		DockingActionIf newAction = getAction(plugin, "Save Script As");
		performAction(newAction, false);
		waitForSwing();

		final SaveDialog saveDialog = waitForDialogComponent(SaveDialog.class);
		final JTextField nameField = (JTextField) getInstanceField("nameField", saveDialog);
		runSwing(() -> {
			nameField.setText(name);
			saveDialog.okCallback();
		});

		String statusText = saveDialog.getStatusText();

		// cancel to prevent residual file creation after the test closes open dialogs
		runSwing(() -> saveDialog.cancelCallback());

		assertEquals("File already exists on disk.", statusText);
	}

	protected void assertCannotPerformSaveAsByNameDueToDuplicate(final String name) {
		DockingActionIf newAction = getAction(plugin, "Save Script As");
		performAction(newAction, false);
		waitForSwing();

		final SaveDialog saveDialog = waitForDialogComponent(SaveDialog.class);
		final JTextField nameField = (JTextField) getInstanceField("nameField", saveDialog);
		runSwing(() -> {
			nameField.setText(name);
			saveDialog.okCallback();
		});

		String statusText = saveDialog.getStatusText();

		// cancel to prevent residual file creation after the test closes open dialogs
		runSwing(() -> saveDialog.cancelCallback());

		assertEquals("Duplicate script name.", statusText);
	}

	protected void assertSaveAs(final String name) {
		DockingActionIf newAction = getAction(plugin, "Save Script As");
		performAction(newAction, false);
		waitForSwing();

		final SaveDialog saveDialog = waitForDialogComponent(SaveDialog.class);
		final JTextField nameField = (JTextField) getInstanceField("nameField", saveDialog);
		runSwing(() -> {
			nameField.setText(name);
			saveDialog.okCallback();
		});

		assertFalse(saveDialog.isVisible());
	}

	protected void assertCannotRefresh() {
		pressRefreshButton();

		// this call will fail if we are not prompted about overwriting the file
		chooseCancel_ForMissingFile();
	}

	protected ResourceFile createTempScriptFile() throws IOException {
		return createTempScriptFile(testName.getMethodName());
	}

	protected ResourceFile createTempScriptFile(String name) throws IOException {
		return createTempScriptFile(name, null);
	}

	protected ResourceFile createTempScriptFile(String name, String pkg) throws IOException {
		if (name.length() > 50) {
			// too long and the script manager complains
			name = name.substring(name.length() - 50);
		}

		File scriptDir = null;
		if (pkg != null) {
			scriptDir = new File(GhidraScriptUtil.USER_SCRIPTS_DIR + "/" + pkg.replace(".", "/"));
			scriptDir.mkdirs();
			scriptDir.deleteOnExit();
		}
		else {
			scriptDir = new File(GhidraScriptUtil.USER_SCRIPTS_DIR);
		}

		File tempFile = File.createTempFile(name, ".java", scriptDir);
		tempFile.deleteOnExit();
		return new ResourceFile(tempFile);
	}

	protected ResourceFile createTempScriptFileWithLines(String... lines) throws IOException {
		ResourceFile newScript = createTempScriptFile();

		PrintWriter writer = new PrintWriter(newScript.getOutputStream());
		for (String line : lines) {
			writer.println(line);
		}
		writer.close();

		return newScript;
	}

	protected String changeEditorContents() {
		assertNotNull("Editor not opened and initialized", editorTextArea);
		assertNotNull("Editor not opened and initialized", buffer);

		// just insert some text into the buffer
		buffer.append("Test text: ").append(testName.getMethodName());

		runSwing(() -> {
			editorTextArea.setText(buffer.toString());
		});

		waitForSwing();
		return buffer.toString();
	}

	protected String changeFileOnDisk(ResourceFile file) throws IOException {
		String fileText = readFileContents(file);
		String updatedText =
			fileText + "\nChanges to file on disk for test: " + testName.getMethodName() + "\n";

		writeStringToFile(file, updatedText);

		return updatedText;
	}

	protected void writeStringToFile(ResourceFile file, String string) throws IOException {
		BufferedWriter writer = new BufferedWriter(new FileWriter(file.getFile(false)));
		writer.write(string);
		writer.close();
	}

	protected void pressNewButton() {
		DockingActionIf newAction = getAction(plugin, "New");
		performAction(newAction, false);
		waitForSwing();
	}

	protected void pressRenameButton() {
		DockingActionIf renameAction = getAction(plugin, "Rename");
		performAction(renameAction, false);
		waitForSwing();

	}

	protected void pressSaveButton() {
		DockingActionIf action = getAction(plugin, "Save Script");
		performAction(action, false);// don't wait--may be a modal dialog
		waitForSwing();
	}

	protected void pressRefreshButton() {
		DockingActionIf action = getAction(plugin, "Refresh Script");
		performAction(action, false);// don't wait--may be a modal dialog
		waitForSwing();
	}

	protected void pressRunButton() {
		DockingActionIf action = getAction(plugin, "Run");
		performAction(action, false);
		waitForSwing();
	}

	protected void pressRunLastScriptButton() {
		DockingActionIf runLastAction = getRunLastScriptAction();
		performAction(runLastAction, false);
		waitForSwing();
	}

	protected KeyBindingInputDialog pressKeyBindingAction() {
		DockingActionIf keyBindingAction = getAction(plugin, "Key Binding");
		performAction(keyBindingAction, false);
		waitForSwing();

		KeyBindingInputDialog kbid = waitForDialogComponent(KeyBindingInputDialog.class);
		assertNotNull(kbid);

		return kbid;
	}

	protected void pressDeleteButton() {
		DockingActionIf deleteAction = getAction(plugin, "Delete");
		performAction(deleteAction, false);
		waitForSwing();
	}

	protected void deleteScriptThroughUI() {
		pressDeleteButton();

		OptionDialog deleteDialog = waitForDialogComponent(OptionDialog.class);
		pressButtonByText(deleteDialog, "Yes");
		waitForSwing();
	}

	/**
	 * Run the currently selected script by pressing the run button and return its output.
	 * 
	 * @param taskName name for the task listener
	 * @return script output written to the console
	 * @throws Exception on failure, e.g. timeout
	 */
	protected String runSelectedScript(String taskName) throws Exception {
		clearConsole();

		TaskListenerFlag taskFlag = new TaskListenerFlag(taskName);
		TaskUtilities.addTrackedTaskListener(taskFlag);

		pressRunButton();
		waitForTaskEnd(taskFlag);

		String output = getConsoleText();
		clearConsole();
		return output;
	}

	/**
	 * Run the last script by pressing the last script button and return output.
	 * 
	 * @param taskName name for the task listener
	 * @return script output written to the console
	 * @throws Exception on failure, e.g. timeout
	 */
	protected String runLastScript(String taskName) throws Exception {
		TaskListenerFlag taskFlag = new TaskListenerFlag(taskName);
		TaskUtilities.addTrackedTaskListener(taskFlag);

		pressRunLastScriptButton();
		waitForTaskEnd(taskFlag);

		String output = getConsoleText();
		clearConsole();
		return output;
	}

	protected void deleteFile(ResourceFile file) {
		assertTrue(file.delete());
	}

	protected void assertFileSaved(ResourceFile file, String expectedContents) throws IOException {
		//
		// verify that the contents of the file on disk are the same as those from our buffer
		//
		waitForSwing();
		String fileText = readFileContents(file);

		if (!expectedContents.trim().equals(fileText.trim())) {
			System.err.println(
				"Contents of file on disk do not match that of the editor after performing " +
					"a save operation: " + file);
			printChars(expectedContents, fileText);
			Assert.fail(
				"Contents of file on disk do not match that of the editor after performing " +
					"a save operation: " + file);
		}
//
//		assertEquals("Contents of file on disk do not match that of the editor after performing " +
//			"a save operation: " + file, expectedContents, fileText);
	}

	protected void assertFileContentsSame(String expectedContents, ResourceFile file)
			throws IOException {
		String fileText = readFileContents(file);

		if (!expectedContents.trim().equals(fileText.trim())) {
			System.err.println("Contents of file on disk have been unexpectedly changed: " + file);
			printChars(expectedContents, fileText);
			Assert.fail("Contents of file on disk have been unexpectedly changed: " + file);
		}
//
//		assertEquals("Contents of file on disk have been unexpectedly changed: " + file,
//			expectedContents, fileText);
	}

	protected String changeScriptCategory(ResourceFile script) throws Exception {
		String newCategory = testName.getMethodName() + System.currentTimeMillis();
		return changeScriptCategory(script, newCategory);
	}

	protected String changeScriptCategory_WithSubcatogory(ResourceFile script) throws Exception {
		String newCategory =
			testName.getMethodName() + System.currentTimeMillis() + ".Cat1.CatName";
		return changeScriptCategory(script, newCategory);
	}

	protected String changeScriptCategory(ResourceFile script, String newCategory)
			throws IOException {
		String contents = readFileContents(script);

		// Format:
		//@category name
		contents = contents.replaceFirst("//@category \\w+", "//@category " + newCategory);

		writeStringToFile(script, contents);

		//
		// Unusual Code: the ScriptManager uses last modified to know when to refresh.  Our test
		//               runs fast enough that the resolution of lastModified is not tripped, so
		//               manually force a change.
		//
		File file = script.getFile(false);
		long lastModified = file.lastModified();
		long inTheFuture = 10000 + System.currentTimeMillis();
		file.setLastModified(lastModified + inTheFuture);

		return newCategory;
	}

	protected void assertCategoryInTree(String newCategory) {
		GTree tree = (GTree) getInstanceField("scriptCategoryTree", provider);
		waitForTree(tree);

		GTreeNode parentNode = tree.getModelRoot();

		String[] parts = newCategory.split("\\.");
		for (String category : parts) {
			parentNode = findChildByName(parentNode, category);
			assertNotNull("Could not find category in tree: " + newCategory, parentNode);
		}
	}

	protected GTreeNode findChildByName(GTreeNode node, String name) {
		List<GTreeNode> children = node.getChildren();
		for (GTreeNode child : children) {
			if (child.getName().equals(name)) {
				return child;
			}
		}
		return null;
	}

	protected void assertCategoryNotInTree(String oldCategory) {
		GTree tree = (GTree) getInstanceField("scriptCategoryTree", provider);
		waitForTree(tree);

		GTreeNode rootNode = tree.getModelRoot();
		List<GTreeNode> children = rootNode.getChildren();
		for (GTreeNode node : children) {
			if (node.getName().equals(oldCategory)) {
				Assert.fail("Category in tree when expected not to be: " + oldCategory);
			}
		}
	}

	protected String readFileContents(ResourceFile script) throws IOException {
		BufferedReader reader = new BufferedReader(new InputStreamReader(script.getInputStream()));
		StringBuilder stringBuilder = new StringBuilder();

		String line = null;
		while ((line = reader.readLine()) != null) {
			stringBuilder.append(line).append('\n');
		}

		reader.close();

		return stringBuilder.toString();
	}

	protected void assertEditorContentsSame(String expectedText) {
		assertNotNull("Editor not opened and initialized", editorTextArea);

		final String[] box = new String[1];
		runSwing(() -> box[0] = editorTextArea.getText());

		if (!expectedText.equals(box[0])) {
//			// let's examine these strings a bit closer, as something in the error reporting
//			// is not quite right
//			System.err.println("length of strings: " + expectedText.length() + " and " +
//				box[0].length());
//
//			int start = 0;
//			StringDiff[] diffs = StringUtilities.getDiffs(expectedText, box[0]);
//			for (StringDiff diff : diffs) {
//				boolean isInsert = diff.insertData != null;
//				if (isInsert) {
//					System.err.println("\n\n>>>\t\tdiff context:\t\t<<<\n" +
//						box[0].substring(start, diff.pos1 - diff.insertData.length()));
//					System.err.println("\n\n>>>>\tinserted value:\t\t<<<\n" + diff.insertData);
//				}
//				else {
//					System.err.println("\n\n>>>\t\tdiff context:\t\t<<<\n" +
//						box[0].substring(start, diff.pos1));
//					System.err.println("\n\n>>>>\tdeleted value:\t\t<<<\n" +
//						expectedText.substring(diff.pos1, diff.pos2));
//				}
//			}
//
			System.err.println("The editor's text does not contain the expected text");
			printChars(expectedText, box[0]);
			Assert.fail("The editor's text does not contain the expected text");
		}

		assertEquals("The editor's text does not contain the expected text", expectedText, box[0]);
	}

	protected void printChars(String expected, String found) {
		// maybe there is a whitespace issue...print each char code
		System.err.println("chars for expected string: ");
		for (int i = 0; i < expected.length(); i++) {
			char c = expected.charAt(i);
			System.err.println(c + " and value: " + ((int) c));
		}

		System.err.println("chars for found string: ");
		for (int i = 0; i < found.length(); i++) {
			char c = found.charAt(i);
			System.err.println(c + " and value: " + ((int) c));
		}
	}

	protected void assertEditorContentsSame(ResourceFile file, String expectedText) {

		Map<ResourceFile, GhidraScriptEditorComponentProvider> editorMap = provider.getEditorMap();
		GhidraScriptEditorComponentProvider fileEditor = editorMap.get(file);
		final JTextArea textArea = (JTextArea) findComponentByName(fileEditor.getComponent(),
			GhidraScriptEditorComponentProvider.EDITOR_COMPONENT_NAME);
		assertNotNull(textArea);

		final String[] box = new String[1];
		runSwing(() -> box[0] = textArea.getText());

		assertEquals("The editor's text does not contain the expected text.  File: " + file,
			expectedText, box[0]);
	}

	protected void chooseOverwriteFileOnDisk() {
		String title = GhidraScriptEditorComponentProvider.FILE_ON_DISK_CHANGED_TITLE;
		OptionDialog fileChangedDialog = waitForDialogComponent(OptionDialog.class);
		assertNotNull("Could not find dialog: " + title, fileChangedDialog);

		final JButton keepChangesButton = findButtonByText(fileChangedDialog,
			GhidraScriptEditorComponentProvider.KEEP_CHANGES_TEXT);
		runSwing(() -> keepChangesButton.doClick());

		OptionDialog destinationDialogDialog = waitForDialogComponent(OptionDialog.class);
		assertEquals(GhidraScriptEditorComponentProvider.CHANGE_DESTINATION_TITLE,
			destinationDialogDialog.getTitle());

		final JButton overwriteButton = findButtonByText(destinationDialogDialog,
			GhidraScriptEditorComponentProvider.OVERWRITE_CHANGES_TEXT);
		runSwing(() -> overwriteButton.doClick());
	}

	protected void chooseDiscaredEditorChanges() {
		String title = GhidraScriptEditorComponentProvider.FILE_ON_DISK_CHANGED_TITLE;
		OptionDialog fileChangedDialog = waitForDialogComponent(OptionDialog.class);
		assertNotNull("Could not find dialog: " + title, fileChangedDialog);

		final JButton button = findButtonByText(fileChangedDialog,
			GhidraScriptEditorComponentProvider.DISCARD_CHANGES_TEXT);
		runSwing(() -> button.doClick());

		waitForSwing();
	}

	protected void chooseCancel() {
		String title = GhidraScriptEditorComponentProvider.FILE_ON_DISK_CHANGED_TITLE;
		OptionDialog fileChangedDialog = waitForDialogComponent(OptionDialog.class);
		assertNotNull("Could not find dialog: " + title, fileChangedDialog);

		assertEquals(title, fileChangedDialog.getTitle());

		final JButton button = findButtonByText(fileChangedDialog, "Cancel");
		runSwing(() -> button.doClick());
	}

	protected ResourceFile chooseSaveAs() {
		String title = GhidraScriptEditorComponentProvider.FILE_ON_DISK_CHANGED_TITLE;
		OptionDialog fileChangedDialog = waitForDialogComponent(OptionDialog.class);
		assertNotNull("Could not find dialog: " + title, fileChangedDialog);

		final JButton keepChangesButton = findButtonByText(fileChangedDialog,
			GhidraScriptEditorComponentProvider.KEEP_CHANGES_TEXT);
		runSwing(() -> keepChangesButton.doClick());

		OptionDialog optionDialog = waitForDialogComponent(OptionDialog.class);
		assertEquals(GhidraScriptEditorComponentProvider.CHANGE_DESTINATION_TITLE,
			optionDialog.getTitle());

		final JButton saveAsButton = findButtonByText(optionDialog,
			GhidraScriptEditorComponentProvider.SAVE_CHANGES_AS_TEXT);
		runSwing(() -> saveAsButton.doClick());

		return processSaveAsDialog();
	}

	protected ResourceFile chooseSaveAs_ForMissingFile() {
		String title = GhidraScriptEditorComponentProvider.FILE_ON_DISK_MISSING_TITLE;
		OptionDialog fileMissingDialog = waitForDialogComponent(OptionDialog.class);
		assertNotNull("Could not find dialog: " + title, fileMissingDialog);

		final JButton keepChangesButton = findButtonByText(fileMissingDialog,
			GhidraScriptEditorComponentProvider.KEEP_CHANGES_TEXT);
		runSwing(() -> keepChangesButton.doClick());

		return processSaveAsDialog();
	}

	protected void chooseCancel_ForMissingFile() {
		String title = GhidraScriptEditorComponentProvider.FILE_ON_DISK_MISSING_TITLE;
		OptionDialog fileChangedDialog = waitForDialogComponent(OptionDialog.class);
		assertNotNull("Could not find dialog: " + title, fileChangedDialog);

		assertEquals(title, fileChangedDialog.getTitle());

		final JButton button = findButtonByText(fileChangedDialog, "Cancel");
		runSwing(() -> button.doClick());
	}

	protected ResourceFile processSaveAsDialog() {
		final String newFileName = testName.getMethodName() + System.currentTimeMillis() + ".java";
		final SaveDialog saveDialog = waitForDialogComponent(SaveDialog.class);

		final JTextField nameField = (JTextField) getInstanceField("nameField", saveDialog);
		runSwing(() -> {
			nameField.setText(newFileName);
			saveDialog.okCallback();
		});

		// after closing the dialog we have to wait for the work to finish in the Swing thread
		// that existed before the modal dialog's Swing thread.
		waitForSwing();

		ResourceFile file = saveDialog.getFile();

		assertEquals(newFileName, file.getName());
		assertTrue(file.exists());

		File realFile = file.getFile(false);
		realFile.deleteOnExit();
		return file;
	}

	protected void assertFileInEditor(ResourceFile... files) {
		Map<ResourceFile, GhidraScriptEditorComponentProvider> map = provider.getEditorMap();
		for (ResourceFile file : files) {
			GhidraScriptEditorComponentProvider editorComp = map.get(file);
			assertNotNull("Editor not found for file: " + file, editorComp);
		}

	}

	protected void cleanupOldTestFiles() {
		// remove the compiled bundles directory so that any scripts we use will be recompiled
		delete(GhidraSourceBundle.getCompiledBundlesDir());

		String myTestName = super.testName.getMethodName();

		// destroy any NewScriptxxx files...and Temp ones too
		List<ResourceFile> paths = provider.getBundleHost()
				.getBundleFiles()
				.stream()
				.filter(ResourceFile::isDirectory)
				.collect(Collectors.toList());

		for (ResourceFile path : paths) {
			File file = path.getFile(false);
			File[] listFiles = file.listFiles();
			if (listFiles == null) {
				continue;
			}

			for (File dirFile : listFiles) {
				String name = dirFile.getName();
				if (name.startsWith("NewScript") || name.startsWith("Temp") ||
					name.startsWith(myTestName)) {
					deleteFile(new ResourceFile(dirFile));
				}
			}
		}
	}

	protected void closeScriptProvider() {
		PluginTool tool = plugin.getTool();
		tool.showComponentProvider(provider, false);
	}

	protected String getConsoleText() {
		// let the update manager have a chance to run
		waitForSwing();
		final String[] container = new String[1];
		runSwing(() -> container[0] = consoleTextPane.getText());
		return container[0];
	}

	protected void chooseJavaProvider() throws InterruptedException, InvocationTargetException {

		if (GhidraScriptUtil.getProviders().size() <= 1) {
			return;
		}

		final PickProviderDialog ppd = waitForDialogComponent(PickProviderDialog.class);
		if (ppd != null) {
			SwingUtilities.invokeAndWait(() -> ppd.setSelectedProvider(new JavaScriptProvider()));
			waitForSwing();
			pressButtonByText(ppd, "OK");
			waitForSwing();
		}
	}

	protected void waitForTaskEnd(TaskListenerFlag flag) {
		waitForSwing();

		int totalTime = 0;
		while (!flag.ended && totalTime <= GUI_RUN_SCRIPT_TIMEOUT_MSECS) {
			totalTime += sleep(DEFAULT_WAIT_DELAY);
		}

		TaskUtilities.removeTrackedTaskListener(flag);

		if (!flag.ended) {
			Assert.fail("Task took too long to complete: " + flag);
		}
		Msg.debug(this, flag.taskName + " task ended in " + totalTime + " ms");
	}

	protected int getSelectedRow() {
		final int[] box = new int[1];
		runSwing(() -> box[0] = scriptTable.getSelectedRow());
		return box[0];
	}

	protected void assertScriptInScriptManager(ResourceFile script) {
		int row = getScriptTableRow(script);
		assertTrue(row >= 0);
	}

	protected void refreshScriptManager() {
		DockingActionIf refreshAction = getAction(plugin, "Refresh");
		performAction(refreshAction, false);
		waitForSwing();
	}

	protected void refreshProvider() {
		runSwing(() -> provider.refresh());

		// we have an invokeLater() situation, where the refresh triggers table data to be
		// re-selected in an invokeLater(), so we must wait for that.
		waitForSwing();
	}

	protected void setNewScriptName(SaveDialog sd, final String newScriptName) {
		final JTextField nameField = (JTextField) getInstanceField("nameField", sd);
		runSwing(() -> nameField.setText(newScriptName));
	}

	protected int getRowCount() {
		final int[] box = new int[1];
		runSwing(() -> box[0] = scriptTable.getRowCount());
		return box[0];
	}

	protected void assertSaveButtonEnabled() throws Exception {
		waitForSwing();
		DockingActionIf saveAction = getAction(plugin, "Save Script");

		boolean isEnabled = saveAction.isEnabledForContext(editor.getActionContext(null));
		if (!isEnabled) {
			// the action is enabled when the provider detects changes; it is disabled for read-only

			if (isReadOnly(testScriptFile)) {
				Msg.error(this,
					"Cannot edit a read-only script: " + testScriptFile.getAbsolutePath());
				Msg.error(this, "Script cannot be in a 'system root'; those are: ");
				Collection<ResourceFile> roots = Application.getApplicationRootDirectories();
				for (ResourceFile resourceFile : roots) {
					String root = resourceFile.getCanonicalPath().replace('\\', '/');
					Msg.error(this, "\troot: " + root);
				}
				fail("Unexpected read-only script (see log)");
			}

			//
			// inside knowledge; brittle code
			// 
			@SuppressWarnings("unchecked")
			FixedSizeStack<UndoableEdit> undoStack =
				(FixedSizeStack<UndoableEdit>) getInstanceField("undoStack", editor);
			if (undoStack.isEmpty()) {

				JTextComponent editTextComponent = grabScriptEditorTextArea();
				String text = getText(editTextComponent);
				fail("No undo items for the script editor--did edit take place?  Editor text: " +
					text);
			}

			Boolean isMissing = (Boolean) invokeInstanceMethod("isFileOnDiskMissing", editor);
			if (!isMissing) {

				JTextComponent editTextComponent = grabScriptEditorTextArea();
				String text = getText(editTextComponent);
				fail("Expected a deleted file to trigger save button enablement.  Editor text: " +
					text);
			}
		}
	}

	private boolean isReadOnly(ResourceFile script) {
		assertNotNull(script);
		return GhidraScriptUtil.isSystemScript(script);
	}

	protected void assertSaveButtonDisabled() {
		waitForSwing();
		DockingActionIf saveAction = getAction(plugin, "Save Script");
		assertFalse(saveAction.isEnabledForContext(editor.getActionContext(null)));

		assertEditorHasNoChanges();
	}

	protected void assertEditorHasNoChanges() {
		final Boolean[] box = new Boolean[1];
		runSwing(() -> box[0] = editor.hasChanges());

		assertFalse("Editor is signaling that it has unsaved changes when expected no " + "changes",
			box[0]);
	}

	protected ResourceFile findScript(String name) {
		ScriptInfo info = provider.getInfoManager().getExistingScriptInfo(name);
		assertNotNull("Cannot find script by the given name: " + name, info);
		return info.getSourceFile();
	}

	protected static String CANCELLABLE_SCRIPT_NAME = TestChangeProgramScript.class.getName();

	protected void cancel() throws Exception {
		Window window = waitForWindowByTitleContaining(CANCELLABLE_SCRIPT_NAME);
		assertNotNull("Could not find script progress dialog", window);
		pressButtonByText(window, "Cancel");
	}

	protected TestChangeProgramScript startCancellableScriptTask() throws Exception {
		TestChangeProgramScript script = new TestChangeProgramScript();
		ResourceFile fakeFile = new ResourceFile(createTempFile(CANCELLABLE_SCRIPT_NAME, "java"));
		script.setSourceFile(fakeFile);
		startRunScriptTask(script);

		boolean success = script.waitForStart();
		assertTrue("Test script did not get started!", success);

		return script;
	}

	protected void cancel_Yes(TestChangeProgramScript script) throws Exception {
		Window window = waitForWindow("Cancel?");
		pressButtonByText(window, "Yes");

		// debug
		printOpenWindows();

		boolean success = script.waitForFinish();
		assertTrue("Timed-out waiting for cancelled script to complete", success);
	}

	protected void cancel_No(TestChangeProgramScript script) throws Exception {
		Window window = waitForWindow("Cancel?");
		pressButtonByText(window, "No");
		assertFalse(window.isShowing());

		window = waitForWindowByTitleContaining(CANCELLABLE_SCRIPT_NAME);
		assertNotNull("Could not find script progress dialog", window);

		script.testOver();

		boolean success = script.waitForFinish();
		assertTrue("Timed-out waiting for cancelled script to complete", success);
	}

	protected void startRunScriptTask(GhidraScript script) throws Exception {
		Task task = new RunScriptTask(script, plugin.getCurrentState(), console);
		task.addTaskListener(provider.getTaskListener());
		new TaskLauncher(task, plugin.getTool().getToolFrame());
	}

	protected String runScriptAndGetOutput(ResourceFile scriptFile) throws Exception {
		GhidraScriptProvider scriptProvider = GhidraScriptUtil.getProvider(scriptFile);
		GhidraScript script =
			scriptProvider.getScriptInstance(scriptFile, new PrintWriter(System.err));

		return runScriptTaskAndGetOutput(script);
	}

	protected String runScriptTaskAndGetOutput(GhidraScript script) throws Exception {
		SpyConsole spyConsole = installSpyConsole();

		Task task = new RunScriptTask(script, plugin.getCurrentState(), spyConsole);
		task.addTaskListener(provider.getTaskListener());

		CountDownLatch latch = new CountDownLatch(1);
		task.addTaskListener(new TaskListener() {

			@Override
			public void taskCompleted(Task t) {
				latch.countDown();
			}

			@Override
			public void taskCancelled(Task t) {
				latch.countDown();
			}
		});

		TaskLauncher.launch(task);

		latch.await(TASK_RUN_SCRIPT_TIMEOUT_SECS, TimeUnit.SECONDS);

		String output = spyConsole.getApiOutput();
		spyConsole.clear();
		return output;
	}

	protected SpyConsole installSpyConsole() {
		final PluginTool tool = plugin.getTool();
		runSwing(() -> {
			ConsoleService defaultConsole = tool.getService(ConsoleService.class);

			//@formatter:off
			invokeInstanceMethod(
				"removeService",
				tool,
				new Class[] { Class.class, Object.class },
				new Object[] { ConsoleService.class, defaultConsole });
			//@formatter:on
		});

		final AtomicReference<SpyConsole> ref = new AtomicReference<>();

		runSwing(() -> {
			final SpyConsole spyConsole = new SpyConsole();

			//@formatter:off
			invokeInstanceMethod(
				"addService",
				tool,
				new Class[] { Class.class, Object.class },
				new Object[] { ConsoleService.class, spyConsole });
			//@formatter:on

			ref.set(spyConsole);
		});

		return ref.get();
	}

	protected ResourceFile writeAbstractScriptContents(ResourceFile scriptFile,
			String scriptMessage) throws IOException {
		String filename = scriptFile.getName();
		String className = filename.replaceAll("\\.java", "");

		//@formatter:off
		String scriptContents =
				"import ghidra.app.script.GhidraScript;\n\n" +

		    "public abstract class "+className+" extends GhidraScript {\n\n" +

		    	"    @Override\n" +
		    	"    public void run() throws Exception {\n" +
		    	"        message();\n" +
		    	"    }\n\n" +

	    		"    public void message() {\n" +
	    		"        println(\""+ scriptMessage +"\");\n" +
	    		"    }\n" +
	    		"}\n\n";

		//@formatter:on

		writeStringToFile(scriptFile, scriptContents);

		setTimestampToTheFuture(scriptFile);

		return scriptFile;
	}

	protected ResourceFile writePackageScriptContents(ResourceFile scriptFile, String pkg)
			throws IOException {
		String filename = scriptFile.getName();
		String className = filename.replaceAll("\\.java", "");

		//@formatter:off
		String scriptContents =
				"package " + pkg + ";\n\n" +
						"import ghidra.app.script.GhidraScript;\n\n" +

		    "public abstract class "+className+" extends GhidraScript {\n\n" +

		    "    static public int counter = 0;\n\n" +

		    	"    @Override\n" +
		    	"    public void run() throws Exception {\n" +
		    	"        message();\n" +
		    	"    }\n\n" +

	    		"    public void message() {\n" +
	    		"        println(\"\" + counter++);\n" +
	    		"    }\n" +
	    		"}\n\n";
		//@formatter:on

		writeStringToFile(scriptFile, scriptContents);

		return scriptFile;
	}

	/**
	 * Unusual Code Alert!: the test runs faster than the writing of the class file
	 * and the File object's modified granularity is not low enough such that sometimes
	 * the code will not recompile a script that we have changed, as it will not do
	 * so if it thinks the file has not changed.
	 *
	 * @param file the file to update
	 */
	protected void setTimestampToTheFuture(ResourceFile file) {
		int magicFutureTimeAmount = 10000;// chosen via manual testing
		File f = file.getFile(false);
		boolean success = f.setLastModified(f.lastModified() + magicFutureTimeAmount);
		assertTrue("Could not update script 'lastModified' time", success);
	}

	protected void assertToolKeyBinding(KeyStroke ks) {
		String actionOwner = GhidraScriptMgrPlugin.class.getSimpleName();
		PluginTool tool = env.getTool();
		Set<DockingActionIf> actions = getActionsByOwner(tool, actionOwner);
		for (DockingActionIf action : actions) {
			KeyStroke keyBinding = action.getKeyBinding();
			if (keyBinding == null) {
				continue;
			}
			if (keyBinding.equals(ks)) {
				return;
			}
		}
		Assert.fail("keybinding not registered in the tool: " + ks);
	}

	protected ResourceFile createChildScript(ResourceFile parentScriptFile,
			String parentScriptPackage) throws IOException {
		ResourceFile newScriptFile = createTempScriptFile("ChildScript");
		String filename = newScriptFile.getName();
		String className = filename.replaceAll("\\.java", "");

		String parentScriptName = parentScriptFile.getName();
		String parentClassName = parentScriptName.replaceAll("\\.java", "");

		String importLine = (parentScriptPackage != null
				? ("import " + parentScriptPackage + "." + parentClassName + ";\n\n")
				: "");

		//@formatter:off
		String newScript =
				importLine +
				"public class "+className+" extends "+parentClassName+" {\n\n" +

		    	"    @Override\n" +
		    	"    public void run() throws Exception {\n" +
		    	"        // just call our parent\n" +
		    	"        message();\n" +
		    	"    }\n" +
		    	"}\n\n";
		//@formatter:on

		writeStringToFile(newScriptFile, newScript);

		return newScriptFile;
	}

	protected ResourceFile createInstanceFieldScript() throws Exception {
		return createScriptWithFields(false);
	}

	protected ResourceFile createStaticFieldScript() throws Exception {
		return createScriptWithFields(true);
	}

	protected ResourceFile createScriptWithFields(boolean staticFields) throws Exception {
		ResourceFile newScriptFile = createTempScriptFile("LocalVariableScript");
		String filename = newScriptFile.getName();
		String className = filename.replaceAll("\\.java", "");

		//@formatter:off
		String field = staticFields ?
				"public static int counter = 0;"           :
					"public int counter = 0;";

		String newScript =
				"import ghidra.app.script.GhidraScript;\n\n" +

		    "public class "+className+" extends GhidraScript {\n\n" +

				 field +

				 "    @Override\n" +
				 "    public void run() throws Exception {\n" +

		    	"        counter++;\n" +
		    	"        println(\"*\" + counter + \"*\");\n" +
		    	"    }\n" +
		    	"}\n\n";
		//@formatter:on

		writeStringToFile(newScriptFile, newScript);

		return newScriptFile;
	}

	protected ResourceFile createInnerClassScript() throws Exception {
		ResourceFile newScriptFile = createTempScriptFile();
		String filename = newScriptFile.getName();
		String className = filename.replaceAll("\\.java", "");

		//@formatter:off
		String newScript =
				"import ghidra.app.script.GhidraScript;\n\n" +

		    "public class "+className+" extends GhidraScript {\n\n" +

		    	"@Override\n" +
		    	"public void run() throws Exception {\n" +
		    	"    MyInnerClass mic = new MyInnerClass();\n" +
		    	"    println(mic.toString());\n\n" +

		    	"    MyExternalClass mec = new MyExternalClass();\n" +
		    	"    println(mec.toString());\n" +
		    	"}\n\n" +

    			"public class MyInnerClass {\n" +
    			"@Override\n" +
    			"public String toString() {\n" +
    			"return \"I am an inner class.\";\n" +
    			"}\n" +
    			"}\n" +
    			"}\n\n" +

			"class MyExternalClass {\n" +
			"@Override\n" +
			"public String toString() {\n" +
			"return \"I am an external class.\";\n" +
			"}\n" +
			"};\n";
		//@formatter:on

		writeStringToFile(newScriptFile, newScript);

		return newScriptFile;
	}

	protected void setScriptEditorContents(String scriptContents) {
		JTextComponent editTextComponent = grabScriptEditorTextArea();
		setText(editTextComponent, scriptContents);
	}

	protected JTextComponent grabScriptEditorTextArea() {
		GhidraScriptEditorComponentProvider scriptEditor = grabScriptEditor();
		JTextArea textArea = (JTextArea) findComponentByName(scriptEditor.getComponent(),
			GhidraScriptEditorComponentProvider.EDITOR_COMPONENT_NAME);
		assertNotNull(textArea);
		return textArea;
	}

	protected void assertAtAddress(long address) {
		assertEquals(program.getAddressFactory().getDefaultAddressSpace().getAddress(address),
			browser.getCurrentAddress());
	}

	protected void closeEditor() {
		GhidraScriptEditorComponentProvider scriptEditor = grabScriptEditor();
		runSwing(() -> scriptEditor.closeComponent());
		//runSwing(() -> editor.closeComponent());
	}

	protected GhidraScriptEditorComponentProvider grabScriptEditor() {

		AtomicReference<GhidraScriptEditorComponentProvider> ref = new AtomicReference<>();

		runSwing(() -> ref.set(provider.getEditor()));

		GhidraScriptEditorComponentProvider theEditor = ref.get();
		assertNotNull(theEditor);
		return theEditor;
	}

	protected void pressEditButton() {
		DockingActionIf editAction = getAction(plugin, "Edit");
		performAction(editAction, false);
		waitForSwing();
	}

	protected void assertScriptInTable(ResourceFile script) throws Exception {
		int row = getScriptTableRow(script);
		Assert.assertNotEquals("Script not found in script table", -1, row);
	}

	protected void assertScriptNotInTable(ResourceFile script) throws Exception {
		int scriptIndex = provider.getScriptIndex(script);
		assertEquals("Script found in script table; should not be there", -1, scriptIndex);
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	protected class TaskListenerFlag implements TrackedTaskListener {

		protected String taskName;
		volatile boolean ended;

		protected TaskListenerFlag(String taskName) {
			this.taskName = taskName;
		}

		@Override
		public void taskAdded(Task task) {
			Msg.trace(this, "taskAdded(): " + task.getTaskTitle());
		}

		@Override
		public void taskRemoved(Task task) {
			Msg.trace(this, "taskRemoved(): " + task.getTaskTitle());
			if (taskName.equals(task.getTaskTitle())) {
				ended = true;
			}
		}

		@Override
		public String toString() {
			return taskName;
		}
	}

	protected class TestChangeProgramScript extends GhidraScript {

		protected CountDownLatch startedLatch = new CountDownLatch(1);
		protected CountDownLatch doneLatch = new CountDownLatch(1);
		protected boolean testOver;

		@Override
		protected void run() throws Exception {

			Address addr = currentProgram.getAddressFactory().getAddress("10001000");
			createLabel(addr, "Test", true);

			startedLatch.countDown();// signal to the test that it can continue

			int total = 0;

			try {
				while (total < DEFAULT_WAIT_TIMEOUT) {
					monitor.checkCanceled();
					total += sleep(DEFAULT_WAIT_DELAY);

					if (testOver) {
						doneLatch.countDown();
						return;
					}
				}
			}
			catch (CancelledException e) {
				doneLatch.countDown();
				throw e;
			}

			doneLatch.countDown();
			throw new AssertException("Test script was never cancelled");
		}

		void testOver() {
			testOver = true;
		}

		boolean waitForStart() throws Exception {
			return startedLatch.await(TASK_RUN_SCRIPT_TIMEOUT_SECS, TimeUnit.SECONDS);
		}

		boolean waitForFinish() throws Exception {
			return doneLatch.await(TASK_RUN_SCRIPT_TIMEOUT_SECS, TimeUnit.SECONDS);
		}
	}

	protected class SpyConsole extends ConsoleComponentProvider {
		protected StringBuffer apiBuffer;

		protected StringWriter outBuffer = new StringWriter();
		protected StringWriter errBuffer = new StringWriter();
		protected PrintWriter out = new PrintWriter(outBuffer);
		protected PrintWriter err = new PrintWriter(errBuffer);

		SpyConsole() {
			super(plugin.getTool(), "Spy Console");
			this.apiBuffer = new StringBuffer();
		}

		@Override
		public PrintWriter getStdErr() {
			return err;
		}

		@Override
		public PrintWriter getStdOut() {
			return out;
		}

		void clear() {
			apiBuffer = new StringBuffer();
			outBuffer = new StringWriter();
			errBuffer = new StringWriter();
		}

		@Override
		public void println(String msg) {
			apiBuffer.append(msg).append('\n');
			Msg.trace(this, "Spy Script Console - println(): " + msg);
		}

		@Override
		public void addMessage(String originator, String msg) {
			apiBuffer.append(msg).append('\n');
			Msg.trace(this, "Spy Script Console - addMessage(): " + msg);
		}

		String getApiOutput() {
			return apiBuffer.toString();
		}
	}

	protected void makeFunctionAt(String addr) throws MemoryAccessException {
		builder.addBytesNOP(addr, 0x10);
		builder.disassemble(addr, 0x10, true);
		builder.createFunction(addr);
	}
}
