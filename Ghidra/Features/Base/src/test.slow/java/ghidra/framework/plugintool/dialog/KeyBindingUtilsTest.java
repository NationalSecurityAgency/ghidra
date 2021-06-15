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
package ghidra.framework.plugintool.dialog;

import static org.junit.Assert.*;

import java.awt.Rectangle;
import java.awt.Window;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.io.*;
import java.util.*;

import javax.swing.*;
import javax.swing.table.TableModel;
import javax.swing.tree.TreePath;

import org.junit.*;

import docking.action.DockingActionIf;
import docking.actions.KeyBindingUtils;
import docking.options.editor.OptionsDialog;
import docking.options.editor.OptionsPanel;
import docking.tool.ToolConstants;
import docking.tool.util.DockingToolConstants;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import generic.io.NullWriter;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.data.DataPlugin;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.plugin.core.function.FunctionPlugin;
import ghidra.app.plugin.core.memory.MemoryMapPlugin;
import ghidra.app.plugin.core.navigation.GoToAddressLabelPlugin;
import ghidra.app.plugin.core.navigation.NavigationHistoryPlugin;
import ghidra.framework.model.ToolServices;
import ghidra.framework.options.Options;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.mgr.OptionsManager;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;

/**
 * Tests the {@link KeyBindingUtils} class.
 *
 * 
 * @since  Tracker Id 329
 */
public class KeyBindingUtilsTest extends AbstractGhidraHeadedIntegrationTest {

	private static final String TEST_FILENAME =
		"KeyBindingUtilsTest_Test_Filename" + KeyBindingUtils.PREFERENCES_FILE_EXTENSION;

	private Writer debug = new NullWriter();

	private PluginTool tool;
	private TestEnv env;

	private KeyBindingsPanel panel;
	private JTable table;
	private TableModel model;
	private JTextField keyField;
	private JButton applyButton;

	@Before
	public void setUp() throws Exception {

//		this hasn't been crashing for a while now
//		File dir = getDebugFileDirectory();
//		File file = new File(dir, testName.getMethodName() + ".txt")
//		Msg.debug(this, "Writing debug data to: " + file);
//		debug = new FileWriter(file);

		// debug to the local console
//		debug = new PrintWriter(System.out);

		setUpTool();
	}

	private void setUpTool() throws Exception {
		debug("setUp()");

		env = new TestEnv();

		debug("one");

		tool = env.getTool();

		// add some plugins so that we have key bindings to work with
		tool.addPlugin(NavigationHistoryPlugin.class.getName());
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		tool.addPlugin(MemoryMapPlugin.class.getName());
		tool.addPlugin(GoToAddressLabelPlugin.class.getName());
		tool.addPlugin(DataTypeManagerPlugin.class.getName());
		tool.addPlugin(DataPlugin.class.getName());
		tool.addPlugin(FunctionPlugin.class.getName());

		env.showTool();

		debug("two");
	}

	private void debug(String message) {
		if (debug == null) {
			return;
		}

		try {
			debug.write(message + "\n");
			debug.flush();
		}
		catch (IOException e) {
			Msg.debug(this, "Error writing to debug file", e);
		}
	}

	@After
	public void tearDown() throws Exception {
		debug("tearDown()");
		env.dispose();
		debug("a");

		debug.close();
	}

	@Test
	public void testParseKeyStroke() {

		KeyStroke ks = KeyStroke.getKeyStroke(KeyEvent.VK_V, 0);
		String parsed = KeyBindingUtils.parseKeyStroke(ks);
		assertEquals("V", parsed);

		ks = KeyStroke.getKeyStroke('v');
		parsed = KeyBindingUtils.parseKeyStroke(ks);
		assertEquals("v", parsed);

		int modifiers = InputEvent.SHIFT_DOWN_MASK | InputEvent.CTRL_DOWN_MASK;
		ks = KeyStroke.getKeyStroke(KeyEvent.VK_V, modifiers);
		parsed = KeyBindingUtils.parseKeyStroke(ks);
		assertEquals("Ctrl-Shift-V", parsed);

		ks = KeyStroke.getKeyStroke(KeyEvent.VK_V, modifiers, true);
		parsed = KeyBindingUtils.parseKeyStroke(ks);
		assertEquals("Ctrl-Shift-V", parsed);

		JButton b = new JButton();
		KeyEvent event = new KeyEvent(b, KeyEvent.KEY_PRESSED, 1, modifiers, KeyEvent.VK_V, 'v');
		ks = KeyStroke.getKeyStrokeForEvent(event);
		parsed = KeyBindingUtils.parseKeyStroke(ks);
		assertEquals("Ctrl-Shift-V", parsed);
	}

	/*
	 * Test method for 'ghidra.framework.plugintool.dialog.KeyBindingUtils.importKeyBindings(PluginTool)'
	 */
	@Test
	public void testExportImportKeyBindings() throws Exception {
		debug("testExportImportKeyBindings()");
		ToolOptions defaultKeyBindings = tool.getOptions(DockingToolConstants.KEY_BINDINGS);

		debug("a");

		// export the key bindings and read them back in to verify that they
		// remain the same
		File exportedFile = exportOptions(defaultKeyBindings);

		debug("b");

		ToolOptions importedOptions = importOptions(exportedFile);

		debug("c");

		// compare the options
		assertOptionsMatch("The two Options objects do not have the same contents.",
			defaultKeyBindings, importedOptions);

		debug("d");

		// now repeat the above test with changing some values before writing out
		invokeInstanceMethod("putObject", defaultKeyBindings,
			new Class[] { String.class, Object.class },
			new Object[] { "TestAction1 (Owner1)", KeyStroke.getKeyStroke(65, 0) });
		invokeInstanceMethod("putObject", defaultKeyBindings,
			new Class[] { String.class, Object.class },
			new Object[] { "TestAction2 (Owner 2)", KeyStroke.getKeyStroke(66, 0) });

		debug("e");

		assertOptionsDontMatch("Two different Options objects have compared to be the same.",
			defaultKeyBindings, importedOptions);

		debug("f");

		exportedFile = exportOptions(defaultKeyBindings);

		debug("g");

		importedOptions = importOptions(exportedFile);

		debug("h");

		assertOptionsMatch("The two Options objects do not have the same contents.",
			defaultKeyBindings, importedOptions);

		debug("i");

		// delete the test file
		exportedFile.delete();

		debug("j");
	}

	@Test
	public void testImportExportWithGUI() throws Exception {

		setKeyBindingsUpDialog();

		debug("a");

		// get current options
		ToolOptions toolKeyBindingOptions = (ToolOptions) getInstanceField("options", panel);

		debug("b");

		// save and reload them to make sure they are the same
		File saveFile = exportOptions(toolKeyBindingOptions);
		ToolOptions originalOptions = importOptions(saveFile);

		assertOptionsMatch(
			"The Options objects do not contain different data after changes have been made.",
			toolKeyBindingOptions, originalOptions);

		debug("c");

		// make some changes using the options dialog
		setKeyBinding("x", KeyEvent.VK_X);

		debug("d");

		// verify the changes are different than the original values
		assertOptionsDontMatch(
			"The Options objects do not contain different data after changes have been made.",
			toolKeyBindingOptions, originalOptions);

		debug("e");

		// import the original values file through the tool
		importOptionsWithGUI(saveFile, true);
		// get the updated values that have not been applied
		Map<String, KeyStroke> keyStrokeMap = panel.getKeyStrokeMap();

		debug("f");

		// verify the data is the same as it was before the changes
		boolean same = compareOptionsWithKeyStrokeMap(originalOptions, keyStrokeMap);
		assertTrue("The Options object contains different data than was imported.", same);

		debug("g");

		// close the tool *without* applying the changes
		closeAllWindows();
		env.dispose();

		debug("h");

		saveFile.delete();

		// reload the tool and make sure the values are those of the changes
		// *before* the last import
		setUp();
		setKeyBindingsUpDialog();

		debug("i");

		ToolOptions newlyLoadedDefaultOptions = (ToolOptions) getInstanceField("options", panel);
		assertOptionsMatch(
			"The options from the first tool instance have changed " +
				"in the second tool instance even though the testing changes were not applied.",
			originalOptions, newlyLoadedDefaultOptions);

		debug("j");

		// now push the changes through again, applying the changes this time
		// to make sure that nothing unexpected happens
		setKeyBinding("y", KeyEvent.VK_Y);

		debug("k");

		saveFile = exportOptions(newlyLoadedDefaultOptions);

		debug("l");

		importOptionsWithGUI(saveFile, true);

		debug("m");

		// apply the changes to the system and close the tool
		runSwing(() -> applyButton.doClick());

		debug("n");

		saveFile.delete();

		// reload the tool and make sure the values are those of the changes
		// *after* the last import
		// reload with our saved tool
		saveAndCloseTool();
		reopenTool(tool);

		debug("p");

		setKeyBindingsUpDialog(tool);

		newlyLoadedDefaultOptions = (ToolOptions) getInstanceField("options", panel);
		assertOptionsDontMatch(
			"The options are the same after making changes, applying, closing and reloading.",
			originalOptions, newlyLoadedDefaultOptions);

		debug("q");
		closeAllWindows();
	}

	@Test
	public void testSharedKeyBindingGetsRestoredWhenToolIsRestarted() throws Exception {

		setKeyBindingsUpDialog();

		// this action is known to be a 'Shared' action
		// Remove Items  (Shared)
		String actionName = "Remove Items";
		DockingActionIf action = getAction(tool, ToolConstants.SHARED_OWNER, actionName);
		assertNotNull(action);
		KeyStroke defaultBinding = action.getKeyBinding();
		KeyStroke newBinding = KeyStroke.getKeyStroke(KeyEvent.VK_X, 0);
		assertNotEquals(defaultBinding, newBinding);
		setKeyBinding(action, "x", newBinding.getKeyCode());

		KeyStroke appliedBinding = action.getKeyBinding();
		assertEquals(newBinding, appliedBinding);

		// reload the tool and make sure the values are those of the changes get restored
		saveAndCloseTool();

		reopenTool(tool);

		KeyStroke restoredBinding = action.getKeyBinding();
		assertEquals(newBinding, restoredBinding);

		setKeyBindingsUpDialog(tool);
		ToolOptions options = (ToolOptions) getInstanceField("options", panel);
		KeyStroke optionBinding = options.getKeyStroke(action.getFullName(), null);
		assertEquals(appliedBinding, optionBinding);

		closeAllWindows();
	}

//==================================================================================================
// Private Methods
//==================================================================================================	

	private void reopenTool(PluginTool tool2) {
		runSwing(() -> {
			ToolServices services = tool.getProject().getToolServices();
			tool = services.launchTool(tool.getName(), null);
		});
		assertNotNull(tool);
	}

	private void saveAndCloseTool() {
		runSwing(() -> {
			ToolServices services = tool.getProject().getToolServices();
			services.saveTool(tool);
		});
		env.closeTool(tool);
	}

	private void setKeyBindingsUpDialog() throws Exception {
		env.showTool();
		setKeyBindingsUpDialog(tool);
	}

	private void setKeyBindingsUpDialog(PluginTool pluginTool) throws Exception {
		debug("setUpDialog()");
		debug("aa");

		final OptionsManager optionsManager =
			(OptionsManager) getInstanceField("optionsMgr", pluginTool);

		debug("bb");
		executeOnSwingWithoutBlocking(() -> {
			debug("bb - thread");
			optionsManager.editOptions();
		});

		debug("cc");

		OptionsDialog optionsDialog =
			(OptionsDialog) getInstanceField("optionsDialog", optionsManager);
		OptionsPanel optionsPanel = (OptionsPanel) getInstanceField("panel", optionsDialog);
		applyButton = findButtonByText(optionsDialog, "Apply");

		debug("dd");

		// this is an instance of OptionsNode
		GTree tree = (GTree) getInstanceField("gTree", optionsPanel);
		Object keyBindingsNode = getGTreeNode(tree.getModelRoot(), "Key Bindings");
		selectNode(tree, keyBindingsNode);

		debug("ee");

		// setup our test variables
		panel = (KeyBindingsPanel) getEditorPanel(keyBindingsNode, optionsDialog);
		table = findComponent(panel, JTable.class);
		keyField = (JTextField) getInstanceField("ksField", panel);
		model = table.getModel();

		debug("ff");
	}

	private Object getEditorPanel(Object testNode, OptionsDialog dialog) {
		Object localOptionsPanel = getInstanceField("panel", dialog);
		Map<?, ?> map = (Map<?, ?>) getInstanceField("editorMap", localOptionsPanel);
		Object editor = map.get(testNode);
		return getInstanceField("panel", editor);

	}

	private void selectNode(GTree tree, Object node) throws Exception {
		debug("selectNode");
		waitForTree(tree);

		debug("\tafter wait for tree");
		TreePath path = (TreePath) invokeInstanceMethod("getTreePath", node);
		setSelectionPath(tree, path);
		debug("\tafter setSelectionPath");
		waitForSwing();
		debug("\tafter waiting for update manager");
		waitForTree(tree);
		debug("\tafter wait for tree");
	}

	private void setSelectionPath(final GTree tree, final TreePath path) throws Exception {
		SwingUtilities.invokeAndWait(() -> tree.setSelectionPath(path));
	}

	private GTreeNode getGTreeNode(GTreeNode parent, String nodeName) throws Exception {
		if (!parent.isLoaded()) {
			return null;
		}

		List<GTreeNode> children = parent.getChildren();
		for (GTreeNode rootChild : children) {
			String name = (String) invokeInstanceMethod("getName", rootChild);
			if (nodeName.equals(name)) {
				return rootChild;
			}
			GTreeNode foundNode = getGTreeNode(rootChild, nodeName);
			if (foundNode != null) {
				return foundNode;
			}
		}
		return null;
	}

	private void setKeyBinding(String keyText, int keyCode) throws Exception {
		Set<DockingActionIf> list = tool.getAllActions();
		DockingActionIf arbitraryAction = null;
		for (DockingActionIf action : list) {
			if (action.getKeyBindingType().isManaged() && action.getKeyBinding() == null) {
				arbitraryAction = action;
				break;
			}
		}

		assertNotNull("Unable to find an action for which to set a key binding", arbitraryAction);
		setKeyBinding(arbitraryAction, keyText, keyCode);
	}

	private void setKeyBinding(DockingActionIf action, String keyText, int keyCode)
			throws Exception {

		selectRowForAction(action);
		triggerText(keyField, keyText);

		assertEquals(keyText.toUpperCase(), keyField.getText());

		runSwing(() -> panel.apply());

		if (!Objects.equals(KeyStroke.getKeyStroke(keyCode, 0), action.getKeyBinding())) {

			Msg.debug(this, "Action did not take keybinding: " + action.getFullName());

			assertEquals("Key binding was not applied", KeyStroke.getKeyStroke(keyCode, 0),
				action.getKeyBinding());
		}
	}

	private void selectRowForAction(DockingActionIf action) throws Exception {
		String actionName = action.getName();
		String owner = action.getOwnerDescription();

		for (int i = 0; i < model.getRowCount(); i++) {
			if (actionName.equals(model.getValueAt(i, 0)) &&
				owner.equals(model.getValueAt(i, 2))) {
				final int idx = i;
				SwingUtilities.invokeAndWait(() -> {
					table.setRowSelectionInterval(idx, idx);
					Rectangle rect = table.getCellRect(idx, idx, true);
					table.scrollRectToVisible(rect);
				});
				return;
			}
		}
		Assert.fail("Could not find action in table: " + actionName);
	}

	// this file cannot return an Options object, as the other method does,
	// because it does not have access to that object (the utils class is
	// called directly by the key bindings panel and this class thus does not
	// have access)
	private void importOptionsWithGUI(File importFile, boolean applyChanges) throws Exception {
		// click the button in a separate thread because it can trigger another
		// modal dialog.
		JButton button = findButtonByText(panel, "Import...");
		assertNotNull(button);
		runSwing(() -> pressButton(button), false);

		// if the apply changes dialog appeared, the close it
		closeWarningDialog(applyChanges);

		// this call will give the import file to the file chooser that is
		// shown
		findAndTestFileChooser(importFile.getParentFile(), importFile.getName());

		// give a chance for the work to be done by the swing thread
		waitForPostedSwingRunnables();
	}

	private void closeWarningDialog(boolean proceed) {
		Window window = waitForWindowByTitleContaining("Continue");
		assertNotNull(window);

		String button = proceed ? "Yes" : "No";
		pressButtonByText(window, button);
	}

	private ToolOptions importOptions(File importFile) throws Exception {
		// create a runnable from which we will later extract the created
		// options
		ImportRunnable importRunnable = new ImportRunnable();
		executeOnSwingWithoutBlocking(importRunnable);

		findAndTestFileChooser(importFile.getParentFile(), importFile.getName());

		return importRunnable.getOptions();
	}

	private File exportOptions(final ToolOptions options) throws Exception {
		// export the data, which causes a file chooser to be shown
		executeOnSwingWithoutBlocking(() -> KeyBindingUtils.exportKeyBindings(options));

		File selectedFile = findAndTestFileChooser(null, TEST_FILENAME);

		return selectedFile;
	}

	// locates the open file chooser and verifies its state
	private File findAndTestFileChooser(File path, String filename) throws Exception {
		// get the file chooser and set the file it will use
		GhidraFileChooser fileChooser = waitForDialogComponent(GhidraFileChooser.class);
		if (fileChooser == null) {
			Msg.debug(this, "Couldn't find file chooser");
			printOpenWindows();
			Assert.fail("Did not get the expected GhidraFileChooser");
		}

		// change directories
		if (path != null) {
			fileChooser.setCurrentDirectory(path);
		}
		waitForUpdateOnChooser(fileChooser);

		File currentDirectory = fileChooser.getCurrentDirectory();
		File fileToSelect = new File(currentDirectory, filename);
		fileChooser.setSelectedFile(fileToSelect);
		waitForUpdateOnChooser(fileChooser);

		// press OK on the file chooser
		final JButton okButton = (JButton) getInstanceField("okButton", fileChooser);

		runSwing(() -> okButton.doClick());

		// wait to make sure that there is enough time to write the data
		waitForPostedSwingRunnables();

		// make sure that the file was created or already existed
		File selectedFile = fileChooser.getSelectedFile(false);
		assertTrue("The test file was not created after exporting.", selectedFile.exists());

		return selectedFile;
	}

	// compares the provided options with the mapping of property names to
	// keystrokes (the map is obtained from the key bindings panel after an
	// import is done).
	private boolean compareOptionsWithKeyStrokeMap(Options oldOptions,
			Map<String, KeyStroke> panelKeyStrokeMap) {
		List<String> propertyNames = oldOptions.getOptionNames();
		for (String name : propertyNames) {

			boolean match = panelKeyStrokeMap.containsKey(name);
			KeyStroke optionsKs = oldOptions.getKeyStroke(name, null);
			KeyStroke panelKs = panelKeyStrokeMap.get(name);

			// if the value is null, then it would not have been placed into the options map 
			// in the key bindings panel, so we only care about non-null values
			if (optionsKs != null) {
				match &= (optionsKs.equals(panelKs));
			}
			else {
				match = true;
			}

			// short-circuit if there are any data that don't match
			if (!match) {
				return false;
			}
		}

		return true;
	}

	private void assertOptionsMatch(String message, ToolOptions options1, ToolOptions options2) {

		List<String> propertyNames = getOptionsNamesWithValues(options1);
		List<String> otherPropertyNames = getOptionsNamesWithValues(options2);

		assertEquals("Options have different number of properties", propertyNames.size(),
			otherPropertyNames.size());

		for (String propertyName : propertyNames) {
			boolean match = options2.contains(propertyName);

			Object value = options1.getObject(propertyName, null);
			Object value2 = options2.getObject(propertyName, null);
			match &= SystemUtilities.isEqual(value, value2);

			// short-circuit if there are any data that don't match
			if (!match) {
				System.err.println("Found non-matching option: propertyName " + propertyName +
					", value 1 = " + value + ", value 2 = " + value2);
				Assert.fail(message);
			}
		}
	}

	private void assertOptionsDontMatch(String message, ToolOptions options1,
			ToolOptions options2) {

		List<String> propertyNames = getOptionsNamesWithValues(options1);
		List<String> otherPropertyNames = getOptionsNamesWithValues(options2);
		if (propertyNames.size() != otherPropertyNames.size()) {
			return;
		}

		for (String propertyName : propertyNames) {
			boolean match = options2.contains(propertyName);

			Object value = options1.getObject(propertyName, null);
			Object value2 = options2.getObject(propertyName, null);

			match &= SystemUtilities.isEqual(value, value2);

			// short-circuit if there are any data that don't match
			if (!match) {
				return;
			}
		}

		Assert.fail(message);
	}

	private List<String> getOptionsNamesWithValues(Options options) {
		List<String> namesWithValues = new ArrayList<>();
		List<String> optionNames = options.getOptionNames();
		for (String string : optionNames) {
			if (options.getObject(string, null) != null) {
				namesWithValues.add(string);
			}
		}
		return namesWithValues;
	}

	// class to call KeyBindingUtils.importKeyBindings() and to store the
	// return value
	class ImportRunnable implements Runnable {
		ToolOptions importedOptions;
		boolean optionsImported;

		@Override
		public void run() {
			importedOptions = KeyBindingUtils.importKeyBindings();
			optionsImported = true;
		}

		public ToolOptions getOptions() {
			// don't return until we've imported our data
			while (!optionsImported) {
				try {
					Thread.sleep(100);
				}
				catch (Exception e) {
					// don't care, try again
				}
			}
			return importedOptions;
		}
	}
}
