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
package ghidra.util.bean.opteditor;

import static org.junit.Assert.*;

import java.awt.*;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.beans.PropertyEditor;
import java.io.*;
import java.util.*;
import java.util.List;

import javax.swing.*;
import javax.swing.text.JTextComponent;
import javax.swing.tree.TreeModel;
import javax.swing.tree.TreePath;

import org.apache.commons.lang3.StringUtils;
import org.junit.*;

import docking.action.DockingActionIf;
import docking.actions.KeyBindingUtils;
import docking.options.editor.*;
import docking.tool.ToolConstants;
import docking.widgets.MultiLineLabel;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.table.RowObjectFilterModel;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import generic.test.TestUtils;
import ghidra.GhidraOptions;
import ghidra.app.plugin.core.console.ConsolePlugin;
import ghidra.app.util.viewer.options.OptionsGui;
import ghidra.app.util.viewer.options.ScreenElement;
import ghidra.framework.main.ConsoleTextPane;
import ghidra.framework.options.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.dialog.KeyBindingsPanel;
import ghidra.framework.preferences.Preferences;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;

/**
 * Tests for the options dialog.
 */
public class OptionsDialogTest extends AbstractGhidraHeadedIntegrationTest {

	private static final String MY_PATH_NAME_OPTION_NAME = "My PathName";
	private static final String TOOL_NODE_NAME = "Tool";
	private PluginTool tool;
	private TestEnv env;
	private OptionsDialog dialog;
	private JTree tree;
	private TreeModel treeModel;
	private JPanel defaultPanel;
	private JPanel viewPanel;
	private OptionsPanel optionsPanel;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.launchDefaultTool();
		configure();
	}

	private void configure() throws Exception {
		Preferences.setProperty(Preferences.PROJECT_DIRECTORY, null);
		setUpDialog(tool);
	}

	@After
	public void tearDown() throws Exception {
		runSwing(() -> dialog.close());
		env.dispose();
	}

	@Test
	public void testShowOptionPanel() {
		assertTrue(defaultPanel.isShowing());
		MultiLineLabel label = (MultiLineLabel) findComponentByName(viewPanel, "DefaultInfo");
		assertNotNull(label);
		String str = "To change Options, select a Folder or Option Group from the\n" +
			"Options Tree and change the Option settings.";
		assertEquals(str, label.getLabel());

		assertNotNull(findButtonByText(dialog, "OK"));
		assertNotNull(findButtonByText(dialog, "Cancel"));
		assertNotNull(findButtonByText(dialog, "Apply"));

	}

	@Test
	public void testListingOptions() throws Exception {

		Object browserDisplayNode =
			getGTreeNode(treeModel.getRoot(), GhidraOptions.CATEGORY_BROWSER_DISPLAY);
		selectNode(browserDisplayNode);

		// get the options panel
		OptionsGui optionsGui = findComponent(optionsPanel, OptionsGui.class);

		assertNotNull(optionsGui);
		assertTrue(optionsGui.isShowing());

		// get the current color option
		Color addressFieldColor = getAddressFieldColor(optionsGui);

		selectAddressEntryInScreenElementOptionsList(optionsGui);

		Color newColor = new Color(255, addressFieldColor.getGreen(), addressFieldColor.getBlue());
		setAddressColorValueInOptionsGUI(optionsGui, newColor);

		// close the options
		final JButton okButton = findButtonByText(dialog.getComponent(), "OK");
		assertTrue(okButton.isEnabled());
		runSwing(() -> okButton.getActionListeners()[0].actionPerformed(null));

		assertTrue(!dialog.isShowing());

		// see if the color has taken effect
		Color newAddressFieldColor = getAddressFieldColor(optionsGui);
		assertEquals(newColor, newAddressFieldColor);
	}

	@Test
	public void testOptionsSavingFromDefaultTool_for_SCR_3964() throws Exception {
		// show a tool
		// edit the options
		// save the tool
		// close the tool
		// reshow the tool
		// verify the options were reloaded

		// get the current value of the option
		ConsolePlugin plugin = env.getPlugin(ConsolePlugin.class);
		Object provider = getInstanceField("provider", plugin);
		ConsoleTextPane textPane = (ConsoleTextPane) getInstanceField("textPane", provider);
		Integer charLimit = (Integer) getInstanceField("maximumCharacterLimit", textPane);

		// change the options
		// find and select the node for the console plugin's options
		Object consoleNode = getGTreeNode(treeModel.getRoot(), "Console");
		selectNode(consoleNode);

		// get the options panel
		ScrollableOptionsEditor simpleOptionsPanel =
			(ScrollableOptionsEditor) getEditorPanel(consoleNode);
		assertNotNull(simpleOptionsPanel);
		assertTrue(simpleOptionsPanel.isShowing());

		String optionName = (String) getInstanceField("MAXIMUM_CHARACTERS_OPTION_NAME", textPane);
		final Component component = findPairedComponent(simpleOptionsPanel, optionName);
		assertNotNull(component);

		// click the option to toggle its state
		final Integer updateCharLimit = charLimit + 100;
		runSwing(() -> ((JTextComponent) component).setText(updateCharLimit.toString()));

		waitForSwing();

		// close the options
		final JButton okButton = findButtonByText(dialog.getComponent(), "OK");
		assertTrue(okButton.isEnabled());
		runSwing(() -> okButton.getActionListeners()[0].actionPerformed(null));

		assertTrue(!dialog.isShowing());

		// save the tool and program
		String toolName = "OptionsTestTool";
		tool.setToolName(toolName);
		tool = saveTool(env.getProject(), tool);

		// close and re-open the tool
		env.closeTool(tool);
		tool = null;

		tool = env.launchTool(toolName, null);
		configure();

		plugin = getPlugin(tool, ConsolePlugin.class);
		provider = getInstanceField("provider", plugin);
		textPane = (ConsoleTextPane) getInstanceField("textPane", provider);
		Integer savedCharLimit = (Integer) getInstanceField("maximumCharacterLimit", textPane);

		// verify the changes
		assertEquals("The set options were not saved and reloaded", updateCharLimit,
			savedCharLimit);
	}

	@Test
	public void testSelectRootNode() throws Exception {
		selectNode(treeModel.getRoot());
		assertTrue(defaultPanel.isShowing());
	}

	@Test
	public void testShowMultiLevelOptions() throws Exception {
		GTreeNode browserNode =
			getGTreeNode(treeModel.getRoot(), GhidraOptions.CATEGORY_BROWSER_FIELDS);
		selectNode(browserNode);

		Options options = tool.getOptions(GhidraOptions.CATEGORY_BROWSER_FIELDS);
		List<String> optNames = options.getOptionNames();
		Collections.sort(optNames);
		for (String simpleName : optNames) {
			String[] nodeNames = extractNames(simpleName);
			if (nodeNames.length == 0) {
				continue;
			}

			GTreeNode parentNode = browserNode;
			for (String nodeName : nodeNames) {
				GTreeNode node = getGTreeNode(parentNode, nodeName);
				assertNotNull(node);
				parentNode = node;
			}
			selectNode(parentNode);
			int pos = simpleName.lastIndexOf(Options.DELIMITER);
			if (pos > 0) {
				simpleName = simpleName.substring(pos + 1);
			}
			// skip options that are "not simple", i.e. have custom editors
			if (simpleName.equals("Display Namespace") ||
				simpleName.equals("Array Display Options") ||
				simpleName.equals("Address Display Options")) {
				continue;
			}

			ScrollableOptionsEditor editor = (ScrollableOptionsEditor) getEditorPanel(parentNode);

			assertNotNull("Did not find options editor for name: " + simpleName, editor);
			assertNotNull("simpleName = " + simpleName, findPairedComponent(editor, simpleName));
		}
	}

	@Test
	public void testShowMultiLevelOptions2() throws Exception {

		Object root = treeModel.getRoot();
		Object toolNode = getGTreeNode(root, TOOL_NODE_NAME);

		Options options = tool.getOptions(ToolConstants.TOOL_OPTIONS);
		List<String> optNames = options.getOptionNames();
		Collections.sort(optNames);
		for (String simpleName : optNames) {
			String[] nodeNames = extractNames(simpleName);
			Object parent = toolNode;
			for (String element : nodeNames) {
				Object node = getGTreeNode(parent, element);
				assertNotNull(node);
				parent = node;
			}
			selectNode(parent);

			int pos = simpleName.lastIndexOf(Options.DELIMITER);
			if (pos > 0) {
				simpleName = simpleName.substring(pos + 1);
			}
			ScrollableOptionsEditor p = (ScrollableOptionsEditor) getEditorPanel(parent);
			assertNotNull(p);
			assertNotNull(findPairedComponent(p, simpleName));
		}
	}

	@Test
	public void testFileChooserEditor() throws Exception {

		ScrollableOptionsEditor editor = showOptions(ToolConstants.TOOL_OPTIONS);

		pressBrowseButton(editor, MY_PATH_NAME_OPTION_NAME);

		GhidraFileChooser chooser = waitForDialogComponent(GhidraFileChooser.class);
		assertNotNull(chooser);
		assertEquals("Choose Path", chooser.getTitle());

		File file = createTempFile("MyFile.txt");
		file.deleteOnExit();
		writeTempFile(file.getAbsolutePath());
		runSwing(() -> chooser.setSelectedFile(file));
		waitForUpdateOnChooser(chooser);

		JButton openButton = findButtonByText(chooser, "Choose Path");
		pressButton(openButton);
		waitForSwing();

		JTextField pathField = getEditorTextField(editor, MY_PATH_NAME_OPTION_NAME);
		assertEquals(file.getAbsolutePath(), pathField.getText());
	}

	@Test
	public void testFileChooserEditor_ClearValue() throws Exception {

		ScrollableOptionsEditor editor = showOptions(ToolConstants.TOOL_OPTIONS);
		JTextField pathField = getEditorTextField(editor, MY_PATH_NAME_OPTION_NAME);

		setText(pathField, "");

		pressOptionsOk();

		showOptionsDialog(tool);
		editor = showOptions(ToolConstants.TOOL_OPTIONS);
		pathField = getEditorTextField(editor, MY_PATH_NAME_OPTION_NAME);
		assertEquals("", pathField.getText());
	}

	@Test
	public void testColorEditor() throws Exception {

		// test double click on color panel
		// verify the color editor is displayed
		Object root = treeModel.getRoot();
		Object toolNode = getGTreeNode(root, TOOL_NODE_NAME);
		selectNode(toolNode);
		assertTrue(!defaultPanel.isShowing());

		ScrollableOptionsEditor simpleOptionsPanel =
			(ScrollableOptionsEditor) getEditorPanel(toolNode);
		assertNotNull(simpleOptionsPanel);
		assertTrue(simpleOptionsPanel.isShowing());

		Component component = findPairedComponent(simpleOptionsPanel, "Favorite Color");
		assertNotNull(component);
		Rectangle rect = component.getBounds();
		clickMouse(component, 1, rect.x, rect.y, 2, 0);

		waitForSwing();

		Window window = waitForWindow("Color Editor");
		assertNotNull(window);

		JColorChooser chooser = findComponent(window, JColorChooser.class);
		assertNotNull(chooser);
		chooser.setColor(Color.BLUE);
		PropertyEditor editor = getPropertyEditorForProperty(simpleOptionsPanel, "Favorite Color");

		JButton okButton = findButtonByText(window, "OK");
		assertNotNull(okButton);
		pressButton(okButton);
		assertEquals(Color.BLUE, editor.getValue());
	}

	@Test
	public void testPropertySelectorEditor() throws Exception {
		Object root = treeModel.getRoot();
		Object toolNode = getGTreeNode(root, TOOL_NODE_NAME);
		assertTrue(defaultPanel.isShowing());

		Object buttonNode = getGTreeNode(toolNode, "Mouse Buttons");
		selectNode(buttonNode);

		ScrollableOptionsEditor simpleOptionsPanel =
			(ScrollableOptionsEditor) getEditorPanel(buttonNode);
		assertNotNull(simpleOptionsPanel);
		assertTrue(simpleOptionsPanel.isShowing());

		PropertySelector ps =
			(PropertySelector) findPairedComponent(simpleOptionsPanel, "Mouse Button To Activate");
		assertNotNull(ps);
		runSwing(() -> ps.setSelectedIndex(0));
		assertEquals("LEFT", ps.getSelectedItem());
	}

	@Test
	public void testRestoreDefaultsFromGUIBeforeApply_SCR_8471() throws Exception {
		String originalValue = getCurrentTextFieldEditorValue("Console", "Character Limit");

		int oldValue = Integer.parseInt(originalValue);
		String newValue = Integer.toString(oldValue + 100);
		setCurrentTextFieldEditorValue("Console", "Character Limit", newValue);

		restoreDefaults();

		String currentValue = getCurrentTextFieldEditorValue("Console", "Character Limit");
		assertEquals("Option not restored after a call to restore defaults", originalValue,
			currentValue);
	}

	@Test
	public void testRestoreDefaultsFromGUIAfterApply_SCR_8471() throws Exception {
		String originalValue = getCurrentTextFieldEditorValue("Console", "Character Limit");

		int oldValue = Integer.parseInt(originalValue);
		String newValue = Integer.toString(oldValue + 100);
		setCurrentTextFieldEditorValue("Console", "Character Limit", newValue);

		apply();

		restoreDefaults();

		String currentValue = getCurrentTextFieldEditorValue("Console", "Character Limit");
		assertEquals("Option not restored after a call to restore defaults", originalValue,
			currentValue);
	}

	@Test
	public void testRestoreDefaultsForKeybindings() throws Exception {
		String actionName = "Clear Cut";
		String pluginName = "DataTypeManagerPlugin";
		KeyStroke defaultKeyStroke = getKeyBinding(actionName);
		assertOptionsKeyStroke(actionName, pluginName, defaultKeyStroke);

		int keyCode = KeyEvent.VK_Q;
		int modifiers = InputEvent.CTRL_DOWN_MASK | InputEvent.ALT_DOWN_MASK;
		KeyStroke newKeyStroke = setKeyBinding(actionName, modifiers, keyCode, 'Q');

		apply();
		assertOptionsKeyStroke(actionName, pluginName, newKeyStroke);

		restoreDefaults();

		KeyStroke currentBinding = getKeyBinding(actionName);
		assertEquals("Key binding not restored after a call to restore defautls", defaultKeyStroke,
			currentBinding);
		assertOptionsKeyStroke(actionName, pluginName, defaultKeyStroke);
	}

	@Test
	public void testRestoreDefaultsForFrontEndKeybindings() throws Exception {
		runSwing(() -> dialog.close());

		setUpDialog(env.getFrontEndTool());

		String actionName = "Archive Project";
		String pluginName = "ArchivePlugin";
		KeyStroke defaultKeyStroke = getKeyBinding(actionName);
		assertOptionsKeyStroke(actionName, pluginName, defaultKeyStroke);

		int keyCode = KeyEvent.VK_Q;
		int modifiers = InputEvent.CTRL_DOWN_MASK | InputEvent.ALT_DOWN_MASK;
		KeyStroke newKeyStroke = setKeyBinding(actionName, modifiers, keyCode, 'Q');

		apply();
		assertOptionsKeyStroke(actionName, pluginName, newKeyStroke);

		restoreDefaults();

		KeyStroke currentBinding = getKeyBinding(actionName);
		assertEquals("Key binding not restored after a call to restore defautls", defaultKeyStroke,
			currentBinding);
		assertOptionsKeyStroke(actionName, pluginName, defaultKeyStroke);
	}

	@Test
	public void testRestoreDefaultsForSubOptions() throws Exception {
		//
		// Tests that options under a folder in the tree will properly restore default values
		//

		boolean originalValue = getCurrentBooleanEditorValueForNestedOption(
			ToolConstants.TOOL_OPTIONS, "My Options", "my sub group Boolean Value");

		setCurrentBooleanEditorValueForNestedOption(ToolConstants.TOOL_OPTIONS, "My Options",
			"my sub group Boolean Value", !originalValue);
		apply();

		restoreDefaults();

		boolean currentValue = getCurrentBooleanEditorValueForNestedOption(
			ToolConstants.TOOL_OPTIONS, "My Options", "my sub group Boolean Value");
		assertEquals("Sub-option did not get restored after restoring default values",
			originalValue, currentValue);
	}

	@Test
	public void testRestoreDefaultsForCustomWrappedOption() throws Exception {
		//
		// Tests that one of the custom WrappedOption objects can properly restore its values.
		//

		boolean originalValue = getCurrentBooleanEditorValueForNestedOption(
			GhidraOptions.CATEGORY_BROWSER_FIELDS, "Address Field", "Show Block Name");

		setCurrentBooleanEditorValueForNestedOption(GhidraOptions.CATEGORY_BROWSER_FIELDS,
			"Address Field", "Show Block Name", !originalValue);

		apply();

		restoreDefaults();

		boolean currentValue = getCurrentBooleanEditorValueForNestedOption(
			GhidraOptions.CATEGORY_BROWSER_FIELDS, "Address Field", "Show Block Name");
		assertEquals("Sub-option did not get restored after restoring default values",
			originalValue, currentValue);
	}

	@Test
	public void testApplyChanges() throws Exception {
		//
		// Verify that options get changed in the options objects
		//
		Object root = treeModel.getRoot();
		Object toolNode = getGTreeNode(root, TOOL_NODE_NAME);
		assertTrue(defaultPanel.isShowing());

		Object buttonNode = getGTreeNode(toolNode, "Mouse Buttons");
		selectNode(buttonNode);

		ScrollableOptionsEditor simpleOptionsPanel =
			(ScrollableOptionsEditor) getEditorPanel(buttonNode);
		assertNotNull(simpleOptionsPanel);
		assertTrue(simpleOptionsPanel.isShowing());

		PropertySelector ps =
			(PropertySelector) findPairedComponent(simpleOptionsPanel, "Mouse Button To Activate");

		// change to "LEFT"
		runSwing(() -> ps.setSelectedIndex(0));

		final JButton applyButton = findButtonByText(dialog.getComponent(), "Apply");
		assertTrue(applyButton.isEnabled());
		runSwing(() -> applyButton.getActionListeners()[0].actionPerformed(null));

		Options options = tool.getOptions(ToolConstants.TOOL_OPTIONS);
		GhidraOptions.CURSOR_MOUSE_BUTTON_NAMES mouseButton =
			options.getEnum("Mouse Buttons" + Options.DELIMITER + "Mouse Button To Activate",
				(GhidraOptions.CURSOR_MOUSE_BUTTON_NAMES) null);
		assertEquals("LEFT", mouseButton.toString());
		assertTrue(dialog.isShowing());
	}

	@Test
	public void testCancel() throws Exception {
		// make changes to options, but cancel
		Object root = treeModel.getRoot();
		Object toolNode = getGTreeNode(root, TOOL_NODE_NAME);
		assertTrue(defaultPanel.isShowing());

		Object buttonNode = getGTreeNode(toolNode, "Mouse Buttons");
		selectNode(buttonNode);

		ScrollableOptionsEditor simpleOptionsPanel =
			(ScrollableOptionsEditor) getEditorPanel(buttonNode);
		assertNotNull(simpleOptionsPanel);
		assertTrue(simpleOptionsPanel.isShowing());

		PropertySelector ps =
			(PropertySelector) findPairedComponent(simpleOptionsPanel, "Mouse Button To Activate");

		// change to "LEFT"
		runSwing(() -> ps.setSelectedIndex(0));

		final JButton cancelButton = findButtonByText(dialog.getComponent(), "Cancel");
		assertTrue(cancelButton.isEnabled());
		runSwing(() -> cancelButton.getActionListeners()[0].actionPerformed(null));

		Options options = tool.getOptions(ToolConstants.TOOL_OPTIONS);
		GhidraOptions.CURSOR_MOUSE_BUTTON_NAMES mouseButton =
			options.getEnum("Mouse Buttons" + Options.DELIMITER + "Mouse Button To Activate",
				(GhidraOptions.CURSOR_MOUSE_BUTTON_NAMES) null);

		assertEquals("MIDDLE", mouseButton.toString());
		assertTrue(!dialog.isShowing());
	}

	@Test
	public void testAddNewOptionCategory() throws Exception {

		ToolOptions options = tool.getOptions("Test");
		assertNotNull(options);
		// the following "get" methods set values internally
		options.getString("String Value 1", "value 1");
		options.getString("String Value 2", "value 2");
		options.getString("String Value 3", "value 3");
		options.getInt("Int Value", 40);

		pressOptionsOk();

		// re-launch the dialog to get the new options
		showOptionsDialog(tool);

		Object root = treeModel.getRoot();
		Object testNode = getGTreeNode(root, "Test");
		assertNotNull(testNode);
		Integer childCount = (Integer) invokeInstanceMethod("getChildCount", testNode);
		assertEquals(0, childCount.intValue());
		selectNode(testNode);

		ScrollableOptionsEditor p = (ScrollableOptionsEditor) getEditorPanel(testNode);
		assertNotNull(p);
		assertTrue(p.isShowing());

		JTextField field = (JTextField) findPairedComponent(p, "String Value 1");
		assertNotNull(field);
		field = (JTextField) findPairedComponent(p, "String Value 2");
		assertNotNull(field);
		field = (JTextField) findPairedComponent(p, "String Value 3");
		assertNotNull(field);
		field = (JTextField) findPairedComponent(p, "Int Value");
		assertNotNull(field);
	}

	@Test
	public void testToolConfigChange() throws Exception {
		Object root = treeModel.getRoot();
		Object toolNode = getGTreeNode(root, TOOL_NODE_NAME);
		assertTrue(defaultPanel.isShowing());
		selectNode(toolNode);

		ScrollableOptionsEditor simpleOptionsPanel =
			(ScrollableOptionsEditor) getEditorPanel(toolNode);
		assertNotNull(simpleOptionsPanel);
		assertTrue(simpleOptionsPanel.isShowing());

		Component component = findPairedComponent(simpleOptionsPanel, "Favorite Color");
		assertNotNull(component);
		Rectangle rect = component.getBounds();
		clickMouse(component, 1, rect.x, rect.y, 2, 0);

		waitForSwing();

		Window window = waitForWindow("Color Editor");
		assertNotNull(window);

		JColorChooser chooser = findComponent(window, JColorChooser.class);
		assertNotNull(chooser);
		chooser.setColor(Color.BLUE);

		JButton okButton = findButtonByText(window, "OK");
		assertNotNull(okButton);
		pressButton(okButton);

		waitForSwing();

		final JButton applyButton = findButtonByText(dialog.getComponent(), "Apply");
		assertTrue(applyButton.isEnabled());
		runSwing(() -> applyButton.getActionListeners()[0].actionPerformed(null));

		Options options = tool.getOptions(ToolConstants.TOOL_OPTIONS);

		Color c = options.getColor("Favorite Color", Color.RED);

		assertEquals(Color.BLUE, c);

		assertTrue(tool.hasConfigChanged());
	}

	@Test
	public void testSaveRestoreToolState() throws Exception {
		Object root = treeModel.getRoot();
		Object toolNode = getGTreeNode(root, TOOL_NODE_NAME);
		assertTrue(defaultPanel.isShowing());
		selectNode(toolNode);

		ScrollableOptionsEditor simpleOptionsPanel =
			(ScrollableOptionsEditor) getEditorPanel(toolNode);
		assertNotNull(simpleOptionsPanel);
		assertTrue(simpleOptionsPanel.isShowing());

		Component canvas = findPairedComponent(simpleOptionsPanel, "Favorite Color");
		assertNotNull(canvas);
		Rectangle rect = canvas.getBounds();
		clickMouse(canvas, 1, rect.x, rect.y, 2, 0);

		waitForSwing();

		Window window = waitForWindow("Color Editor");
		assertNotNull(window);

		JColorChooser chooser = findComponent(window, JColorChooser.class);
		assertNotNull(chooser);
		chooser.setColor(Color.BLUE);

		JButton okButton = findButtonByText(window, "OK");
		assertNotNull(okButton);
		pressButton(okButton);

		waitForSwing();

		JButton applyButton = findButtonByText(dialog.getComponent(), "Apply");
		assertTrue(applyButton.isEnabled());
		runSwing(() -> applyButton.getActionListeners()[0].actionPerformed(null));

		Options options = tool.getOptions(ToolConstants.TOOL_OPTIONS);

		Color c = options.getColor("Favorite Color", Color.RED);

		assertEquals(Color.BLUE, c);

		env.saveRestoreToolState();

		tool = env.getTool();
		assertEquals(Color.BLUE, options.getColor("Favorite Color", null));

	}

	private KeyStroke getKeyBinding(String actionName) throws Exception {
		OptionsEditor editor = seleNodeWithCustomEditor("Key Bindings");
		KeyBindingsPanel panel = (KeyBindingsPanel) getInstanceField("panel", editor);

		int row = selectRowForAction(panel, actionName);

		JTable table = (JTable) getInstanceField("actionTable", panel);
		@SuppressWarnings("unchecked")
		RowObjectFilterModel<DockingActionIf> model =
			(RowObjectFilterModel<DockingActionIf>) table.getModel();

		DockingActionIf rowValue = model.getModelData().get(row);

		String keyBindingColumnValue =
			(String) model.getColumnValueForRow(rowValue, 1 /* key binding column */);
		if (StringUtils.isBlank(keyBindingColumnValue)) {
			return null;
		}
		return KeyBindingUtils.parseKeyStroke(keyBindingColumnValue);
	}

	private void assertOptionsKeyStroke(String actionName, String pluginName, KeyStroke value)
			throws Exception {
		OptionsEditor editor = seleNodeWithCustomEditor("Key Bindings");
		KeyBindingsPanel panel = (KeyBindingsPanel) getInstanceField("panel", editor);

		Options options = (Options) getInstanceField("options", panel);
		KeyStroke optionsKeyStroke =
			options.getKeyStroke(actionName + " (" + pluginName + ")", null);
		assertEquals("The options keystroke does not match the value in keybinding options table",
			value, optionsKeyStroke);
	}

	private KeyStroke setKeyBinding(String actionName, int modifiers, int keyCode, char keyChar)
			throws Exception {
		OptionsEditor editor = seleNodeWithCustomEditor("Key Bindings");
		final KeyBindingsPanel panel = (KeyBindingsPanel) getInstanceField("panel", editor);

		selectRowForAction(panel, actionName);

		JTextField textField = (JTextField) getInstanceField("ksField", panel);
		triggerKey(textField, modifiers, keyCode, keyChar);

		KeyStroke expectedKeyStroke = KeyStroke.getKeyStroke(keyCode, modifiers, false);
		KeyStroke currentBinding = getKeyBinding(actionName);
		assertEquals("Did not properly set new keybinding", expectedKeyStroke, currentBinding);
		return currentBinding;
	}

	private int selectRowForAction(KeyBindingsPanel panel, String actionName) {
		final JTable table = (JTable) getInstanceField("actionTable", panel);
		@SuppressWarnings("unchecked")
		final RowObjectFilterModel<DockingActionIf> model =
			(RowObjectFilterModel<DockingActionIf>) table.getModel();

		int actionRow = -1;
		List<DockingActionIf> modelData = model.getModelData();
		int rowCount = modelData.size();
		for (int i = 0; i < rowCount; i++) {
			DockingActionIf rowData = modelData.get(i);
			String rowActionName =
				(String) model.getColumnValueForRow(rowData, 0 /* action name column */);
			if (rowActionName.equals(actionName)) {
				actionRow = i;
				break;
			}
		}

		assertTrue("Could not find row for action: " + actionName, actionRow != -1);

		final int row = actionRow;
		runSwing(() -> table.setRowSelectionInterval(row, row));

		return row;
	}

	private Color getAddressFieldColor(OptionsGui optionsGUI) {
		selectAddressEntryInScreenElementOptionsList(optionsGUI);
		final JColorChooser colorChooser =
			(JColorChooser) TestUtils.getInstanceField("colorChooser", optionsGUI);
		return colorChooser.getColor();
	}

	private void selectAddressEntryInScreenElementOptionsList(OptionsGui optionsGUI) {
		final JList<?> namesList = (JList<?>) TestUtils.getInstanceField("namesList", optionsGUI);
		ListModel<?> listModel = namesList.getModel();
		int addressIndex = -1;
		for (int i = 0; i < listModel.getSize(); i++) {
			ScreenElement element = (ScreenElement) listModel.getElementAt(i);
			if (element.getName().equals("Address")) {
				addressIndex = i;
				break;
			}
		}

		assertTrue("Unable to find the Address screen element", addressIndex >= 0);

		// first we need to find the index we want to select
		final int finalIndex = addressIndex;
		runSwing(() -> namesList.setSelectedIndex(finalIndex));
		assertEquals(namesList.getSelectedIndex(), addressIndex);
	}

	private void setAddressColorValueInOptionsGUI(OptionsGui optionsGUI, final Color newColor) {
		final JColorChooser colorChooser =
			(JColorChooser) TestUtils.getInstanceField("colorChooser", optionsGUI);
		runSwing(() -> colorChooser.setColor(newColor));

	}

	private void selectNode(Object node) throws Exception {
		GTreeNode gtNode = (GTreeNode) node;
		TreePath path = gtNode.getTreePath();
		setSelectionPath(path);
		waitForTree(gtNode.getTree());
	}

	private GTreeNode getGTreeNode(Object parent, String nodeName) throws Exception {
		GTreeNode parentNode = (GTreeNode) parent;
		for (int i = 0; i < parentNode.getChildCount(); i++) {
			GTreeNode node = parentNode.getChild(i);
			if (node.getName().equals(nodeName)) {
				return node;
			}
			GTreeNode foundNode = getGTreeNode(node, nodeName);
			if (foundNode != null) {
				return foundNode;
			}
		}

		return null;
	}

	private Object getEditorPanel(Object testNode) {
		@SuppressWarnings("rawtypes")
		Map map = (Map) getInstanceField("editorMap", optionsPanel);
		return map.get(testNode);
	}

	private void waitForThreadedModel() throws InterruptedException {
		GTreeNode root = (GTreeNode) treeModel.getRoot();
		GTree gTree = root.getTree();
		while (gTree.isBusy()) {
			Thread.sleep(50);
		}
	}

	private void pressBrowseButton(ScrollableOptionsEditor editor, String optionName) {
		Component comp = findPairedComponent(editor, optionName);
		assertNotNull(comp);
		AbstractButton button = findAbstractButtonByName((Container) comp, "BrowseButton");
		assertNotNull(button);

		pressButton(button, false);
		waitForSwing();
	}

	private JTextField getEditorTextField(ScrollableOptionsEditor editor, String optionName) {
		Component comp = findPairedComponent(editor, optionName);
		assertNotNull(comp);

		JTextField tf = findComponent((Container) comp, JTextField.class);
		assertNotNull(tf);
		return tf;
	}

	private void pressOptionsOk() {
		pressButtonByName(dialog.getComponent(), "OK", true);
		waitForSwing();
	}

	private ScrollableOptionsEditor showOptions(String category) throws Exception {
		Object root = treeModel.getRoot();
		Object toolNode = getGTreeNode(root, category);
		selectNode(toolNode);
		assertTrue(!defaultPanel.isShowing());

		ScrollableOptionsEditor editor = (ScrollableOptionsEditor) getEditorPanel(toolNode);
		assertNotNull(editor);
		assertTrue(editor.isShowing());
		return editor;
	}

	private PropertyEditor getPropertyEditorForProperty(ScrollableOptionsEditor simpleOptionsPanel,
			String propertyName) {
		// list of EditorInfo objects, which are internal to the SimpleOptionsPanel
		Object scrollableOptionsPanel = getInstanceField("optionsPanel", simpleOptionsPanel);

		@SuppressWarnings("rawtypes")
		List editorInfoList = (List) getInstanceField("editorInfoList", scrollableOptionsPanel);
		for (Object editorStateObject : editorInfoList) {
			// each object is a EditorInfo, which contains a field called 'component'
			EditorState editorState = (EditorState) editorStateObject;
			if (editorState.getTitle() == propertyName) {
				// get the 'editor' object
				return (PropertyEditor) getInstanceField("editor", editorStateObject);
			}
		}

		return null;
	}

	private boolean getCurrentBooleanEditorValueForNestedOption(String parentNodeName,
			String childNodeName, String optionName) throws Exception {

		ScrollableOptionsEditor editor =
			selectSubNodeWithDefaultEditor(parentNodeName, childNodeName);
		JCheckBox checkBox = (JCheckBox) findPairedComponent(editor, optionName);
		return checkBox.isSelected();
	}

	private void setCurrentBooleanEditorValueForNestedOption(String parentNodeName,
			String childNodeName, String optionName, final boolean newValue) throws Exception {

		ScrollableOptionsEditor editor =
			selectSubNodeWithDefaultEditor(parentNodeName, childNodeName);
		final JCheckBox checkBox = (JCheckBox) findPairedComponent(editor, optionName);
		runSwing(() -> checkBox.setSelected(newValue));
		assertEquals(newValue, checkBox.isSelected());
	}

	private String getCurrentTextFieldEditorValue(String parentNodeName, String childNodeName)
			throws Exception {

		ScrollableOptionsEditor editor = selectNodeWithDefaultEditor(parentNodeName);
		JTextField textField = (JTextField) findPairedComponent(editor, childNodeName);
		return getText(textField);
	}

	private void setCurrentTextFieldEditorValue(String parentNodeName, String childNodeName,
			String newValue) throws Exception {

		ScrollableOptionsEditor editor = selectNodeWithDefaultEditor(parentNodeName);
		JTextField textField = (JTextField) findPairedComponent(editor, childNodeName);
		setText(textField, newValue);
		String updatedText = getText(textField);

		assertEquals("Unable to set the current value of field \"" + childNodeName + "\"", newValue,
			updatedText);
	}

	private void restoreDefaults() {
		runSwing(() -> invokeInstanceMethod("restoreDefaultOptionsForCurrentEditor", optionsPanel));

		waitForSwing();
	}

	private ScrollableOptionsEditor selectNodeWithDefaultEditor(String nodeName) throws Exception {
		Object root = treeModel.getRoot();
		Object node = getGTreeNode(root, nodeName);
		selectNode(node);

		ScrollableOptionsEditor editor = (ScrollableOptionsEditor) getEditorPanel(node);
		assertNotNull(editor);
		assertTrue(editor.isShowing());
		return editor;
	}

	private OptionsEditor seleNodeWithCustomEditor(String nodeName) throws Exception {
		Object root = treeModel.getRoot();
		Object node = getGTreeNode(root, nodeName);
		selectNode(node);

		OptionsEditor editor = (OptionsEditor) getEditorPanel(node);
		assertNotNull(editor);
		return editor;
	}

	private ScrollableOptionsEditor selectSubNodeWithDefaultEditor(String parentNodeName,
			String childNodeName) throws Exception {
		Object root = treeModel.getRoot();
		Object parentNode = getGTreeNode(root, parentNodeName);
		Object childNode = getGTreeNode(parentNode, childNodeName);
		selectNode(childNode);

		ScrollableOptionsEditor editor = (ScrollableOptionsEditor) getEditorPanel(childNode);
		assertNotNull(editor);
		assertTrue(editor.isShowing());
		return editor;
	}

	private void apply() {
		final JButton applyButton = findButtonByText(dialog.getComponent(), "Apply");
		assertTrue(applyButton.isEnabled());
		runSwing(() -> applyButton.getActionListeners()[0].actionPerformed(null));
	}

	private void setUpDialog(PluginTool pluginTool) throws Exception {

		createMultiLevelOptions();
		showOptionsDialog(pluginTool);
	}

	private void showOptionsDialog(PluginTool pluginTool) throws Exception {
		// TODO change to getAction("Edit Options")
		Set<DockingActionIf> list = pluginTool.getAllActions();
		for (DockingActionIf action : list) {
			if (action.getName().equals("Edit Options")) {
				performAction(action, false);
				break;
			}
		}

		waitForSwing();
		dialog = waitForDialogComponent(OptionsDialog.class);
		optionsPanel = (OptionsPanel) getInstanceField("panel", dialog);
		Container pane = dialog.getComponent();
		tree = findComponent(pane, JTree.class);
		treeModel = tree.getModel();

		selectNode(treeModel.getRoot());

		defaultPanel = (JPanel) findComponentByName(pane, "Default");
		viewPanel = (JPanel) findComponentByName(pane, "View");
		waitForThreadedModel();

		assertTrue(defaultPanel.isShowing());
	}

	private Component findPairedComponent(Container container, String labelText) {
		Component[] c = container.getComponents();
		for (int i = 0; i < c.length; i++) {
			if (c[i] instanceof JLabel) {
				if (((JLabel) c[i]).getText().equals(labelText)) {
					return c[i + 1];
				}
			}
			if (c[i] instanceof Container) {
				Component comp = findPairedComponent((Container) c[i], labelText);
				if (comp != null) {
					return comp;
				}
			}
		}
		return null;

	}

	private String[] extractNames(String fullOptionName) {
		int pos = fullOptionName.lastIndexOf(Options.DELIMITER);
		if (pos < 0) {
			return new String[0];
		}
		// exclude the option name at the end
		String fullGroupName = fullOptionName.substring(0, pos);

		StringTokenizer st = new StringTokenizer(fullGroupName, "" + Options.DELIMITER);
		List<String> list = new ArrayList<>(3);
		while (st.hasMoreTokens()) {
			String groupName = st.nextToken();
			list.add(groupName);
		}
		String[] names = new String[list.size()];
		return list.toArray(names);
	}

	private void createMultiLevelOptions() {
		Options options = tool.getOptions(ToolConstants.TOOL_OPTIONS);

		// register this options because it is used in a test that saves and restores and
		// only registered options are saved.
		String myOptionsName = "My Options" + Options.DELIMITER;
		options.registerOption(myOptionsName + "my sub group Boolean Value", true, null,
			"description");

		File file = new File(System.getProperty("user.dir"));
		options.registerOption(MY_PATH_NAME_OPTION_NAME, OptionType.FILE_TYPE, file, null,
			"description");
		options.setFile(MY_PATH_NAME_OPTION_NAME, file);

		// the following "get" methods set a value
		options.getInt(myOptionsName + "my sub group" + Options.DELIMITER + "My Test Value", 10);

		options.setBoolean(myOptionsName + "my sub group Boolean Value", true);

		String intOptionName = myOptionsName + "my sub group" + Options.DELIMITER + "Group A" +
			Options.DELIMITER + "Second Int Value";
		options.registerOption(intOptionName, 50, null, "description");
		options.setInt(intOptionName, 50);

		String name = myOptionsName + "my sub group" + Options.DELIMITER + "Group A" +
			Options.DELIMITER + "First boolean value";
		options.registerOption(name, true, null, "description");
		options.setBoolean(name, true);

		name =
			"New Options" + Options.DELIMITER + " subgroup A" + Options.DELIMITER + " subgroup B" +
				Options.DELIMITER + " subgroup C" + Options.DELIMITER + "Another int value";
		options.registerOption(name, 300, null, "description");
		options.setInt(name, 300);

		name = "Favorite Color";
		options.registerOption(name, Color.RED, null, "description");
		options.setColor(name, Color.RED);

		// select the middle button
		name = "Mouse Buttons" + Options.DELIMITER + "Mouse Button To Activate";
		options.registerOption(name, GhidraOptions.CURSOR_MOUSE_BUTTON_NAMES.MIDDLE, null,
			"description");
		options.setEnum(name,
			GhidraOptions.CURSOR_MOUSE_BUTTON_NAMES.MIDDLE);

	}

	private void writeTempFile(String filename) throws IOException {
		BufferedWriter writer = new BufferedWriter(new FileWriter(filename));
		writer.write("test file");
		writer.flush();
		writer.close();
	}

	private void setSelectionPath(final TreePath path) throws Exception {
		runSwing(() -> tree.setSelectionPath(path));

		runSwing(() -> tree.expandPath(path));
	}
}
