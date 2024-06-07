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
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.util.List;
import java.util.Set;

import javax.swing.*;
import javax.swing.table.*;

import org.junit.*;

import docking.DockingWindowManager;
import docking.action.*;
import docking.actions.KeyBindingUtils;
import docking.actions.ToolActions;
import docking.widgets.MultiLineLabel;
import generic.test.TestUtils;
import generic.util.action.SystemKeyBindings;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.navigation.GoToAddressLabelPlugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;

/**
 * Tests for key bindings option panel
 */
public class KeyBindingsTest extends AbstractGhidraHeadedIntegrationTest {

	private PluginTool tool;
	private TestEnv env;
	private KeyBindingsPanel panel;
	private JTable table;
	private TableModel model;
	private JTextField keyField;
	private JTextPane statusPane;
	private JDialog dialog;

	private DockingActionIf action1;
	private DockingActionIf action2;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.getTool();

		tool.addPlugin(CodeBrowserPlugin.class.getName());
		tool.addPlugin(GoToAddressLabelPlugin.class.getName());

		env.showTool();

		setUpDialog();

		grabActionsWithoutKeybinding();
	}

	@After
	public void tearDown() throws Exception {
		dialog.setVisible(false);
		env.dispose();
	}

	@Test
	public void testKeyBindingsDisplay() throws Exception {

		assertEquals(3, model.getColumnCount());
		String[] ids = new String[] { "Action Name", "KeyBinding", "Plugin Name" };
		TableColumnModel m = table.getColumnModel();
		for (int i = 0; i < ids.length; i++) {
			TableColumn c = m.getColumn(i);
			assertEquals(ids[i], c.getIdentifier());
		}
		assertTrue(model.getRowCount() > 0);

		// look for the info panel
		MultiLineLabel label = findComponent(panel, MultiLineLabel.class);
		String str = "To add or change a key binding, select an action\n" +
			"and type any key combination\n" + " \n" +
			"To remove a key binding, select an action and\n" + "press <Enter> or <Backspace>";

		assertEquals(str, label.getLabel());

		//  verify that the description is displayed for the selected action

		selectRowForAction(action1);

		String actualText = getText(statusPane);
		String description = action1.getDescription();
		String escaped = description.replaceAll("&", "&amp;");
		assertTrue(
			"Description is not updated for action '" + action1.getName() + "'; instead the " +
				"description is '" + actualText + "'\n\tDescrption: " + escaped,
			actualText.indexOf(escaped) != -1);
	}

	@Test
	public void testManagedKeyBindings() {
		Set<DockingActionIf> list = tool.getAllActions();
		for (DockingActionIf action : list) {
			if (!ignoreAction(action)) {
				boolean inTable = actionInKeyBindingsTable(action);
				assertTrue("Action should be in the key bindingds table: " + action.getFullName(),
					inTable);
			}
		}
	}

	@Test
	public void testEditKeyBinding() throws Exception {
		// find action that has a keystroke assigned
		DockingActionIf action = getKeyBindingPluginAction();
		assertNotNull("Could not find edit key binding action.", action);

		selectRowForAction(action);
		triggerText(keyField, "z");
		assertKeyFieldText("Z");

		apply();
		assertEquals(KeyStroke.getKeyStroke(KeyEvent.VK_Z, 0), getKeyStroke(action));
	}

	@Test
	public void testActionNotSelected() throws Exception {
		table.clearSelection();
		Set<DockingActionIf> list = tool.getAllActions();
		for (DockingActionIf action : list) {
			KeyStroke ks = getKeyStroke(action);
			if (supportsKeyBindings(action) && ks != KeyStroke.getKeyStroke(KeyEvent.VK_Z, 0)) {
				break;
			}
		}

		triggerText(keyField, "z");
		assertMessage("No action is selected.");
	}

	@Test
	public void testSetKeyBinding() throws Exception {
		// set a key binding on an action that does not have a key binding
		selectRowForAction(action1);
		triggerActionKey(keyField, InputEvent.CTRL_DOWN_MASK, KeyEvent.VK_X);
		KeyStroke ks = KeyStroke.getKeyStroke(KeyEvent.VK_X, InputEvent.CTRL_DOWN_MASK);
		assertKeyFieldText(KeyBindingUtils.parseKeyStroke(ks));

		apply();
		assertEquals(ks, getKeyStroke(action1));
	}

	@Test
	public void testSetKeyBinding2() throws Exception {

		selectRowForAction(action1);
		triggerText(keyField, "x");
		assertKeyFieldText("X");

		apply();
		assertEquals(KeyStroke.getKeyStroke(KeyEvent.VK_X, 0), getKeyStroke(action1));
	}

	@Test
	public void testSetKeyBinding3() throws Exception {

		selectRowForAction(action1);
		typeKeyStroke(InputEvent.CTRL_DOWN_MASK, KeyEvent.VK_HOME);
		KeyStroke ks = KeyStroke.getKeyStroke(KeyEvent.VK_HOME, InputEvent.CTRL_DOWN_MASK);
		assertKeyFieldText(ks);

		apply();
		assertEquals(ks, getKeyStroke(action1));
	}

	@Test
	public void testSetKeyBinding4() throws Exception {

		selectRowForAction(action1);
		typeKeyStroke(KeyEvent.VK_PAGE_UP);
		KeyStroke ks = KeyStroke.getKeyStroke(KeyEvent.VK_PAGE_UP, 0);
		assertKeyFieldText(ks);

		apply();
		assertEquals(ks, getKeyStroke(action1));
	}

	@Test
	public void testSetKeyBinding_AltGraphFix() throws Exception {

		//
		// This test is verifying a hack that was put in to fix the difference in 'Alt' key handling
		// on Windows (https://bugs.openjdk.java.net/browse/JDK-8194873).
		// Create an action and set the keybinding to use the 'Alt' modifier.
		// Verify that the action will also get mapped to the 'Alt Graph' modifier.
		//

		// verify that no action is mapped to the new binding
		int keyCode = KeyEvent.VK_0;
		int modifiers = InputEvent.ALT_DOWN_MASK | InputEvent.ALT_GRAPH_DOWN_MASK;
		KeyEvent keyEvent = new KeyEvent(dialog, KeyEvent.KEY_PRESSED, System.currentTimeMillis(),
			modifiers, keyCode, KeyEvent.CHAR_UNDEFINED);
		KeyStroke keyStroke = KeyStroke.getKeyStrokeForEvent(keyEvent);
		DockingWindowManager dwm = DockingWindowManager.getActiveInstance();
		Action action =
			(Action) TestUtils.invokeInstanceMethod("getActionForKeyStroke", dwm, keyStroke);
		assertNull(action);

		// set the new binding that uses the 'Alt' key
		selectRowForAction(action1);
		typeKeyStroke(InputEvent.ALT_DOWN_MASK, keyCode);
		KeyStroke ks = KeyStroke.getKeyStroke(keyCode, InputEvent.ALT_DOWN_MASK);
		assertKeyFieldText(ks);
		apply();
		assertEquals(ks, getKeyStroke(action1));

		// verify the additional binding for 'Alt Graph'
		action = (Action) TestUtils.invokeInstanceMethod("getActionForKeyStroke", dwm, keyStroke);
		assertNotNull(action);
	}

	@Test
	public void testClearKeyBinding1() throws Exception {

		selectRowForAction(action1);

		typeKeyStroke(KeyEvent.VK_ENTER);
		assertNoKeyStrokeText();

		apply();
		assertNull(getKeyStroke(action1));
	}

	@Test
	public void testClearKeyBinding2() throws Exception {

		selectRowForAction(action1);
		typeBackspace();
		assertNoKeyStrokeText();

		apply();
		assertNull(getKeyStroke(action1));
	}

	@Test
	public void testMultipleActionsOnKeyBinding() throws Exception {

		// verify that a list of collisions show up

		selectRowForAction(action1);
		typeKeyStroke(KeyEvent.VK_OPEN_BRACKET);
		apply();

		// set same binding on a different action, which will trigger the collisions list
		selectRowForAction(action2);
		typeKeyStroke(KeyEvent.VK_OPEN_BRACKET);

		MultiLineLabel label = (MultiLineLabel) findComponentByName(panel, "CollisionLabel");

		String msg = label.getLabel();
		String[] lines = msg.split("\n");
		assertEquals(3, lines.length);

		boolean success = msg.contains(action1.getName()) && msg.contains(action2.getName());

		assertTrue("In-use action message incorrect.\n\tIt should contain these 2 actions:\n\t\t" +
			action1.getName() + "\n\t\t" + action2.getName() + ".\nActual message:\n" + msg + "\n",
			success);
	}

	@Test
	public void testSetReservedKeybinding() throws Exception {
		// try to set a reserved keybinding
		KeyStroke reservedKeystroke = SystemKeyBindings.UPDATE_KEY_BINDINGS_KEY; // F4

		selectRowForAction(action1);
		typeKeyStroke(reservedKeystroke);

		assertNoKeyStrokeText();
		assertMessage("F4 in use by System action 'Set KeyBinding'");

		apply();
		assertEquals(null, getKeyStroke(action1));

		// set a valid binding
		setUpDialog();
		selectRowForAction(action1);

		KeyStroke validKeyStroke = KeyStroke.getKeyStroke(KeyEvent.VK_X, InputEvent.CTRL_DOWN_MASK);
		typeKeyStroke(validKeyStroke);
		assertKeyFieldText(validKeyStroke);

		apply();
		assertEquals(validKeyStroke, getKeyStroke(action1));

		// try again to set a reserved binding
		setUpDialog();
		selectRowForAction(action1);
		assertEquals(validKeyStroke, getKeyStroke(action1));

		typeKeyStroke(reservedKeystroke.getKeyCode());
		assertNoKeyStrokeText();
		assertMessage("F4 in use by System action 'Set KeyBinding'");

		apply();
		assertEquals(validKeyStroke, getKeyStroke(action1));
	}

	@Test
	public void testSetKeyBindingOnSystemAction() throws Exception {
		//
		// Test that users can change the keybinding for a System action.  The new binding cannot
		// be in use by any other action.
		//
		DockingActionIf goToAction = getAction(tool, "Go To Address/Label"); // arbitrary plugin action
		KeyStroke goToKs = goToAction.getKeyBinding();
		assertNotNull(goToKs);

		DockingActionIf systemAction = getAction("Show Context Menu"); // arbitrary system action
		KeyStroke systemKs = systemAction.getKeyBinding();
		assertNotNull(systemKs);
		selectRowForAction(systemAction);

		typeKeyStroke(goToKs);
		assertNoKeyStrokeText();
		assertMessage("System action cannot be set to in-use key stroke");

		apply();
		assertEquals(systemKs, getKeyStroke(systemAction)); // unchanged

		// clear the in-use binding and then try again
		clearKeyBinding(goToKs);

		setUpDialog();
		selectRowForAction(systemAction);

		typeKeyStroke(goToKs);
		assertKeyFieldText("G");

		apply();
		assertEquals(goToKs, getKeyStroke(systemAction));
	}

	@Test
	public void testSetKeybindingUsingSystemDefaultBinding_InUse() throws Exception {
		//
		// Test that users can change the keybinding for a non-System action to use a pre-defined
		// System key stroke only if the binding is not in-use by a System action. 
		//
		// This test will clear the system key binding in the UI by using the backspace key.
		// Note: The 'Apply' button must be pressed before the system key stroke can be reused.
		//

		DockingActionIf systemAction = getAction("Show Context Menu"); // arbitrary system action
		KeyStroke systemKs = systemAction.getKeyBinding();
		String systemKsText = KeyBindingUtils.parseKeyStroke(systemKs);
		assertEquals(SystemKeyBindings.CONTEXT_MENU_KEY1, systemKs);
		assertNotNull(systemKs);

		DockingActionIf goToAction = getAction(tool, "Go To Address/Label"); // arbitrary plugin action
		KeyStroke goToKs = goToAction.getKeyBinding();
		assertNotNull(goToKs);

		setUpDialog();

		selectRowForAction(action1);
		typeKeyStroke(systemKs);
		assertNoKeyStrokeText();
		assertMessage(systemKsText + " in use by System action 'Show Context Menu'");

		selectRowForAction(systemAction);
		typeBackspace();
		apply();
		assertEquals(null, getKeyStroke(systemAction));

		selectRowForAction(action1);
		typeKeyStroke(systemKs);
		assertKeyFieldText(systemKsText);
		assertNoErrorMessage();
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private boolean ignoreAction(DockingActionIf action) {
		if (!action.getKeyBindingType().isManaged()) {
			return true;
		}

		return action.getFullName().contains("Table Data");
	}

	private void assertNoKeyStrokeText() {
		assertEquals("", keyField.getText());
	}

	private void assertKeyFieldText(KeyStroke ks) {
		assertKeyFieldText(KeyBindingUtils.parseKeyStroke(ks));
	}

	private void assertKeyFieldText(String s) {
		assertEquals(s, runSwing(() -> keyField.getText()));
	}

	private void assertNoErrorMessage() {
		assertMessage("");
	}

	private void typeBackspace() {
		triggerBackspaceKey(keyField);
		waitForSwing();
	}

	private void typeKeyStroke(KeyStroke ks) {
		triggerKey(keyField, ks);
		waitForSwing();
	}

	private void typeKeyStroke(int keyCode) {
		typeKeyStroke(0, keyCode);
	}

	private void typeKeyStroke(int modifiers, int keyCode) {
		triggerKey(keyField, modifiers, keyCode, KeyEvent.CHAR_UNDEFINED);
		waitForSwing();
	}

	private void clearKeyBinding(KeyStroke ks) {

		ToolActions toolActions = (ToolActions) tool.getToolActions();
		Action action = toolActions.getAction(ks);
		if (action instanceof MultipleKeyAction multiAction) {
			List<DockingActionIf> actions = multiAction.getActions();
			for (DockingActionIf dockingAction : actions) {
				runSwing(() -> dockingAction.setKeyBindingData(null));
			}
		}
		else if (action instanceof SystemKeyBindingAction systemAction) {
			DockingActionIf dockingAction = systemAction.getAction();
			runSwing(() -> dockingAction.setKeyBindingData(null));
		}
	}

	private DockingActionIf getAction(String name) {

		Set<DockingActionIf> actions = tool.getAllActions();
		for (DockingActionIf action : actions) {
			if (action.getName().equals(name)) {
				return action;
			}
		}

		fail("Unable to find System action '%s'".formatted(name));
		return null;
	}

	private void assertMessage(String text) {
		String kbStatusMessage = runSwing(panel::getStatusText);
		if (!kbStatusMessage.contains(text)) {
			fail("Expected message: " + text + ".  Found message: " + kbStatusMessage);
		}
	}

	private void apply() {
		runSwing(() -> panel.apply());
		waitForSwing();
	}

	private boolean supportsKeyBindings(DockingActionIf action) {
		return ignoreAction(action);
	}

	private DockingActionIf getKeyBindingPluginAction() {
		Set<DockingActionIf> list = tool.getAllActions();
		for (DockingActionIf action : list) {
			KeyStroke ks = action.getKeyBinding();
			if (!ignoreAction(action) && ks != null &&
				ks != KeyStroke.getKeyStroke(KeyEvent.VK_Z, 0)) {
				return action;
			}
		}
		return null;
	}

	private boolean actionInKeyBindingsTable(DockingActionIf action) {
		String actionName = action.getName();
		KeyStroke ks = action.getKeyBinding();

		for (int i = 0; i < model.getRowCount(); i++) {
			if (actionName.equals(model.getValueAt(i, 0))) {
				if (ks != null) {
					String ksStr = (String) model.getValueAt(i, 1);
					return ksStr.equals(KeyBindingUtils.parseKeyStroke(ks));
				}
				return true;
			}
		}
		return false;
	}

	private void selectRowForAction(DockingActionIf action) {
		String actionName = action.getName();
		for (int i = 0; i < model.getRowCount(); i++) {
			if (actionName.equals(model.getValueAt(i, 0))) {
				int idx = i;
				runSwing(() -> {
					table.setRowSelectionInterval(idx, idx);
					Rectangle rect = table.getCellRect(idx, idx, true);
					table.scrollRectToVisible(rect);
				});

				waitForSwing();
				return;
			}
		}
		fail("Could not find action to select: " + action);
	}

	private KeyStroke getKeyStroke(DockingActionIf action) {
		return runSwing(() -> action.getKeyBinding());
	}

	private void setUpDialog() throws Exception {

		if (panel != null) {
			runSwing(() -> {
				dialog.setVisible(false);
			});
		}

		runSwing(() -> {
			panel = new KeyBindingsPanel(tool);
			panel.setOptionsPropertyChangeListener(evt -> {
				// stub
			});

			dialog = new JDialog(tool.getToolFrame(), "Test KeyBindings", false);
			dialog.getContentPane().add(panel);
			dialog.pack();
			dialog.setVisible(true);
		});
		table = findComponent(panel, JTable.class);
		keyField = (JTextField) findComponentByName(panel, "Key Entry Text Field");
		statusPane = findComponent(panel, JTextPane.class);
		model = table.getModel();
		waitForSwing();
	}

	// find 2 actions that do not have key bindings so that we can add and change the values
	private void grabActionsWithoutKeybinding() {
		Set<DockingActionIf> list = tool.getAllActions();
		for (DockingActionIf action : list) {
			if (ignoreAction(action)) {
				continue;
			}
			if (action.getKeyBinding() != null) {
				continue;
			}

			if (action1 == null) {
				action1 = action;
			}
			else {

				if (action.getName().equals(action1.getName())) {
					continue; // same name, different owners; these are 'shared' actions--ignore
				}

				action2 = action;
				return; // grabbed all actions--we are done
			}
		}
	}
}
