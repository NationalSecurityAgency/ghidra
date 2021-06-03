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
import java.util.Set;

import javax.swing.*;
import javax.swing.table.*;

import org.junit.*;

import docking.DockingWindowManager;
import docking.KeyEntryTextField;
import docking.action.DockingActionIf;
import docking.tool.util.DockingToolConstants;
import docking.widgets.MultiLineLabel;
import generic.test.TestUtils;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.Msg;

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
			"and type any key combination\n" +
			" \n" +
			"To remove a key binding, select an action and\n" +
			"press <Enter> or <Backspace>";

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

	private boolean ignoreAction(DockingActionIf action) {
		if (!action.getKeyBindingType().isManaged()) {
			return true;
		}

		return action.getFullName().contains("Table Data");
	}

	@Test
	public void testEditKeyBinding() throws Exception {
		// find action that has a keystroke assigned
		DockingActionIf action = getKeyBindingPluginAction();
		assertNotNull("Could not find edit key binding action.", action);

		selectRowForAction(action);
		triggerText(keyField, "z");
		assertEquals("Z", keyField.getText());

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
		assertTrue(statusPane.getText().indexOf("No action is selected.") != -1);
	}

	@Test
	public void testSetKeyBinding() throws Exception {
		// set a key binding on an action that does not have a key binding

		selectRowForAction(action1);
		triggerActionKey(keyField, InputEvent.CTRL_DOWN_MASK, KeyEvent.VK_X);
		assertEquals(
			KeyEntryTextField.parseKeyStroke(
				KeyStroke.getKeyStroke(KeyEvent.VK_X, InputEvent.CTRL_DOWN_MASK)),
			keyField.getText());

		apply();
		assertEquals(KeyStroke.getKeyStroke(KeyEvent.VK_X, InputEvent.CTRL_DOWN_MASK),
			getKeyStroke(action1));

	}

	@Test
	public void testSetKeyBinding2() throws Exception {

		selectRowForAction(action1);
		triggerText(keyField, "x");
		assertEquals("X", keyField.getText());

		apply();
		assertEquals(KeyStroke.getKeyStroke(KeyEvent.VK_X, 0), getKeyStroke(action1));

	}

	@Test
	public void testSetKeyBindingNotAllowed() throws Exception {

		selectRowForAction(action1);
		triggerActionKey(keyField, 0, KeyEvent.VK_F1);
		// F1 is the help key and cannot be used
		assertEquals("", keyField.getText());

		triggerActionKey(keyField, 0, KeyEvent.VK_HELP);
		assertEquals("", keyField.getText());

		triggerActionKey(keyField, 0, KeyEvent.VK_SHIFT);
		assertEquals("", keyField.getText());

		triggerActionKey(keyField, 0, KeyEvent.VK_ENTER);
		assertEquals("", keyField.getText());
	}

	@Test
	public void testSetKeyBinding3() throws Exception {

		selectRowForAction(action1);
		triggerActionKey(keyField, InputEvent.CTRL_DOWN_MASK, KeyEvent.VK_HOME);
		assertEquals(
			KeyEntryTextField.parseKeyStroke(
				KeyStroke.getKeyStroke(KeyEvent.VK_HOME, InputEvent.CTRL_DOWN_MASK)),
			keyField.getText());

		apply();
		assertEquals(KeyStroke.getKeyStroke(KeyEvent.VK_HOME, InputEvent.CTRL_DOWN_MASK),
			getKeyStroke(action1));
	}

	@Test
	public void testSetKeyBinding4() throws Exception {

		selectRowForAction(action1);
		triggerActionKey(keyField, 0, KeyEvent.VK_PAGE_UP);
		assertEquals(
			KeyEntryTextField.parseKeyStroke(KeyStroke.getKeyStroke(KeyEvent.VK_PAGE_UP, 0)),
			keyField.getText());

		apply();
		assertEquals(KeyStroke.getKeyStroke(KeyEvent.VK_PAGE_UP, 0), getKeyStroke(action1));
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
		KeyEvent keyEvent =
			new KeyEvent(dialog, KeyEvent.KEY_PRESSED, System.currentTimeMillis(), modifiers,
				keyCode, KeyEvent.CHAR_UNDEFINED);
		KeyStroke keyStroke = KeyStroke.getKeyStrokeForEvent(keyEvent);
		DockingWindowManager dwm = DockingWindowManager.getActiveInstance();
		Action action =
			(Action) TestUtils.invokeInstanceMethod("getActionForKeyStroke", dwm, keyStroke);
		assertNull(action);

		// set the new binding that uses the 'Alt' key
		selectRowForAction(action1);
		triggerActionKey(keyField, InputEvent.ALT_DOWN_MASK, keyCode);
		String keyStrokeString = KeyEntryTextField.parseKeyStroke(
			KeyStroke.getKeyStroke(keyCode, InputEvent.ALT_DOWN_MASK));
		assertEquals(keyStrokeString, keyField.getText());
		apply();
		assertEquals(KeyStroke.getKeyStroke(keyCode, InputEvent.ALT_DOWN_MASK),
			getKeyStroke(action1));

		// verify the additional binding for 'Alt Graph'
		action =
			(Action) TestUtils.invokeInstanceMethod("getActionForKeyStroke", dwm, keyStroke);
		assertNotNull(action);
	}

	@Test
	public void testClearKeyBinding1() throws Exception {

		selectRowForAction(action1);

		triggerActionKey(keyField, 0, KeyEvent.VK_ENTER);
		assertEquals("", keyField.getText());

		apply();
		assertNull(getKeyStroke(action1));
	}

	@Test
	public void testClearKeyBinding2() throws Exception {

		selectRowForAction(action1);
		triggerText(keyField, "\b");
		assertEquals("", keyField.getText());

		apply();
		assertNull(getKeyStroke(action1));
	}

	@Test
	public void testMultipleActionsOnKeyBinding() throws Exception {

		// verify that a list of collisions show up

		selectRowForAction(action1);
		triggerActionKey(keyField, 0, KeyEvent.VK_OPEN_BRACKET);
		apply();

		// set same binding on a different action, which will trigger the collisions list
		selectRowForAction(action2);
		triggerActionKey(keyField, 0, KeyEvent.VK_OPEN_BRACKET);

		MultiLineLabel label = (MultiLineLabel) findComponentByName(panel, "CollisionLabel");

		String msg = label.getLabel();
		String[] lines = msg.split("\n");
		assertEquals(3, lines.length);
		assertTrue(lines[1].contains(action1.getName()));
		assertTrue(lines[2].contains(action2.getName()));
	}

	@Test
	public void testSetReservedKeybinding() throws Exception {
		// try to set a reserved keybinding
		KeyStroke reservedKeystroke = KeyStroke.getKeyStroke(KeyEvent.VK_F4, 0);

		selectRowForAction(action1);
		triggerActionKey(keyField, 0, reservedKeystroke.getKeyCode());

		assertEquals("", keyField.getText());

		apply();
		assertEquals(null, getKeyStroke(action1));

		// set a valid binding
		setUpDialog();
		selectRowForAction(action1);

		capture(panel, "pre.keystroke.change");
		KeyStroke validKeyStroke = KeyStroke.getKeyStroke(KeyEvent.VK_X, InputEvent.CTRL_DOWN_MASK);
		triggerActionKey(keyField, InputEvent.CTRL_DOWN_MASK, validKeyStroke.getKeyCode());
		assertEquals(KeyEntryTextField.parseKeyStroke(validKeyStroke), keyField.getText());
		capture(panel, "post.keystroke.change");

		apply();
		capture(panel, "post.keystroke.apply");
		assertEquals(validKeyStroke, getKeyStroke(action1));

		// try again to set a reserved binding
		setUpDialog();
		selectRowForAction(action1);

		assertEquals(validKeyStroke, getKeyStroke(action1));

		String originalText = keyField.getText();
		triggerActionKey(keyField, 0, reservedKeystroke.getKeyCode());

		assertEquals(originalText, keyField.getText());

		apply();
		assertEquals(validKeyStroke, getKeyStroke(action1));
	}

//==================================================================================================
// Private Methods
//==================================================================================================

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
			if (ignoreAction(action) && ks != null &&
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
					return ksStr.equals(KeyEntryTextField.parseKeyStroke(ks));
				}
				return true;
			}
		}
		return false;
	}

	private void selectRowForAction(DockingActionIf action) throws Exception {
		String actionName = action.getName();

		Msg.debug(this, "Keybinding Action: " + action.getFullName());
		for (int i = 0; i < model.getRowCount(); i++) {
			if (actionName.equals(model.getValueAt(i, 0))) {
				final int idx = i;

				Msg.debug(this, "\tselection row for action: " + i);
				runSwing(() -> {
					table.setRowSelectionInterval(idx, idx);
					Rectangle rect = table.getCellRect(idx, idx, true);
					table.scrollRectToVisible(rect);
				});
				return;
			}
		}
		waitForSwing();
	}

	private KeyStroke getKeyStroke(DockingActionIf action) {
		return runSwing(() -> action.getKeyBinding());
	}

	private void setUpDialog() throws Exception {
		runSwing(() -> {
			panel = new KeyBindingsPanel(tool, tool.getOptions(DockingToolConstants.KEY_BINDINGS));
			panel.setOptionsPropertyChangeListener(evt -> {
				// stub
			});

			dialog = new JDialog(tool.getToolFrame(), "Test KeyBindings", false);
			dialog.getContentPane().add(panel);
			dialog.pack();
			dialog.setVisible(true);
		});
		table = findComponent(panel, JTable.class);
		keyField = findComponent(panel, JTextField.class);
		keyField = (JTextField) getInstanceField("ksField", panel);
		statusPane = findComponent(panel, JTextPane.class);
		model = table.getModel();
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
