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
package docking.action;

import static org.junit.Assert.*;

import java.awt.event.KeyEvent;
import java.util.Map;
import java.util.Set;

import javax.swing.*;

import org.junit.*;

import docking.*;
import docking.actions.*;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.navigation.GoToAddressLabelPlugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import util.CollectionUtils;

public class KeyEntryDialogTest extends AbstractGhidraHeadedIntegrationTest {

	private PluginTool tool;
	private TestEnv env;
	private KeyEntryDialog keyEntryDialog;
	private JTextPane collisionPane;
	private KeyEntryTextField keyEntryField;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.launchDefaultTool();
	}

	@After
	public void tearDown() throws Exception {
		close(keyEntryDialog);
		env.dispose();
	}

	@Test
	public void testKeyEntry() throws Exception {
		// make sure we can set an unbound action
		DockingAction unboundAction = getUnboundAction();
		showDialog(unboundAction);

		KeyStroke acceleratorKey = unboundAction.getKeyBinding();
		assertNull(acceleratorKey);

		triggerText(keyEntryField, "q");

		pressDialogOK();
		acceleratorKey = unboundAction.getKeyBinding();
		assertNotNull(acceleratorKey);
		assertEquals(acceleratorKey.getKeyCode(), KeyEvent.VK_Q);

		// clear the action
		showDialog(unboundAction);
		triggerBackspaceKey(keyEntryField);

		pressDialogOK();
		acceleratorKey = unboundAction.getKeyBinding();
		assertNull(acceleratorKey);

		// make sure we can set an action that already had a binding
		DockingAction boundAction = getBoundAction();
		showDialog(boundAction);

		assertEquals("G", keyEntryField.getText());

		triggerText(keyEntryField, "q");

		pressDialogOK();
		acceleratorKey = boundAction.getKeyBinding();
		assertNotNull(acceleratorKey);
		assertEquals(acceleratorKey.getKeyCode(), KeyEvent.VK_Q);
	}

	@Test
	public void testClearDefaultKeyBinding() throws Exception {

		DockingAction boundAction = getBoundAction_Shared();
		showDialog(boundAction);

		assertEquals("OPEN_BRACKET", keyEntryField.getText());
		triggerBackspaceKey(keyEntryField);

		pressDialogOK();
		KeyStroke ks = boundAction.getKeyBinding();
		assertNull(ks);
	}

	@Test
	public void testClearDefaultKeyBinding_SharedKeybinding() throws Exception {

		DockingAction boundAction = getBoundAction_Shared();
		showDialog(boundAction);

		KeyStroke oldKs = boundAction.getKeyBinding();
		assertEquals("OPEN_BRACKET", keyEntryField.getText());
		triggerBackspaceKey(keyEntryField);

		pressDialogOK();
		KeyStroke ks = boundAction.getKeyBinding();
		assertNull(ks);

		ToolActions toolActions = (ToolActions) tool.getToolActions();
		Action toolAction = toolActions.getAction(oldKs);
		assertNull("Shared actions' keybinding not cleared", toolAction);
	}

	@Test
	public void testCollision() throws Exception {
		// make sure we get a collision for a value that is already bound
		DockingAction unboundAction = getUnboundAction();
		showDialog(unboundAction);

		assertEquals("", keyEntryField.getText());

		String collisionString = "Actions mapped to";
		assertTrue(collisionPane.getText().indexOf(collisionString) == -1);

		// 'G' is bound to goto
		triggerText(keyEntryField, "g");

		assertTrue(collisionPane.getText().indexOf(collisionString) != -1);

		// cancel
		pressDialogCancel();

		// make sure we can still set the value after the collision is detected
		showDialog(unboundAction);

		assertEquals("", keyEntryField.getText());
		assertTrue(collisionPane.getText().indexOf(collisionString) == -1);

		triggerText(keyEntryField, "g");

		assertTrue(collisionPane.getText().indexOf(collisionString) != -1);

		pressDialogOK();

		KeyStroke acceleratorKey = unboundAction.getKeyBinding();
		assertNotNull(acceleratorKey);
		assertEquals(acceleratorKey.getKeyCode(), KeyEvent.VK_G);
	}

	@Test
	public void testReservedKeyBindings() throws Exception {
		DockingAction unboundAction = getUnboundAction();
		showDialog(unboundAction);

		assertEquals("", keyEntryField.getText());
		String reservedString = " is a reserved keystroke";
		assertTrue(keyEntryDialog.getStatusText().indexOf(reservedString) == -1);

		// test that typing a reserved key does not enter any text in the text field
		KeyStroke keyBindingKeyStroke = KeyStroke.getKeyStroke(KeyEvent.VK_F4, 0);
		triggerActionKey(keyEntryField, keyBindingKeyStroke.getModifiers(),
			keyBindingKeyStroke.getKeyCode());
		assertEquals(keyEntryDialog.getStatusText().trim(), "");

		triggerBackspaceKey(keyEntryField);
		triggerText(keyEntryField, "g");
		pressDialogOK();

		KeyStroke acceleratorKey = unboundAction.getKeyBinding();
		assertNotNull(acceleratorKey);
		assertEquals(acceleratorKey.getKeyCode(), KeyEvent.VK_G);
	}

	@Test
	public void testPlaceholderActionsAppearInDialog() throws Exception {

		DockingAction unboundAction = getUnboundAction();
		showDialog(unboundAction);

		int modifiers = 0;
		int keyCode = KeyEvent.VK_DELETE;
		triggerActionKey(keyEntryField, modifiers, keyCode);

		String placeholderText = "Remove Items";
		assertTrue("Placeholder action is not registered with the KeyEntryDialog",
			collisionPane.getText().contains(placeholderText));

		// this can be any of the plugins that register this action placeholder
		placeholderText = "TableServicePlugin";
		assertTrue("Placeholder action is not registered with the KeyEntryDialog",
			collisionPane.getText().contains(placeholderText));
	}

//==================================================================================================
// Private methods
//==================================================================================================    

	private DockingAction getUnboundAction() {
		CodeBrowserPlugin codeBrowserPlugin = env.getPlugin(CodeBrowserPlugin.class);
		return (DockingAction) getInstanceField("tableFromSelectionAction", codeBrowserPlugin);
	}

	private DockingAction getBoundAction() {
		GoToAddressLabelPlugin goToPlugin = env.getPlugin(GoToAddressLabelPlugin.class);
		return (DockingAction) getInstanceField("action", goToPlugin);
	}

	private DockingAction getBoundAction_Shared() {
		Set<DockingActionIf> sharedActions =
			getActionsByOwnerAndName(tool, "Shared", "Define Array");
		assertFalse(sharedActions.isEmpty());
		return (DockingAction) CollectionUtils.any(sharedActions);
	}

	private void pressDialogOK() {
		JButton okButton = (JButton) getInstanceField("okButton", keyEntryDialog);
		pressButton(okButton);
	}

	private void pressDialogCancel() {
		JButton cancelButton = (JButton) getInstanceField("cancelButton", keyEntryDialog);
		pressButton(cancelButton);
	}

	public DockingAction getKeyBindingAction() {

		DockingToolActions toolActions = tool.getToolActions();
		KeyBindingsManager kbm =
			(KeyBindingsManager) getInstanceField("keyBindingsManager", toolActions);
		@SuppressWarnings("unchecked")
		Map<KeyStroke, DockingKeyBindingAction> dockingKeyMap =
			(Map<KeyStroke, DockingKeyBindingAction>) getInstanceField("dockingKeyMap", kbm);
		KeyStroke ks = KeyStroke.getKeyStroke(KeyEvent.VK_F4, 0);
		DockingKeyBindingAction dockingAction = dockingKeyMap.get(ks);
		DockingAction f4Action = (DockingAction) getInstanceField("docakbleAction", dockingAction);
		return f4Action;
	}

	private void showDialog(final DockingAction actionToEdit) throws Exception {
		DockingAction keyBindingAction = getKeyBindingAction();
		executeOnSwingWithoutBlocking(() -> {
			DockingWindowManager.setMouseOverAction(actionToEdit);
			performAction(keyBindingAction, false);
		});

		keyEntryDialog = waitForDialogComponent(KeyEntryDialog.class);
		assertNotNull(keyEntryDialog);

		collisionPane = (JTextPane) getInstanceField("collisionPane", keyEntryDialog);
		keyEntryField = (KeyEntryTextField) getInstanceField("keyEntryField", keyEntryDialog);
	}
}
