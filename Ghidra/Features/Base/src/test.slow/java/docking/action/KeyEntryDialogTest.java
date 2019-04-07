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

import javax.swing.*;

import org.junit.*;

import docking.*;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.data.DataPlugin;
import ghidra.app.plugin.core.function.FunctionPlugin;
import ghidra.app.plugin.core.memory.MemoryMapPlugin;
import ghidra.app.plugin.core.navigation.GoToAddressLabelPlugin;
import ghidra.app.plugin.core.navigation.NavigationHistoryPlugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;

public class KeyEntryDialogTest extends AbstractGhidraHeadedIntegrationTest {

	private PluginTool tool;
	private TestEnv env;
	private KeyEntryDialog keyEntryDialog;
	private JTextPane collisionPane;
	private KeyEntryTextField keyEntryField;

	@Before
	public void setUp() throws Exception {

		env = new TestEnv();
		tool = env.getTool();
		tool.addPlugin(NavigationHistoryPlugin.class.getName());
		tool.addPlugin(CodeBrowserPlugin.class.getName());
		tool.addPlugin(MemoryMapPlugin.class.getName());
		tool.addPlugin(GoToAddressLabelPlugin.class.getName());
		tool.addPlugin(DataPlugin.class.getName());
		tool.addPlugin(FunctionPlugin.class.getName());

		env.showTool();
	}

	@After
	public void tearDown() throws Exception {
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

	private void pressDialogOK() {
		JButton okButton = (JButton) getInstanceField("okButton", keyEntryDialog);
		pressButton(okButton);
	}

	private void pressDialogCancel() {
		JButton cancelButton = (JButton) getInstanceField("cancelButton", keyEntryDialog);
		pressButton(cancelButton);
	}

	public DockingAction getKeyBindingAction() {
		DockingWindowManager dwm = DockingWindowManager.getInstance(tool.getToolFrame());
		DockingActionManager dockingActionManager =
			(DockingActionManager) getInstanceField("actionManager", dwm);
		return (DockingAction) getInstanceField("keyBindingsAction", dockingActionManager);
	}

	private void showDialog(final DockingAction actionToEdit) throws Exception {
		final DockingAction keyBindingAction = getKeyBindingAction();
		executeOnSwingWithoutBlocking(() -> {
			DockingWindowManager.setMouseOverAction(actionToEdit);
			performAction(keyBindingAction, false);
		});

		keyEntryDialog = waitForDialogComponent(tool.getToolFrame(), KeyEntryDialog.class, 2000);
		assertNotNull(keyEntryDialog);

		collisionPane = (JTextPane) getInstanceField("collisionPane", keyEntryDialog);
		keyEntryField = (KeyEntryTextField) getInstanceField("keyEntryField", keyEntryDialog);
	}
}
