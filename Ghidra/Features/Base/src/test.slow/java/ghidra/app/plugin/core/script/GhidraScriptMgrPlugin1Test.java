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

import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;

import javax.swing.*;
import javax.swing.table.TableColumn;

import org.junit.Test;

import docking.DockingUtils;
import docking.action.DockingActionIf;
import docking.actions.KeyBindingUtils;
import docking.actions.ToolActions;
import docking.widgets.DropDownTextField;
import docking.widgets.DropDownTextFieldDataModel.SearchMode;
import ghidra.util.TaskUtilities;

public class GhidraScriptMgrPlugin1Test extends AbstractGhidraScriptMgrPluginTest {

	@Test
	public void testRunLastScriptAction() throws Exception {

		assertRunLastActionEnabled(false);

		//
		// Run a script once...
		//
		String initialScriptName = "HelloWorldScript.java";
		selectScript(initialScriptName);
		String fullOutput = runSelectedScript(initialScriptName);
		String expectedOutput = "Hello World";
		assertTrue("Script did not run - output: " + fullOutput,
			fullOutput.indexOf(expectedOutput) != -1);

		//
		// Run the script again
		//
		assertRunLastActionEnabled(true);
		fullOutput = runLastScript(initialScriptName);
		assertTrue("Did not rerun last run script", fullOutput.indexOf(expectedOutput) != -1);

		//
		// Now select and run another script
		//
		String secondScriptName = "FormatExampleScript.java";
		selectScript(secondScriptName);
		fullOutput = runSelectedScript(secondScriptName);
		expectedOutput = "jumped over the";
		assertTrue("Script did not run - output: " + fullOutput,
			fullOutput.indexOf(expectedOutput) != -1);

		//
		// Run the script again
		//
		assertRunLastActionEnabled(true);
		fullOutput = runLastScript(secondScriptName);
		assertTrue("Did not rerun last run script", fullOutput.indexOf(expectedOutput) != -1);
	}

	@Test
	public void testRunLastScriptActionWithDifferentRowSelected() throws Exception {

		//
		// Run a script once...
		//
		String scriptName = "HelloWorldScript.java";
		selectScript(scriptName);
		String fullOutput = runSelectedScript(scriptName);
		String expectedOutput = "Hello World";
		assertTrue("Script did not run - output: " + fullOutput,
			fullOutput.indexOf(expectedOutput) != -1);

		selectScript("PrintStructureScript.java");// note: this script will error out

		//
		// Run the script again
		//
		fullOutput = runLastScript(scriptName);
		assertTrue("Did not rerun last run script", fullOutput.indexOf(expectedOutput) != -1);
	}

	@Test
	public void testRunLastScriptActionWithScriptProviderClosed() throws Exception {
		//
		// Run a script once...
		//
		String scriptName = "HelloWorldScript.java";
		selectScript(scriptName);
		String fullOutput = runSelectedScript(scriptName);
		String expectedOutput = "Hello World";
		assertTrue("Script did not run - output: " + fullOutput,
			fullOutput.indexOf(expectedOutput) != -1);

		closeScriptProvider();

		//
		// Run the script again
		//
		fullOutput = runLastScript(scriptName);
		assertTrue("Did not rerun last run script", fullOutput.indexOf(expectedOutput) != -1);
	}

	@Test
	public void testAddKeyBindingToScript() throws Exception {

		//
		// Adding a key binding to a script will not only supply a key bindings, but will also
		// add an action to the tool.
		//

		String scriptName = "HelloWorldPopupScript.java";
		selectScript(scriptName);

		KeyBindingInputDialog kbDialog = pressKeyBindingAction();
		KeyStroke newKs = KeyStroke.getKeyStroke(KeyEvent.VK_E,
			DockingUtils.CONTROL_KEY_MODIFIER_MASK | InputEvent.SHIFT_DOWN_MASK);
		runSwing(() -> kbDialog.setKeyStroke(newKs));
		pressButtonByText(kbDialog.getComponent(), "OK");

		// verify the table updated
		assertColumnValue("In Tool", Boolean.TRUE);
		assertColumnValue("Key", KeyBindingUtils.parseKeyStroke(newKs));

		// verify the action is in the tool
		DockingActionIf toolAction = getAction(plugin, scriptName);
		assertNotNull(toolAction);
		KeyStroke actionKs = toolAction.getKeyBinding();
		assertEquals(newKs, actionKs);

		ToolActions toolActions = (ToolActions) plugin.getTool().getToolActions();
		Action toolActionByKeyStroke = toolActions.getAction(newKs);
		assertNotNull(toolActionByKeyStroke);
	}

	@Test
	public void testScriptQuickChooser() throws Exception {

		ScriptSelectionDialog dialog = launchQuickChooser();

		String scriptName = "HelloWorldScript";
		pickScript(dialog, scriptName, "HelloWorldScript.java");

		String output = getConsoleText();

		String expectedOutput = "Hello World";
		assertTrue("Script did not run - output: " + output,
			output.indexOf(expectedOutput) != -1);
	}

	@Test
	public void testScriptQuickLaunch_WithGlobbing() throws Exception {

		ScriptSelectionDialog dialog = launchQuickChooser();

		String scriptName = "Hello*dScr";
		pickScript(dialog, scriptName, "HelloWorldScript.java");

		String output = getConsoleText();

		String expectedOutput = "Hello World";
		assertTrue("Script did not run - output: " + output,
			output.indexOf(expectedOutput) != -1);
	}

//==================================================================================================
// Private Methods 
//==================================================================================================	

	private void pickScript(ScriptSelectionDialog dialog, String userText, String scriptName) {
		DropDownTextField<?> textField =
			(DropDownTextField<?>) findComponent(dialog.getComponent(), JTextField.class);

		runSwing(() -> textField.setSearchMode(SearchMode.WILDCARD));

		triggerText(textField, userText);

		TaskListenerFlag taskFlag = new TaskListenerFlag(scriptName);
		TaskUtilities.addTrackedTaskListener(taskFlag);

		triggerEnter(textField);

		waitForTaskEnd(taskFlag);
	}

	private ScriptSelectionDialog launchQuickChooser() {
		DockingActionIf action = getAction(env.getTool(), "Script Quick Launch");
		performAction(action, false);
		return waitForDialogComponent(ScriptSelectionDialog.class);
	}

	private void assertColumnValue(String columnName, Object expectedValue) {
		int row = scriptTable.getSelectedRow();

		TableColumn column = scriptTable.getColumn(columnName);
		int modelIndex = column.getModelIndex();
		int columnIndex = scriptTable.convertColumnIndexToView(modelIndex);

		Object actualValue = runSwing(() -> scriptTable.getValueAt(row, columnIndex));
		assertEquals(
			"Column value is not as expected for row/col: " + row + "/" + columnIndex +
				" for column '" + columnName + "'",
			expectedValue.toString(), actualValue.toString());
	}

	/*
	 * TODO Tests missing  
	 * 	ScriptAction has odd behavior (code coverage should expose the lack of tests):
	 * 		-test that a script with a meta data key binding
	 * 		-test that a user can add a key binding to a script with a meta data key binding
	 * 		-test that a user can clear a GUI-assigned key binding and that the value 
	 * 			defined in the meta data will still be used
	 */
}
