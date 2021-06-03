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
package docking.widgets.dialogs;

import javax.swing.JButton;
import javax.swing.JTextField;

import org.junit.After;

import docking.DockingWindowManager;
import docking.test.AbstractDockingTest;
import docking.widgets.textfield.IntegerTextField;

public abstract class AbstractNumberInputDialogTest extends AbstractDockingTest {

	protected AbstractNumberInputDialog dialog;
	protected JButton okButton;
	protected JTextField textField;

	@After
	public void tearDown() throws Exception {
		if (dialog != null) {
			runSwing(() -> dialog.close());
		}
	}

	protected void createAndShowDialog(int initialValue, int min, int max) {
		dialog = new NumberInputDialog(null, initialValue, min, max);
		showDialogOnSwingWithoutBlocking(dialog);
		okButton = (JButton) getInstanceField("okButton", dialog);
		textField = getTextFieldForDialog(dialog);
	}

	protected void createAndShowDialog(int initial, int min) {
		dialog = new NumberInputDialog(null, initial, min);
		showDialogOnSwingWithoutBlocking(dialog);
		okButton = (JButton) getInstanceField("okButton", dialog);
		textField = getTextFieldForDialog(dialog);
	}

	protected void oK() {
		runSwing(() -> okButton.doClick());
	}

	protected void setText(String value) {
		setText(textField, value);
	}

	protected void showDialogOnSwingWithoutBlocking(AbstractNumberInputDialog theDialog) {

		runSwing(() -> {

			DockingWindowManager.showDialog(theDialog);
		}, false);

		waitForDialogComponent(AbstractNumberInputDialog.class);
	}

	protected JTextField getTextFieldForDialog(AbstractNumberInputDialog theDialog) {
		IntegerTextField inputField = theDialog.getNumberInputField();
		return (JTextField) getInstanceField("textField", inputField);
	}
}
