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
package docking.widgets.values;

import javax.swing.JButton;
import javax.swing.JTextField;

import docking.DialogComponentProvider;
import docking.DockingWindowManager;
import docking.test.AbstractDockingTest;

public abstract class AbstractValueTest extends AbstractDockingTest {

	protected ValuesMapDialog dialog;
	protected GValuesMap values = new GValuesMap();

	protected void showDialogOnSwingWithoutBlocking() {

		runSwing(() -> {
			dialog = new ValuesMapDialog("Test", null, values);
			DockingWindowManager.showDialog(dialog);
		}, false);

		waitForDialogComponent(DialogComponentProvider.class);
	}

	protected void setTextOnComponent(AbstractValue<?> nameValue, String text) {
		runSwing(() -> {
			JTextField field = (JTextField) nameValue.getComponent();
			field.setText(text);
		});
	}

	protected void pressOk() {
		JButton okButton = (JButton) getInstanceField("okButton", dialog);
		runSwing(() -> okButton.doClick());
	}

	protected void pressCancel() {
		JButton okButton = (JButton) getInstanceField("cancelButton", dialog);
		runSwing(() -> okButton.doClick());
	}

}
