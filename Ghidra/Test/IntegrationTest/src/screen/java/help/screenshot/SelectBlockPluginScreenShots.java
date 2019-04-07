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
package help.screenshot;

import javax.swing.JRadioButton;
import javax.swing.JTextField;

import org.junit.Test;

import docking.DialogComponentProvider;

public class SelectBlockPluginScreenShots extends GhidraScreenShotGenerator {

	public SelectBlockPluginScreenShots() {
		super();
	}

@Test
    public void testDialog() {

		performAction("SelectBlock", "SelectBlockPlugin", false);

		captureDialog();
	}

@Test
	public void testToBadAddr() {

		performAction("SelectBlock", "SelectBlockPlugin", false);

		DialogComponentProvider dialog = getDialog();

		JRadioButton toButton = (JRadioButton) getInstanceField("toButton", dialog);
		clickButton(toButton);
		waitForSwing();

		JTextField addressField = (JTextField) getInstanceField("toAddressField", dialog);
		enableTextField(addressField);
		waitForSwing();

		setText(addressField, "foobar");

		pressButtonByText(dialog, "Select Bytes");

		captureDialog();
	}

	private void clickButton(final JRadioButton button) {

		runSwing(new Runnable() {

			@Override
			public void run() {
				button.setSelected(true);

			}
		});
	}

	private void enableTextField(final JTextField field) {

		runSwing(new Runnable() {

			@Override
			public void run() {
				field.setEditable(true);
				field.setEnabled(true);
			}
		});
	}
}
