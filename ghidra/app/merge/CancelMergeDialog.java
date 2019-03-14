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
package ghidra.app.merge;

import java.awt.Component;

import javax.swing.Icon;
import javax.swing.ImageIcon;

import docking.widgets.OptionDialog;

public class CancelMergeDialog extends OptionDialog {

	public CancelMergeDialog(Icon icon) {
		super("Confirm Cancel Merge",
			"Warning!  Cancel causes the entire merge process to be canceled.\n" +
					"Do you want to cancel the Merge Process?",
					"Yes", null, OptionDialog.PLAIN_MESSAGE, icon, true, "No");
		setFocusComponent(cancelButton);
	}

	public static int showYesNoDialog(Component parent, ImageIcon icon) {
		CancelMergeDialog dialog = new CancelMergeDialog(icon);
		dialog.show(parent);
		return dialog.getResult();
	}

}
