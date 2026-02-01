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
package ghidra.util.charset.picker;

import docking.DialogComponentProvider;
import docking.DockingWindowManager;
import ghidra.util.HelpLocation;
import ghidra.util.charset.CharsetInfo;

/**
 * Dialog that displays a charset picker table and lets the user press ok or cancel.
 * <p>
 * Call {@link #getSelectedCharset()} after the dialog closes to get the selected value.
 */
public class CharsetPickerDialog extends DialogComponentProvider {

	/**
	 * Allows user to pick a charset from a table in a modal dialog.
	 * 
	 * @param defaultCSI default charset to initially select in the table
	 * @return selected charset, or null if canceled
	 */
	public static CharsetInfo pickCharset(CharsetInfo defaultCSI) {
		CharsetPickerDialog dlg = new CharsetPickerDialog();
		dlg.setSelectedCharset(defaultCSI);
		DockingWindowManager.showDialog(dlg);
		return dlg.getSelectedCharset();
	}

	private CharsetPickerPanel panel;
	private CharsetInfo csi;

	public CharsetPickerDialog() {
		super("Pick Charset", true, false, true, false);

		panel = new CharsetPickerPanel(null);
		addWorkPanel(panel);
		addOKButton();
		addCancelButton();
		setDefaultSize(800, 800);
		setRememberLocation(false);
		setHelpLocation(new HelpLocation("Charsets", "CharsetPicker"));
	}

	@Override
	protected void okCallback() {
		this.csi = panel.getSelectedCharset();
		close();
	}

	@Override
	protected void cancelCallback() {
		this.csi = null;
		super.cancelCallback();
	}

	public void setSelectedCharset(CharsetInfo csi) {
		panel.setSelectedCharset(csi);
	}

	public CharsetInfo getSelectedCharset() {
		return csi;
	}

}
