/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.plugin.core.references;

import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.symbol.Reference;
import ghidra.util.Msg;
import ghidra.util.NumericUtilities;

import java.awt.KeyboardFocusManager;

import javax.swing.JPanel;
import javax.swing.SwingUtilities;

abstract class EditReferencePanel extends JPanel {
	
	EditReferencePanel(String name) {
		super();
		setName(name);
	}
	
	/**
	 * Initialize panel content with existing reference.
	 * This initialization is used when editing an existing reference.
	 * @param fromCodeUnit reference source
	 * @param ref existing reference from te specified fromCodeUnit
	 */
	abstract void initialize(CodeUnit fromCodeUnit, Reference ref);
	
	/**
	 * Initialize panel content based upon specified fromCodeUnit and opIndex.
	 * This initialization is used when adding a new reference.
	 * @param fromCodeUnit reference source
	 * @param opIndex reference source operand
	 * @param fromSubIndex a valid sub-operand index corresponding to the fromOpIndex.  If -1
	 * the current location will be used instead of analyzing the from-operand.
	 * @return true if panel can support specified code unit and operand
	 */
	abstract boolean initialize(CodeUnit fromCodeUnit, int opIndex, int subOpIndex);
	
	/**
	 * Add/Update reference callback
	 * @return true if reference added
	 */
	abstract boolean applyReference();
	
	/**
	 * Cleanup any program resource held.
	 */
	abstract void cleanup();

	/**
	 * Attempt to switch the current Operand index.
	 * @param opIndex
	 * @return true if successful, false if operand not supported
	 */
	abstract boolean setOpIndex(int opIndex);

	/**
	 * Returns true if the current state is valid for the 
	 * current fromCodeUnit, opIndex and/or reference data.
	 */
	abstract boolean isValidContext();
	
	/**
	 * Display input error
	 * @param error error message
	 */
	protected void showInputErr(String error) {
		Msg.showError(this, this, "Reference Input Error", error);
	}
	
	/**
	 * Places focus in the first focusable component within this panel.
	 * @see java.awt.Component#requestFocus()
	 */
	@Override
    public void requestFocus() {
		SwingUtilities.invokeLater(new Runnable() {
			public void run() {
				KeyboardFocusManager kfm = KeyboardFocusManager.getCurrentKeyboardFocusManager();
				kfm.focusNextComponent(EditReferencePanel.this);
			}
		});
	}

	/**
	 * Provides flexible parsing of a decimal or hexidecimal value
	 * where hex values are prefixed by '0x'.  A sign prefix may be specified 
	 * first (+ or -).
	 * @param str input string
	 * @return parsed value
	 * @throws NumberFormatException if unable to parse value
	 */
	protected long parseLongInput(String str) throws NumberFormatException {
		
		if (str == null) {
			throw new NumberFormatException();
		}
		str = str.trim().toLowerCase();
		try {
			int ix = 0;
			char c = str.charAt(0);
			boolean neg = (c == '-');
			if (neg || c == '+') {
				++ix;
			}
			if (str.substring(ix).startsWith("0x")) {
				long val = NumericUtilities.parseHexLong(str.substring(ix+2));
				return neg ? -val : val;
			}
		}
		catch (IndexOutOfBoundsException e) {
			throw new NumberFormatException();
		}
		
		return Long.parseLong(str);
	}
	
}
