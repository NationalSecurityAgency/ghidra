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
package ghidra.bitpatterns.gui;

import javax.swing.JPanel;

import docking.DockingWindowManager;
import docking.widgets.label.GLabel;
import docking.widgets.textfield.IntegerTextField;
import ghidra.util.HelpLocation;
import ghidra.util.layout.PairLayout;

/**
 * A provider for the component used to enter the number of total fixed bits and post
 * fixed bits in a pattern file before a set of patterns is exported to XML.
 */
public class BitsInputDialogComponentProvider extends InputDialogComponentProvider {

	private static final String TOTAL_BITS_LABEL = "Total Bits ";
	private static final Long DEFAULT_TOTAL_BITS = 32L;
	private static final String POST_BITS_LABEL = "Post Bits ";
	private static final Long DEFAULT_POST_BITS = 16L;

	private IntegerTextField totalBitsBox;
	private IntegerTextField preBitsBox;

	/**
	 * Create a dialog used for entering number of fixed total and post bits.
	 * @param title title String
	 */
	public BitsInputDialogComponentProvider(String title) {
		super(title);
		JPanel panel = createPanel();
		addWorkPanel(panel);
		addOKButton();
		addCancelButton();
		setDefaultButton(okButton);
		DockingWindowManager.showDialog(null, this);
		HelpLocation helpLocation =
			new HelpLocation("FunctionBitPatternsExplorerPlugin", "Pattern_Clipboard_Tab");
		this.setHelpLocation(helpLocation);
	}

	@Override
	protected JPanel createPanel() {
		JPanel mainPanel = new JPanel();
		PairLayout pairLayout = new PairLayout();
		mainPanel.setLayout(pairLayout);

		mainPanel.add(new GLabel(TOTAL_BITS_LABEL));
		totalBitsBox = new IntegerTextField();
		totalBitsBox.setValue(DEFAULT_TOTAL_BITS);
		mainPanel.add(totalBitsBox.getComponent());

		mainPanel.add(new GLabel(POST_BITS_LABEL));
		preBitsBox = new IntegerTextField();
		preBitsBox.setValue(DEFAULT_POST_BITS);
		mainPanel.add(preBitsBox.getComponent());

		return mainPanel;
	}

	/**
	 * Get the total number of fixed bits a pattern must contain.
	 * @return number of total bits
	 */
	public int getTotalBits() {
		return totalBitsBox.getIntValue();
	}

	/**
	 * Get the number of fixed bits a pattern must contain after a function start.
	 * @return number of post bits
	 */
	public int getPostBits() {
		return preBitsBox.getIntValue();
	}

}
