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

import java.awt.Component;

import javax.swing.JPanel;

import docking.DockingWindowManager;
import docking.widgets.label.GLabel;
import docking.widgets.textfield.IntegerTextField;
import ghidra.bitpatterns.info.ByteSequenceLengthFilter;
import ghidra.util.HelpLocation;
import ghidra.util.layout.PairLayout;

/**
 * Objects of this class are used to display a panel which allows the user to 
 * input the parameters for a {@link ByteSequenceLengthFilter}.
 */

public class ByteSequenceLengthFilterInputDialog extends InputDialogComponentProvider {

	private IntegerTextField indexBox;
	private IntegerTextField minLengthBox;
	private static final String INDEX_BOX_TITLE_TEXT =
		"Prefix Length in Bytes (Negative for Suffix): ";
	private static final String LENGTH_BOX_TITLE_TEXT = "Minimum Length in Bytes of String:";
	private static final String OK_BUTTON_TEXT = "Apply";

	/**
	 * Creates a dialog for entering data for a length filter
	 * @param title title of dialog
	 * @param parent parent component
	 */
	protected ByteSequenceLengthFilterInputDialog(String title, Component parent) {
		super(title);

		JPanel panel = createPanel();
		addWorkPanel(panel);
		addOKButton();
		okButton.setText(OK_BUTTON_TEXT);
		addCancelButton();
		setDefaultButton(okButton);
		HelpLocation helpLocation =
			new HelpLocation("FunctionBitPatternsExplorerPlugin", "Length_Filters");
		setHelpLocation(helpLocation);
		DockingWindowManager.showDialog(parent, this);
	}

	@Override
	protected JPanel createPanel() {
		JPanel mainPanel = new JPanel();
		PairLayout pairLayout = new PairLayout();
		mainPanel.setLayout(pairLayout);
		mainPanel.add(new GLabel(INDEX_BOX_TITLE_TEXT));
		indexBox = new IntegerTextField();
		mainPanel.add(indexBox.getComponent());
		mainPanel.add(new GLabel(LENGTH_BOX_TITLE_TEXT));
		minLengthBox = new IntegerTextField();
		mainPanel.add(minLengthBox.getComponent());
		return mainPanel;
	}

	/**
	 * Returns a new {@link ByteSequenceLengthFilter} based on the values in the minimum length filed and the index field.
	 * @return a {@link ByteSequenceLengthFilter} if the value in the minimum length field is >= the value in the index 
	 * field, otherwise {@code null}
	 */
	public ByteSequenceLengthFilter getValue() {
		int index = indexBox.getIntValue();
		int minLength = minLengthBox.getIntValue();
		if (index > minLength) {
			return null;
		}
		try {
			return new ByteSequenceLengthFilter(index, minLength);
		}
		catch (IllegalArgumentException e) {
			return null;
		}
	}

}
