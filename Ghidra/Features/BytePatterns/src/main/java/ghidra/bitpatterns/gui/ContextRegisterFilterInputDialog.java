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
import java.math.BigInteger;
import java.util.*;

import javax.swing.*;

import docking.DockingWindowManager;
import docking.widgets.combobox.GhidraComboBox;
import ghidra.bitpatterns.info.ContextRegisterExtent;
import ghidra.bitpatterns.info.ContextRegisterFilter;
import ghidra.util.HelpLocation;
import ghidra.util.layout.PairLayout;

/**
 * 
 *  Objects of this class provide a pop-up window for the user to create a context register filter.
 *
 */

public class ContextRegisterFilterInputDialog extends InputDialogComponentProvider {

	private static final int TEXT_FIELD_COLUMNS = 10;
	private Map<String, GhidraComboBox<RegisterValueWrapper>> regsToBoxes;
	private ContextRegisterExtent extent;

	/**
	 * Creates an {@link InputDialogComponentProvider} for defining a {@link ContextRegisterFilter}
	 * @param title title of dialog
	 * @param extent extent contain all possible values for the context registers
	 * @param parent parent component
	 */
	public ContextRegisterFilterInputDialog(String title, ContextRegisterExtent extent,
			Component parent) {
		super(title);

		this.extent = extent;
		regsToBoxes = new HashMap<String, GhidraComboBox<RegisterValueWrapper>>();

		JPanel panel = createPanel();
		addWorkPanel(panel);
		addOKButton();
		okButton.setText("Apply");
		addCancelButton();
		setDefaultButton(okButton);
		HelpLocation helpLocation =
			new HelpLocation("FunctionBitPatternsExplorerPlugin", "Context_Register_Filters");
		setHelpLocation(helpLocation);

		DockingWindowManager.showDialog(parent, this);

	}

	@Override
	protected JPanel createPanel() {
		JPanel panel = new JPanel();
		BoxLayout boxLayout = new BoxLayout(panel, BoxLayout.Y_AXIS);
		panel.setLayout(boxLayout);
		panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
		for (String currentRegister : extent.getContextRegisters()) {
			JPanel currentRegPanel = new JPanel();
			PairLayout pairLayout = new PairLayout();
			currentRegPanel.setLayout(pairLayout);
			JTextField currentTextField = new JTextField(currentRegister, TEXT_FIELD_COLUMNS);
			currentTextField.setEditable(false);
			currentRegPanel.add(currentTextField);
			List<BigInteger> regValues = extent.getValuesForRegister(currentRegister);
			RegisterValueWrapper[] valueArray = new RegisterValueWrapper[regValues.size() + 1];
			valueArray[0] = new RegisterValueWrapper(null);
			for (int i = 1; i < regValues.size() + 1; ++i) {
				valueArray[i] = new RegisterValueWrapper(regValues.get(i - 1));
			}
			GhidraComboBox<RegisterValueWrapper> currentCombo =
				new GhidraComboBox<RegisterValueWrapper>(valueArray);
			currentRegPanel.add(currentCombo);
			panel.add(currentRegPanel);
			regsToBoxes.put(currentRegister, currentCombo);
		}
		return panel;
	}

	/**
	 * Creates a {@link ContextRegisterFilter} based on the values entered by the user
	 * @return the {@link ContextRegisterFilter}
	 */
	public ContextRegisterFilter getFilter() {
		if (isCanceled) {
			return null;
		}
		ContextRegisterFilter registerFilter = new ContextRegisterFilter();
		for (String currentRegister : regsToBoxes.keySet()) {
			BigInteger value = ((RegisterValueWrapper) regsToBoxes.get(
				currentRegister).getSelectedItem()).getValue();
			if (value != null) {
				registerFilter.addRegAndValueToFilter(currentRegister, value);
			}
		}
		return registerFilter;
	}

}
