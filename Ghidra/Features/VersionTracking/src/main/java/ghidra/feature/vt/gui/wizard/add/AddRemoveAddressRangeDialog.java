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
package ghidra.feature.vt.gui.wizard.add;

import java.awt.Dimension;
import java.util.Objects;
import java.util.function.Consumer;

import javax.swing.*;

import docking.DialogComponentProvider;
import docking.widgets.label.GDLabel;
import ghidra.app.util.AddressInput;
import ghidra.app.util.HelpTopics;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.layout.PairLayout;

public class AddRemoveAddressRangeDialog extends DialogComponentProvider {

	private Program program;
	private Consumer<AddressRange> addressRangeConsumer;

	private JPanel addressRangePanel;
	private JLabel minLabel;
	private JLabel maxLabel;
	private AddressInput minAddressField;
	private AddressInput maxAddressField;

	protected AddRemoveAddressRangeDialog(String type, String programIndicator, Program program,
			Consumer<AddressRange> addressRangeConsumer) {
		super(programIndicator + " Address Range", true, true, true, false);
		this.program = program;
		this.addressRangeConsumer = Objects.requireNonNull(addressRangeConsumer);
		setHelpLocation(new HelpLocation(HelpTopics.LABEL, "AddEditDialog"));
		addWorkPanel(createAddressRangePanel());

		setFocusComponent(minAddressField);

		addOKButton();
		addCancelButton();

		setOkButtonText(type);
		setDefaultButton(okButton);
	}

	private JPanel createAddressRangePanel() {
		addressRangePanel = new JPanel();
		addressRangePanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 0, 0));
		addressRangePanel.setLayout(new PairLayout(5, 5));

		minLabel = new GDLabel("Minimum:");
		minLabel.setToolTipText("Enter minimum address to add or remove");
		addressRangePanel.add(minLabel);

		minAddressField = new AddressInput(program);
		Dimension minPreferredSize = getPreferredSize();
		minPreferredSize.width = 200;
		minAddressField.setPreferredSize(minPreferredSize);
		addressRangePanel.add(minAddressField);

		maxLabel = new GDLabel("Maximum:");
		maxLabel.setToolTipText("Enter maximum address to add or remove");
		addressRangePanel.add(maxLabel);

		maxAddressField = new AddressInput(program);
		Dimension maxPreferredSize = getPreferredSize();
		maxPreferredSize.width = 200;
		minAddressField.setPreferredSize(maxPreferredSize);
		addressRangePanel.add(maxAddressField);

		return addressRangePanel;
	}

	@Override
	protected void dialogShown() {
		super.dialogShown();
		minAddressField.clear();
		maxAddressField.clear();
		minAddressField.requestFocus();
	}

	/**
	 * This method gets called when the user clicks on the OK Button.  The base
	 * class calls this method.
	 */
	@Override
	protected void okCallback() {
		if (isValidRange()) {
			addressRangeConsumer.accept(new AddressRangeImpl(getMinAddress(), getMaxAddress()));
			close();
		}
	}

	private boolean isValidRange() {
		Address minAddress = getMinAddress();
		if (minAddress == null) {
			setStatusText("Specify a minimum address.");
			return false;
		}
		Address maxAddress = getMaxAddress();
		if (maxAddress == null) {
			setStatusText("Specify a maximum address.");
			return false;
		}
		if (!minAddress.getAddressSpace().equals(maxAddress.getAddressSpace())) {
			setStatusText("Min and Max must be in same address space.");
			return false;
		}
		if (minAddress.compareTo(maxAddress) > 0) {
			setStatusText("Max address must be greater than Min address.");
			return false;
		}
		return true;
	}

	private Address getMinAddress() {
		return minAddressField.getAddress();
	}

	private Address getMaxAddress() {
		return maxAddressField.getAddress();
	}
}
