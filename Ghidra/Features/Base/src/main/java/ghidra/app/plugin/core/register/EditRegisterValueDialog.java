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
package ghidra.app.plugin.core.register;

import java.math.BigInteger;

import javax.swing.*;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import docking.DialogComponentProvider;
import docking.widgets.label.GLabel;
import ghidra.app.util.AddressInput;
import ghidra.app.util.bean.FixedBitSizeValueField;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.util.HelpLocation;
import ghidra.util.MessageType;
import ghidra.util.layout.PairLayout;

class EditRegisterValueDialog extends DialogComponentProvider {

	private AddressInput startAddrField;
	private AddressInput endAddrField;
	private FixedBitSizeValueField registerValueField;
	private boolean wasCancelled = true;

	EditRegisterValueDialog(Register register, Address start, Address end, BigInteger value,
			AddressFactory factory) {
		super("Edit Register Value Range");
		addWorkPanel(buildWorkPanel(register, start, end, value, factory));

		addOKButton();
		addCancelButton();
		setHelpLocation(new HelpLocation("RegisterPlugin", "EditRegisterValues"));
	}

	private JComponent buildWorkPanel(Register register, Address start, Address end,
			BigInteger value, AddressFactory factory) {

		JTextField registerField =
			new JTextField(register.getName() + " (" + register.getBitLength() + ")");
		registerField.setEditable(false);

		startAddrField = new AddressInput();
		endAddrField = new AddressInput();
		ChangeListener changeListener = new ChangeListener() {
			@Override
			public void stateChanged(ChangeEvent e) {
				updateOk();
			}
		};
		startAddrField.setAddressFactory(factory);
		endAddrField.setAddressFactory(factory);
		startAddrField.addChangeListener(changeListener);
		endAddrField.addChangeListener(changeListener);

		registerValueField = new FixedBitSizeValueField(register.getBitLength(), true, false);
		startAddrField.setAddress(start);
		endAddrField.setAddress(end);
		registerValueField.setValue(value);

		JPanel panel = new JPanel(new PairLayout(5, 1));

		panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
		panel.add(new GLabel("Register:"));
		panel.add(registerField);
		panel.add(new GLabel("Start Address:"));
		panel.add(startAddrField);
		panel.add(new GLabel("End Address:"));
		panel.add(endAddrField);
		panel.add(new GLabel("Value:"));
		panel.add(registerValueField);

		return panel;
	}

	protected void updateOk() {
		Address start = startAddrField.getAddress();
		Address end = endAddrField.getAddress();
		AddressSpace startSpace = startAddrField.getAddressSpace();
		AddressSpace endSpace = endAddrField.getAddressSpace();
		setOkEnabled(checkValidAddresses(startSpace, start, endSpace, end));
	}

	private boolean checkValidAddresses(AddressSpace startSpace, Address start,
			AddressSpace endSpace, Address end) {

		if (startSpace != endSpace) {
			setStatusText("Start and end addresses must be in the same address space!",
				MessageType.ERROR);
			return false;
		}

		if (start == null) {
			setStatusText("Please enter a starting address.", MessageType.ERROR);
			return false;
		}

		if (end == null) {
			setStatusText("Please enter an end address.", MessageType.ERROR);
			return false;
		}

		if (start.getAddressSpace() != startSpace) {
			// must be an overlay that is not in the range
			setStatusText("Start offset must be in overlay range [" + startSpace.getMinAddress() +
				", " + startSpace.getMaxAddress() + "]", MessageType.ERROR);
			return false;
		}

		if (end.getAddressSpace() != endSpace) {
			// must be an overlay that is not in the range
			setStatusText("End offset must be in overlay range [" + endSpace.getMinAddress() +
				", " + endSpace.getMaxAddress() + "]", MessageType.ERROR);
			return false;
		}

		if (start.compareTo(end) > 0) {
			setStatusText("Start address must be less than end address!", MessageType.ERROR);
			return false;
		}
		setStatusText("");
		return true;
	}

	@Override
	protected void okCallback() {
		wasCancelled = false;
		close();
	}

	@Override
	protected void cancelCallback() {
		close();
	}

	public boolean wasCancelled() {
		return wasCancelled;
	}

	public Address getStartAddress() {
		return startAddrField.getAddress();
	}

	public Address getEndAddress() {
		return endAddrField.getAddress();
	}

	public BigInteger getValue() {
		return registerValueField.getValue();
	}
}
