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
package ghidra.app.util.dialog;

import java.awt.BorderLayout;

import javax.swing.BorderFactory;
import javax.swing.JPanel;

import docking.DialogComponentProvider;
import docking.DockingWindowManager;
import docking.widgets.label.GLabel;
import ghidra.app.util.AddressInput;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;

public class AskAddrDialog extends DialogComponentProvider {
	private boolean isCanceled;
	private AddressInput addrInput;

	public AskAddrDialog(final String title, final String message, AddressFactory af,
			Address lastAddr) {
		super(title, true, true, true, false);

		addrInput = new AddressInput();
		addrInput.setAddressFactory(af);
		addrInput.selectDefaultAddressSpace();
		if (lastAddr != null) {
			addrInput.setAddress(lastAddr);
		}
		addrInput.select();

		JPanel panel = new JPanel(new BorderLayout(10, 10));
		panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
		panel.add(new GLabel(message), BorderLayout.WEST);
		panel.add(addrInput, BorderLayout.CENTER);

		addWorkPanel(panel);
		addOKButton();
		addCancelButton();
		setDefaultButton(okButton);

		DockingWindowManager.showDialog(null, this);
	}

	@Override
	protected void okCallback() {
		isCanceled = false;
		if (addrInput.getAddress() == null) {
			setStatusText("Please enter a valid ADDRESS.");
			return;
		}
		close();
	}

	@Override
	protected void cancelCallback() {
		isCanceled = true;
		close();
	}

	public boolean isCanceled() {
		return isCanceled;
	}

	public Address getValueAsAddress() {
		return addrInput.getAddress();
	}
}
