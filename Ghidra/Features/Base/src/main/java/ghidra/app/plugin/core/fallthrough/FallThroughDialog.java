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
package ghidra.app.plugin.core.fallthrough;

import java.awt.*;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import docking.DialogComponentProvider;
import docking.widgets.button.GRadioButton;
import docking.widgets.label.GDLabel;
import generic.theme.Gui;
import ghidra.app.util.AddressInput;
import ghidra.program.model.address.Address;
import ghidra.util.HelpLocation;
import resources.Icons;

/**
 * Dialog to prompt for overriding a fallthrough address on an instruction.
 */
class FallThroughDialog extends DialogComponentProvider implements ChangeListener {

	private JLabel addressLabel;
	private JLabel instLabel;
	private JButton homeButton;
	private FallThroughPlugin plugin;
	private FallThroughModel model;
	private AddressInput addrField;
	private JRadioButton defaultRB;
	private JRadioButton userRB;
	private boolean changing;

	FallThroughDialog(FallThroughPlugin plugin, FallThroughModel model) {
		super("Set Fallthrough Address", true);
		setHelpLocation(new HelpLocation(plugin.getName(), "Set Fallthrough"));
		this.plugin = plugin;
		this.model = model;
		addWorkPanel(create());
		addOKButton();
		addApplyButton();
		addCancelButton();
		updateState();
		model.setChangeListener(this);
	}

	@Override
	protected void applyCallback() {
		model.execute();
	}

	@Override
	protected void cancelCallback() {
		close();
	}

	@Override
	protected void okCallback() {
		if (model.execute()) {
			cancelCallback();
		}
	}

	public void updateState() {
		Address addr = model.getAddress();
		if (addr == null) {
			cancelCallback();
			return;
		}

		changing = true;
		addressLabel.setText(addr.toString());
		instLabel.setText(model.getInstructionRepresentation());

		if (model.isDefaultFallthrough()) {
			defaultRB.setSelected(true);
		}
		else if (model.isUserDefinedFallthrough()) {
			userRB.setSelected(true);
		}

		Address ftAddr = model.getCurrentFallthrough();
		if (ftAddr != null) {
			if (!ftAddr.equals(addrField.getAddress())) {
				addrField.setAddress(ftAddr);
			}
		}
		else {
			addrField.clear();
		}
		boolean enabled = model.allowAddressEdits();
		addrField.setEnabled(enabled);

		changing = false;
		if (model.isValidInput()) {
			setOkEnabled(true);
			setApplyEnabled(true);
		}
		String msg = model.getMessage();
		if (msg != null) {
			setStatusText(msg);
		}
	}

	private void addressChanged(Address address) {
		if (changing) {
			return;
		}

		Runnable r = () -> {
			if (address != null || addrField.getText().length() == 0) {
				model.setCurrentFallthrough(address);
			}
			else {
				setStatusText("Invalid Address");
				setOkEnabled(false);
				setApplyEnabled(false);
			}
		};
		SwingUtilities.invokeLater(r);
	}

	private JPanel create() {
		JPanel panel = new JPanel(new BorderLayout(0, 10));
		panel.setBorder(BorderFactory.createEmptyBorder(5, 0, 0, 0));
		addrField = new AddressInput(model.getProgram(), this::addressChanged);
		addrField.addActionListener(e -> model.setCurrentFallthrough(addrField.getAddress()));
		panel.add(createHomePanel(), BorderLayout.NORTH);
		panel.add(createAddressPanel(), BorderLayout.CENTER);
		return panel;
	}

	private JPanel createAddressPanel() {
		JPanel panel = new JPanel(new BorderLayout());
		panel.setBorder(BorderFactory.createTitledBorder("Fallthrough Address"));

		panel.add(addrField, BorderLayout.NORTH);
		panel.add(createRadioButtonPanel(), BorderLayout.CENTER);
		return panel;
	}

	private JPanel createHomePanel() {
		JPanel panel = new JPanel(new BorderLayout());
		panel.setBorder(new TitledBorder("Home"));

		addressLabel = new GDLabel("01001000");

		Font monoFont = Gui.getFont("font.monospaced");
		addressLabel.setFont(monoFont);

		instLabel = new GDLabel("jmp DAT_01001000");
		instLabel.setFont(monoFont);

		homeButton = createButton("Home");
		homeButton.addActionListener(e -> plugin.goTo(model.getAddress()));

		JPanel innerPanel = new JPanel();
		BoxLayout bl = new BoxLayout(innerPanel, BoxLayout.X_AXIS);
		innerPanel.setLayout(bl);

		innerPanel.add(Box.createHorizontalStrut(5));
		innerPanel.add(homeButton);
		innerPanel.add(Box.createHorizontalStrut(10));
		innerPanel.add(addressLabel);
		innerPanel.add(Box.createHorizontalStrut(20));
		innerPanel.add(instLabel);
		innerPanel.add(Box.createHorizontalStrut(10));
		panel.add(innerPanel, BorderLayout.CENTER);
		return panel;
	}

	private JPanel createRadioButtonPanel() {

		JPanel panel = new JPanel();
		BoxLayout bl = new BoxLayout(panel, BoxLayout.X_AXIS);
		panel.setLayout(bl);

		ButtonGroup group = new ButtonGroup();
		defaultRB = new GRadioButton("Default", true);
		defaultRB.addActionListener(ev -> model.defaultSelected());
		defaultRB.setToolTipText("Use default fallthrough address");

		userRB = new GRadioButton("User", false);
		userRB.addActionListener(ev -> model.userSelected());
		userRB.setToolTipText("Override default fallthrough address");

		group.add(defaultRB);
		group.add(userRB);

		panel.add(defaultRB);
		panel.add(userRB);

		JPanel outerPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
		outerPanel.add(panel);
		return outerPanel;
	}

	private JButton createButton(String altText) {
		JButton button = new JButton();
		Icon icon = Icons.HOME_ICON;
		button = new JButton(icon);
		Insets noInsets = new Insets(0, 0, 0, 0);
		button.setMargin(noInsets);

		button.setToolTipText("Go back to home address");
		return button;
	}

	@Override
	public void stateChanged(ChangeEvent e) {
		updateState();
	}

}
