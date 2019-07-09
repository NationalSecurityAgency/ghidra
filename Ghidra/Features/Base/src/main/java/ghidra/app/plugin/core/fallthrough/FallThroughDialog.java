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
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.net.URL;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import docking.DialogComponentProvider;
import docking.widgets.button.GRadioButton;
import docking.widgets.label.GDLabel;
import ghidra.app.util.AddressInput;
import ghidra.program.model.address.Address;
import ghidra.util.HelpLocation;
import resources.ResourceManager;

/**
 * Dialog to prompt for overriding a fallthrough address on an
 * instruction.
 * 
 * 
 * 
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

	/**
	 * @see ghidra.util.bean.GhidraDialog#applyCallback()
	 */
	@Override
	protected void applyCallback() {
		model.execute();
	}

	/**
	 * @see ghidra.util.bean.GhidraDialog#cancelCallback()
	 */
	@Override
	protected void cancelCallback() {
		close();
	}

	/**
	 * @see ghidra.util.bean.GhidraDialog#okCallback()
	 */
	@Override
	protected void okCallback() {
		if (model.execute()) {
			cancelCallback();
		}
	}

	/**
	 * @see javax.swing.event.ChangeListener#stateChanged(javax.swing.event.ChangeEvent)
	 */
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

	private void addressChanged() {
		if (changing) {
			return;
		}

		Runnable r = new Runnable() {
			@Override
			public void run() {
				Address addr = addrField.getAddress();
				if (addr != null || addrField.getValue().length() == 0) {
					model.setCurrentFallthrough(addr);
				}
				else {
					setStatusText("Invalid Address");
					setOkEnabled(false);
					setApplyEnabled(false);
				}
			}
		};
		SwingUtilities.invokeLater(r);
	}

	private JPanel create() {
		JPanel panel = new JPanel(new BorderLayout(0, 10));
		panel.setBorder(BorderFactory.createEmptyBorder(5, 0, 0, 0));
		addrField = new AddressInput();
		addrField.setAddressFactory(model.getProgram().getAddressFactory());
		addrField.addChangeListener(new ChangeListener() {
			@Override
			public void stateChanged(ChangeEvent e) {
				addressChanged();
			}
		});
		addrField.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				model.setCurrentFallthrough(addrField.getAddress());
			}
		});
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

		Font font = addressLabel.getFont();
		Font monoFont = new Font("monospaced", font.getStyle(), font.getSize());
		addressLabel.setFont(monoFont);

		instLabel = new GDLabel("jmp DAT_01001000");
		instLabel.setFont(monoFont);

		homeButton = createButton("images/go-home.png", "Home");
		homeButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				plugin.goTo(model.getAddress());
			}
		});

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
		defaultRB.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent ev) {
				model.defaultSelected();
			}
		});
		defaultRB.setToolTipText("Use default fallthrough address");

		userRB = new GRadioButton("User", false);
		userRB.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent ev) {
				model.userSelected();
			}
		});
		userRB.setToolTipText("Override default fallthrough address");

		group.add(defaultRB);
		group.add(userRB);

		panel.add(defaultRB);
		panel.add(userRB);

		JPanel outerPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
		outerPanel.add(panel);
		return outerPanel;
	}

	private JButton createButton(String filename, String altText) {
		JButton button = new JButton();
		URL imageURL = ResourceManager.getResource(filename);
		if (imageURL != null) {
			ImageIcon icon = new ImageIcon(imageURL);
			button = new JButton(icon);
			Insets noInsets = new Insets(0, 0, 0, 0);
			button.setMargin(noInsets);
		}
		else {
			button = new JButton(altText);
		}
		button.setToolTipText("Go back to home address");
		return button;
	}

	@Override
	public void stateChanged(ChangeEvent e) {
		updateState();
	}

}
