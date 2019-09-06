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
package ghidra.app.util;

import java.awt.BorderLayout;
import java.awt.FontMetrics;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.Arrays;
import java.util.Comparator;

import javax.swing.*;
import javax.swing.event.*;

import docking.widgets.combobox.GComboBox;
import ghidra.program.model.address.*;

/**
 * Panel for user input of addresses.  Handles case with multiple address
 * spaces.
 */
public class AddressInput extends JPanel {
	private JTextField textField;
	private JComboBox<AddressSpace> combo;
	private boolean comboAdded;
	private AddressFactory addrFactory;
	private ChangeListener changeListener;
	private boolean updatingAddress;
	private boolean updateSpaceField;
	private boolean stateChanging;
	private JTextField spaceField;

	private static final Comparator<AddressSpace> ADDRESS_SPACE_SORT_COMPARATOR =
		new Comparator<>() {
			@Override
			public int compare(AddressSpace s1, AddressSpace s2) {
				if (s1.isOverlaySpace()) {
					if (!s2.isOverlaySpace()) {
						return 1;
					}
				}
				else if (s2.isOverlaySpace()) {
					return -1;
				}
				return s1.getName().compareTo(s2.getName());
			}
		};

	/**
	 * Constructor for AddressInput.
	 */
	public AddressInput() {

		setLayout(new BorderLayout());
		textField = new JTextField(10);
		textField.setName("JTextField");//for JUnits...
		combo = new GComboBox<>();
		combo.setName("JComboBox");//for JUnits...
		add(textField, BorderLayout.CENTER);
		//add(combo, BorderLayout.WEST);
		comboAdded = false;

		textField.getDocument().addDocumentListener(new DocumentListener() {
			@Override
			public void insertUpdate(DocumentEvent e) {
				stateChanged();
			}

			@Override
			public void removeUpdate(DocumentEvent e) {
				stateChanged();
			}

			@Override
			public void changedUpdate(DocumentEvent e) {
				stateChanged();
			}
		});

		combo.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent ev) {
				stateChanged();
			}
		});
	}

	/**
	 * Set the field to display the given address
	 */
	public void setAddress(Address addr) {
		if (stateChanging) {
			// called while we are in doing a state changed notification
			return;
		}
		updatingAddress = true;
		textField.setText(addr.toString(false));
		combo.setSelectedItem(addr.getAddressSpace());
		updatingAddress = false;
		if (updateSpaceField) {
			updateSpaceField = false;
			spaceField.setText(addr.getAddressSpace().getName());
		}
	}

	/**
	 * Returns the address in the field or null if the address can't
	 * be parsed.
	 * 
	 * @throws NullPointerException if AddressFactory has not been set.
	 */
	public Address getAddress() {
		String addrStr = textField.getText();

		AddressSpace space = getAddressSpace();
		try {
			return space.getAddress(addrStr);
		}
		catch (AddressFormatException e) {
			return null;
		}
	}

	/**
	 * Returns the address space selected in the combobox or in the input text itself
	 * if specified (eg: "register:1"). If the address space is not specified; returns the
	 * default space.
	 * 
	 * @throws NullPointerException if AddressFactory has not been set.
	 */
	public AddressSpace getAddressSpace() {
		if (comboAdded) {
			return (AddressSpace) combo.getSelectedItem();
		}
		return addrFactory.getDefaultAddressSpace();
	}

	/**
	 * Returns true if the Address input field contains text.
	 * The getAddress() method will return null if text is not
	 * a valid address.
	 */
	public boolean hasInput() {
		return textField.getText().length() != 0;
	}

	/**
	 * Set the address factory to be used to parse addresses.  Also
	 * used to set the combo box with the list of valid address spaces
	 * if there is more than one space.
	 */
	public void setAddressFactory(AddressFactory factory) {
		setAddressFactory(factory, false, false);
	}

	public AddressFactory getAddressFactory() {
		return addrFactory;
	}

	/**
	 * Set the address factory to be used to parse addresses. Also used to set the combo box
	 * with the list of valid address spaces if there is more than one space.
	 * @param factory address factory to use
	 * @param filterOverlaySpaces true if overlay spaces should not appear in the combo box
	 * for the address spaces.
	 * @param allowOtherSpace true if the OTHER space should appear in the combo box for 
	 * the address spaces
	 */
	public void setAddressFactory(AddressFactory factory, boolean filterOverlaySpaces,
			boolean allowOtherSpace) {
		this.addrFactory = factory;
		AddressSpace[] spaces = factory.getAddressSpaces();

		Arrays.sort(spaces, ADDRESS_SPACE_SORT_COMPARATOR);
		DefaultComboBoxModel<AddressSpace> model = new DefaultComboBoxModel<>();
		combo.setModel(model);

		FontMetrics fm = combo.getFontMetrics(combo.getFont());
		int width = 0;
		for (AddressSpace space : spaces) {
			if (filterOverlaySpaces && space.isOverlaySpace()) {
				continue;
			}

			if (!allowOtherSpace && space.equals(AddressSpace.OTHER_SPACE)) {
				continue;
			}

			String s = space.toString();
			width = Math.max(width, fm.stringWidth(s));

			model.addElement(space);
		}

//      // Commented out the following 2 lines since they were causing the Combo to only
//		// display "..." in some cases instead of the actual address space name.
//		Dimension d = combo.getPreferredSize();
//		combo.setPreferredSize(new Dimension(width + 30, d.height));

		if (model.getSize() > 1) {
			if (!comboAdded) {
				add(combo, BorderLayout.WEST);
				comboAdded = true;
			}
		}
		else if (comboAdded) {
			remove(combo);
			comboAdded = false;
		}
		invalidate();
	}

	/**
	 * Sets the selected combo box item
	 * to the default address space.
	 */
	public void selectDefaultAddressSpace() {
		if (addrFactory != null) {
			AddressSpace space = addrFactory.getDefaultAddressSpace();
			combo.setSelectedItem(space);
		}
	}

	/**
	 * Clear the offset part of the address field.
	 */
	public void clear() {
		textField.setText("");
	}

	/**
	 * Select the text field that is the offset.
	 */
	public void select() {
		textField.selectAll();
	}

	/**
	 * Get the offset part of the address field.
	 * @return String
	 */
	public String getValue() {
		return textField.getText();
	}

	/**
	 * Set the offset part of the address field.
	 * @param value the offset value string
	 */
	public void setValue(String value) {
		textField.setText(value);
	}

	@Override
	public boolean isEnabled() {
		return textField.isEnabled();
	}

	public boolean containsAddressSpaces() {
		return comboAdded;
	}

	/**
	 * Set the address space (if it is shown) such that it is not editable.
	 * If the combo box is shown for multiple address spaces, then
	 * the combo box is replaced with a fixed uneditable text field that shows
	 * the currently selected address space.
	 * @param state false means that the combo box should not be editable
	 */
	public void setAddressSpaceEditable(boolean state) {
		if (!state && comboAdded) {
			AddressSpace selectedSpace = (AddressSpace) combo.getSelectedItem();
			String spaceName = selectedSpace != null ? selectedSpace.getName() + ":" : "         ";
			spaceField = new JTextField(spaceName);

			spaceField.setEnabled(false);
			remove(combo);
			add(spaceField, BorderLayout.WEST);
			if (textField.getText().length() == 0) {
				updateSpaceField = true;
			}
		}
	}

	/**
	 * Adds a change listener that will be notified anytime this address value
	 * in this panel changes
	 * @param listener the change listener to be notified.
	 */
	public void addChangeListener(ChangeListener listener) {
		changeListener = listener;
	}

	/**
	 * Add an action listener that will be notified anytime the user presses the
	 * return key while in the text field.
	 * @param listener the action listener to be notified.
	 */
	public void addActionListener(ActionListener listener) {
		this.textField.addActionListener(listener);
	}

	/**
	 * Removes the action listener from the list to be notified.
	 * @param listener
	 */
	public void removeActionListener(ActionListener listener) {
		this.textField.removeActionListener(listener);
	}

	/**
	 * @see java.awt.Component#setEnabled(boolean)
	 */
	@Override
	public void setEnabled(boolean enabled) {
		super.setEnabled(enabled);
		textField.setEnabled(enabled);
		combo.setEnabled(enabled);
	}

	/**
	 * Set the text field to be editable according to the state param.
	 */
	public void setEditable(boolean state) {
		textField.setEditable(state);
	}

	public boolean isEditable() {
		return textField.isEditable();
	}

	private void stateChanged() {
		if (changeListener != null && !updatingAddress && !stateChanging) {
			stateChanging = true;
			changeListener.stateChanged(null);
			stateChanging = false;
		}
	}

	public void showAddressSpaceCombo(boolean showCombo) {
		if (showCombo) {
			if (!comboAdded) {
				add(combo, BorderLayout.WEST);
				comboAdded = true;
			}
		}
		else if (comboAdded) {
			remove(combo);
			comboAdded = false;
		}
		invalidate();
	}

	@Override
	public void requestFocus() {
		textField.requestFocus();
	}

	protected JTextField getAddressTextField() {
		return textField;
	}

	protected JTextField getAddressSpaceTextField() {
		return spaceField;
	}

}
