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
import java.awt.CardLayout;
import java.awt.event.ActionListener;
import java.util.Arrays;
import java.util.Comparator;
import java.util.function.Consumer;
import java.util.function.Predicate;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import docking.widgets.combobox.GComboBox;
import docking.widgets.table.FocusableEditor;
import docking.widgets.textfield.HexDecimalModeTextField;
import generic.expressions.ExpressionException;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.util.AddressEvaluator;
import utility.function.Dummy;

/**
 * Input field for entering address or address expression.  Handles multiple address
 * spaces and supports both hex and decimal number modes for evaluating numbers.
 */
public class AddressInput extends JPanel implements FocusableEditor {
	public final static Predicate<AddressSpace> ALL_MEMORY_SPACES = s -> s.isMemorySpace();
	public final static Predicate<AddressSpace> LOADED_MEMORY_SPACES = s -> s.isLoadedMemorySpace();

	private HexDecimalModeTextField textField;
	private AddressSpaceField addressSpaceField;
	AddressEvaluator addressEvaluator;
	private Predicate<AddressSpace> addressSpaceFilter = LOADED_MEMORY_SPACES;
	private Consumer<Address> addressChangedConsumer;
	private Consumer<String> addressErrorConsumer = Dummy.consumer();
	private boolean comboAdded;
	private boolean assumeHex = true;
	private boolean notificationsEnabled = true;

	private static final Comparator<AddressSpace> ADDRESS_SPACE_SORT_COMPARATOR = (s1, s2) -> {
		if (s1.isOverlaySpace()) {
			if (!s2.isOverlaySpace()) {
				return 1;
			}
		}
		else if (s2.isOverlaySpace()) {
			return -1;
		}
		return s1.getName().compareTo(s2.getName());
	};

	/**
	 * Constructs an AddressInput field with no specified program or address.
	 */
	public AddressInput() {
		this(null, null, null);
	}

	/**
	 * Constructs an AddressInput field with a consumer to be called when the address field's
	 * value changes.
	 * @param addressChangedConsumer the consumer to be called when the value in the address field 
	 * changes
	 */
	public AddressInput(Consumer<Address> addressChangedConsumer) {
		this(null, null, addressChangedConsumer);
	}

	/**
	 * Constructs an AddressInput field and initialized with a program.
	 * @param program the program used to evaluate the entered address expression.
	 */
	public AddressInput(Program program) {
		this(program, null, null);
	}

	/**
	 * Constructs an AddressInput field and initialized with an address factory.
	 * @param factory the address factory used to evaluate the entered address expression.
	 */
	public AddressInput(AddressFactory factory) {
		this(null, factory, null);
	}

	/**
	 * Constructs an AddressInput field with a consumer to be notified when the address field
	 * changes and initialized with a program.
	 * @param program the program used to evaluate the entered address expression.
	 * @param addressChangedConsumer the consumer to be called when the value in the address field
	 * changes
	 */
	public AddressInput(Program program, Consumer<Address> addressChangedConsumer) {
		this(program, null, addressChangedConsumer);
	}

	/**
	 * Constructs an AddressInput field with a consumer to be notified when the address field
	 * changes and initialized with an address factory.
	 * @param factory the address factory used to evaluate the entered address expression.
	 * @param addressChangedConsumer the consumer to be called when the value in the address field
	 * changes
	 */
	public AddressInput(AddressFactory factory, Consumer<Address> addressChangedConsumer) {
		this(null, factory, addressChangedConsumer);
	}

	private AddressInput(Program program, AddressFactory factory,
			Consumer<Address> addressChangedConsumer) {
		this.addressChangedConsumer = Dummy.ifNull(addressChangedConsumer);
		buildComponent();
		if (program != null) {
			setProgram(program);
		}
		else if (factory != null) {
			setAddressFactory(factory);
		}
	}

	/**
	 * Sets a filter predicate to determine which address spaces should be selectable by the user.
	 * If after filtering only one space is remaining, the address space portion of the address
	 * input field will not be shown.
	 * @param spaceFilter the predicate for filtering selectable address spaces.
	 */
	public void setAddressSpaceFilter(Predicate<AddressSpace> spaceFilter) {
		this.addressSpaceFilter = spaceFilter;
		updateAddressSpaceCombo();
	}

	/**
	 * Sets the text in the expression input textfield.
	 * @param text the text to initialize the input textfield
	 */
	public void setText(String text) {
		textField.setText(text);
	}

	/**
	 * Used to set the internal borders for use in specialized use cases such as a table field
	 * editor.
	 * @param border the border to use for the internal components that make up this input field
	 */
	public void setComponentBorders(Border border) {
		addressSpaceField.setComponentsBorder(border);
		textField.setBorder(border);
	}

	/**
	 * Sets the hex/decimal mode for this field. When in hex mode, all numbers are assumed to be
	 * hexadecimal values. When in decimal mode, all numbers are assumed to be decimal numbers 
	 * unless prefixed with "0x".
	 * @param hexMode true to assume numbers are hexadecimal.
	 */
	public void setAssumeHex(boolean hexMode) {
		textField.setHexMode(hexMode);
		hexModeChanged(hexMode);
	}

	/**
	 * Set the field to display the given address
	 * @param address the new address to display
	 */
	public void setAddress(Address address) {
		if (address.equals(getAddress())) {
			return;
		}
		notificationsEnabled = false;
		try {
			String addressString = address.toString(false);
			addressString = removeLeadingZeros(addressString);
			if (!assumeHex) {
				addressString = "0x" + addressString;
			}
			textField.setText(addressString);
			addressSpaceField.setAddressSpace(address.getAddressSpace());
		}
		finally {
			notificationsEnabled = true;
		}
	}

	/**
	 * Sets the selected AddressSpace to the given space.
	 * @param addressSpace the address space to set selected
	 */
	public void setAddressSpace(AddressSpace addressSpace) {
		addressSpaceField.setAddressSpace(addressSpace);
	}

	/**
	 * Returns the address in the field or null if the address can't
	 * be parsed.
	 * @return The address for the current value in the text field
	 * @throws ExpressionException if expression can not be evaluated to a valid address.
	 * 
	 * @throws NullPointerException if AddressFactory has not been set.
	 */
	public Address getAddressWithExceptions() throws ExpressionException {
		String addrExpression = textField.getText();
		if (addrExpression.isBlank()) {
			return null;
		}

		return addressEvaluator.parseAsAddress(addrExpression);
	}

	/**
	 * Gets the current address the field evaluates to or null if the text does not evaluate to 
	 * a valid, unique address.
	 * @return the current address the field evalutes to or null if the text does not evalute to 
	 * a valid unique address.
	 */
	public Address getAddress() {
		try {
			return getAddressWithExceptions();
		}
		catch (ExpressionException e) {
			return null;
		}
	}

	/**
	 * Returns the address space selected in the combobox the default address space if the
	 * comboBox is not being shown.
	 * 
	 * @return the selected address space, or the default address space if no combo added, or
	 * null if no program is set.
	 */
	public AddressSpace getAddressSpace() {
		return addressSpaceField.getAddressSpace();
	}

	/**
	 * Returns true if the Address input field contains text.
	 * The getAddress() method will return null if text is not
	 * a valid address.
	 * @return true if the address field is not blank
	 */
	public boolean hasInput() {
		return !textField.getText().isBlank();
	}

	/**
	 * Returns the text in this field.
	 * @return the text in this field
	 */
	public String getText() {
		return textField.getText().trim();
	}

	/**
	 * Set the program to be used to parse addresses and expressions and also
	 * to determine the list of valid address spaces. Only loaded memory spaces
	 * will be allowed (see {@link AddressSpace#isLoadedMemorySpace()}).
	 * @param program the program to use to resolve address expressions
	 */
	public void setProgram(Program program) {
		addressEvaluator = new AddressEvaluator(program, assumeHex);
		updateAddressSpaceCombo();
	}

	/**
	 * Sets the program and the address space filter at the same time. This avoid some weird 
	 * intermediate results if the are set separately.
	 * @param program the program to use to parse addresses and expressions.
	 * @param addessSpaceFilter the predicate to determine which address spaces are user selectable
	 */
	public void setProgram(Program program, Predicate<AddressSpace> addessSpaceFilter) {
		this.addressSpaceFilter = addessSpaceFilter;
		setProgram(program);
	}

	/**
	 * Legacy method for setting the address factory to be used to parse address. Should only be
	 * used when a program is not readily available.
	 * @param factory the address factory to be used to parse addresses.
	 */
	public void setAddressFactory(AddressFactory factory) {
		addressEvaluator = new AddressEvaluator(factory, assumeHex);
		updateAddressSpaceCombo();
	}

	/**
	 * Sets a consumer to be notified when the address input field changes, but can't be parsed
	 * into a valid address.
	 * @param addressErrorConsumer the consumer to be notified for bad address input
	 */
	public void setAddressErrorConsumer(Consumer<String> addressErrorConsumer) {
		this.addressErrorConsumer = addressErrorConsumer;
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
	 * Set the address space and offset.
	 * NOTE: Unlike {@link #setAddress(Address)} this method is intended for test use only 
	 * and mimics user input with address changed notification
	 * @param addr the address value
	 */
	public void simulateAddressChanged(Address addr) {
		setAddress(addr);
		notifyAddressChanged();
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
		addressSpaceField.setEditable(state);
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
	 * @param listener the listener to be removed
	 */
	public void removeActionListener(ActionListener listener) {
		this.textField.removeActionListener(listener);
	}

	@Override
	public void setEnabled(boolean enabled) {
		super.setEnabled(enabled);
		textField.setEnabled(enabled);
		addressSpaceField.setEnabled(enabled);
	}

	/**
	 * Sets the accessible name for this address input field.
	 * @param name the accessible name for this address field
	 */
	public void setAccessibleName(String name) {
		textField.getAccessibleContext().setAccessibleName(name);
	}

	/**
	 * Set the text field to be editable or not.
	 * @param b true if the address input field can be edited
	 */
	public void setEditable(boolean b) {
		textField.setEditable(b);
		addressSpaceField.setEditable(b);
	}

	/**
	 * Returns true if the address input field is editable.
	 * @return true if the address input field is editable.
	 */
	public boolean isEditable() {
		return textField.isEditable();
	}

	@Override
	public void focusEditor() {
		if (addressSpaceField.getSpaceCount() > 1 && addressSpaceField.isEnabled()) {
			addressSpaceField.requestFocusInWindow();
		}
		else {
			textField.requestFocusInWindow();
		}
	}

	@Override
	public void requestFocus() {
		textField.requestFocus();
	}

	private void buildComponent() {
		setLayout(new BorderLayout());
		textField = new HexDecimalModeTextField(10, b -> hexModeChanged(b));
		textField.setHexMode(true);
		textField.setName("JTextField");//for JUnits...
		addressSpaceField = new AddressSpaceField();
		add(textField, BorderLayout.CENTER);
		comboAdded = false;

		textField.getDocument().addDocumentListener(new DocumentListener() {
			@Override
			public void insertUpdate(DocumentEvent e) {
				notifyAddressChanged();
			}

			@Override
			public void removeUpdate(DocumentEvent e) {
				notifyAddressChanged();
			}

			@Override
			public void changedUpdate(DocumentEvent e) {
				notifyAddressChanged();
			}
		});

	}

	private void hexModeChanged(boolean hexMode) {
		this.assumeHex = hexMode;
		addressEvaluator.setAssumeHex(hexMode);
		notifyAddressChanged();
	}

	private String removeLeadingZeros(String addressString) {
		// if it has a colon, then is is a segmented address, don't mess with it.
		if (addressString.indexOf(":") >= 0) {
			return addressString;
		}
		for (int i = 0; i < addressString.length(); i++) {
			if (addressString.charAt(i) != '0') {
				return addressString.substring(i);
			}
		}
		return "0";
	}

	private void updateAddressSpaceCombo() {
		notificationsEnabled = false;
		try {
			addressSpaceField.updateAddressSpaces(addressEvaluator.getAddressFactory());
		}
		finally {
			notificationsEnabled = true;
		}
		addRemoveAdressSpaceField();
	}

	private void addRemoveAdressSpaceField() {
		remove(addressSpaceField);
		if (addressSpaceField.getSpaceCount() > 1) {
			add(addressSpaceField, BorderLayout.WEST);
		}
		revalidate();
	}

	private void notifyAddressChanged() {
		if (notificationsEnabled) {
			try {
				Address address = getAddressWithExceptions();
				addressChangedConsumer.accept(address);
			}
			catch (ExpressionException e) {
				addressChangedConsumer.accept(null);
				addressErrorConsumer.accept(e.getMessage());
			}
		}
	}

	private class AddressSpaceField extends JPanel {
		private JComboBox<AddressSpace> combo;
		private JTextField uneditableSpaceField;
		private CardLayout layout;
		private boolean editable = true;

		private AddressSpaceField() {
			layout = new CardLayout();
			setLayout(layout);

			combo = new GComboBox<>();
			combo.setName("JComboBox");//for JUnits...
			combo.getAccessibleContext().setAccessibleName("Address Space");
			combo.addActionListener(ev -> addressSpaceChanged());
			add(combo, "combo");

			uneditableSpaceField = new JTextField("");
			uneditableSpaceField.setEnabled(false);
			add(uneditableSpaceField, "text");
		}

		private void addressSpaceChanged() {
			AddressSpace space = (AddressSpace) combo.getSelectedItem();
			addressEvaluator.setPreferredAddressSpace(space);
			notifyAddressChanged();
		}

		private void setEditable(boolean state) {
			this.editable = state;
			updateLayout();
		}

		private void updateLayout() {
			boolean showCombo = isEnabled() && editable;
			layout.show(this, showCombo ? "combo" : "text");
		}

		@Override
		public void setEnabled(boolean enabled) {
			super.setEnabled(enabled);
			updateLayout();
		}

		private int getSpaceCount() {
			return combo.getModel().getSize();
		}

		private void updateAddressSpaces(AddressFactory addressFactory) {
			ComboBoxModel<AddressSpace> model = createAddressSpaceModel(addressFactory);
			combo.setModel(model);
			AddressSpace defaultAddressSpace = addressFactory.getDefaultAddressSpace();
			if (addressSpaceFilter.test(defaultAddressSpace)) {
				setAddressSpace(defaultAddressSpace);
			}
			else {
				setAddressSpace(model.getElementAt(0));
			}
		}

		private AddressSpace getAddressSpace() {
			return (AddressSpace) combo.getSelectedItem();
		}

		private void setAddressSpace(AddressSpace addressSpace) {
			combo.setSelectedItem(addressSpace);
			String name = addressSpace.getName();
			uneditableSpaceField.setText(name);
			invalidate();
		}

		private void setComponentsBorder(Border border) {
			combo.setBorder(border);
			uneditableSpaceField.setBorder(border);
		}

		private ComboBoxModel<AddressSpace> createAddressSpaceModel(AddressFactory factory) {
			AddressSpace[] spaces = factory.getAddressSpaces();

			Arrays.sort(spaces, ADDRESS_SPACE_SORT_COMPARATOR);
			DefaultComboBoxModel<AddressSpace> model = new DefaultComboBoxModel<>();

			for (AddressSpace space : spaces) {
				if (!addressSpaceFilter.test(space)) {
					continue;
				}
				model.addElement(space);
			}
			return model;
		}
	}

}
