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
package docking.widgets.model;

import java.awt.Component;
import java.awt.Font;
import java.awt.event.FocusAdapter;
import java.awt.event.FocusEvent;
import java.util.List;
import java.util.Objects;

import javax.swing.*;

import ghidra.program.model.address.*;
import ghidra.util.MathUtilities;

public class GAddressRangeField extends JPanel {
	private static final Font MONOSPACED = Font.decode("monospaced");
	private final JComboBox<String> fieldSpace = new JComboBox<>();
	private final JTextField fieldMin = new JTextField("0");
	private final JTextField fieldMax = new JTextField("0");

	private final DefaultComboBoxModel<String> modelSpace = new DefaultComboBoxModel<>();

	private AddressFactory factory;

	public GAddressRangeField() {
		setLayout(new BoxLayout(this, BoxLayout.X_AXIS));

		add(new JLabel("["));
		fieldSpace.setFont(MONOSPACED);
		add(fieldSpace);
		add(new JLabel(":"));
		fieldMin.setFont(MONOSPACED);
		add(fieldMin);
		add(new JLabel(", "));
		fieldMax.setFont(MONOSPACED);
		add(fieldMax);
		add(new JLabel("]"));

		fieldSpace.setEditable(false);
		fieldSpace.setModel(modelSpace);

		fieldSpace.addFocusListener(new FocusAdapter() {
			@Override
			public void focusLost(FocusEvent e) {
				spaceFocusLost(e);
				checkDispatchFocus(e);
			}
		});

		fieldMin.addFocusListener(new FocusAdapter() {
			@Override
			public void focusLost(FocusEvent e) {
				minFocusLost(e);
				checkDispatchFocus(e);
			}
		});
		fieldMax.addFocusListener(new FocusAdapter() {
			@Override
			public void focusLost(FocusEvent e) {
				maxFocusLost(e);
				checkDispatchFocus(e);
			}
		});
	}

	protected void checkDispatchFocus(FocusEvent e) {
		Component opp = e.getOppositeComponent();
		if (opp == null || !SwingUtilities.isDescendingFrom(opp, this)) {
			dispatchEvent(e);
		}
	}

	public void setAddressFactory(AddressFactory factory) {
		this.factory = factory;

		modelSpace.removeAllElements();

		if (factory != null) {
			for (AddressSpace space : factory.getAddressSpaces()) {
				modelSpace.addElement(space.getName());
			}
			modelSpace.setSelectedItem(factory.getDefaultAddressSpace().getName());
			revalidateMin();
			revalidateMax();
			adjustMaxToMin();
		}
	}

	protected AddressSpace getSpace(boolean required) {
		AddressSpace space = factory.getAddressSpace((String) fieldSpace.getSelectedItem());
		if (required) {
			return Objects.requireNonNull(space);
		}
		return space;
	}

	protected long parseLong(String text, long defaultVal) {
		try {
			return Long.parseUnsignedLong(text, 16);
		}
		catch (NumberFormatException ex) {
			return defaultVal;
		}
	}

	protected void revalidateMin() {
		AddressSpace space = getSpace(true);
		long spaceMin = space.getMinAddress().getOffset();
		long min = MathUtilities.unsignedMax(parseLong(fieldMin.getText(), spaceMin), spaceMin);

		fieldMin.setText(Long.toUnsignedString(min, 16));
	}

	protected void revalidateMax() {
		AddressSpace space = getSpace(true);
		long spaceMax = space.getMaxAddress().getOffset();
		long max = MathUtilities.unsignedMin(parseLong(fieldMax.getText(), spaceMax), spaceMax);

		fieldMax.setText(Long.toUnsignedString(max, 16));
	}

	protected void adjustMaxToMin() {
		AddressSpace space = getSpace(true);
		long spaceMin = space.getMinAddress().getOffset();
		long min = parseLong(fieldMin.getText(), spaceMin);
		long max = MathUtilities.unsignedMax(min, parseLong(fieldMax.getText(), min));
		fieldMax.setText(Long.toUnsignedString(max, 16));
	}

	protected void adjustMinToMax() {
		AddressSpace space = getSpace(true);
		long spaceMax = space.getMaxAddress().getOffset();
		long max = parseLong(fieldMax.getText(), spaceMax);
		long min = MathUtilities.unsignedMin(max, parseLong(fieldMin.getText(), max));
		fieldMin.setText(Long.toUnsignedString(min, 16));
	}

	protected void spaceFocusLost(FocusEvent e) {
		if (factory == null) {
			return;
		}
		revalidateMin();
		revalidateMax();
		adjustMaxToMin();
	}

	protected void minFocusLost(FocusEvent e) {
		if (factory == null) {
			return;
		}
		revalidateMin();
		adjustMaxToMin();
	}

	protected void maxFocusLost(FocusEvent e) {
		if (factory == null) {
			return;
		}
		revalidateMax();
		adjustMinToMax();
	}

	public void setRange(AddressRange range) {
		if (factory == null) {
			throw new IllegalStateException("Must set address factory first.");
		}
		if (!List.of(factory.getAddressSpaces()).contains(range.getAddressSpace())) {
			throw new IllegalArgumentException(
				"Given range's space must be in the factory's physical spaces");
		}
		fieldSpace.setSelectedItem(range.getAddressSpace().getName());
		fieldMin.setText(Long.toUnsignedString(range.getMinAddress().getOffset(), 16));
		fieldMax.setText(Long.toUnsignedString(range.getMaxAddress().getOffset(), 16));
	}

	public AddressRange getRange() {
		String name = (String) fieldSpace.getSelectedItem();
		if (name == null) {
			return null;
		}
		AddressSpace space = Objects.requireNonNull(factory.getAddressSpace(name));
		long min = Long.parseUnsignedLong(fieldMin.getText(), 16);
		long max = Long.parseUnsignedLong(fieldMax.getText(), 16);
		return new AddressRangeImpl(space.getAddress(min), space.getAddress(max));
	}

	@Override
	public void setEnabled(boolean enabled) {
		super.setEnabled(enabled);
		fieldSpace.setEnabled(enabled);
		fieldMin.setEnabled(enabled);
		fieldMax.setEnabled(enabled);
	}
}
