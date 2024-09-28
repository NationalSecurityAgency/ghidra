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

import java.awt.*;
import java.util.*;
import java.util.List;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import org.apache.commons.collections4.map.LazyMap;

import docking.widgets.checkbox.GCheckBox;
import docking.widgets.combobox.GComboBox;
import docking.widgets.label.GLabel;
import docking.widgets.textfield.IntegerTextField;
import ghidra.framework.options.SaveState;
import ghidra.program.model.address.*;
import ghidra.util.exception.AssertException;
import ghidra.util.layout.*;

/**
 * Editor Panel for displaying and editing options associated with importing or exporting. It takes
 * in a list of Options and generates editors for each of them on th fly.
 */
public class OptionsEditorPanel extends JPanel {
	private static final int MAX_PER_COLUMN = 11;
	private static final int MAX_BOOLEANS_WITH_SELECT_ALL = 5;
	private int columns;
	private AddressFactoryService addressFactoryService;

	/**
	 * Construct a new OptionsEditorPanel
	 * @param options the list of options to be edited.
	 * @param addressFactoryService a service for providing an appropriate AddressFactory if needed
	 * for editing an options.  If null, address based options will not be available.
	 */
	public OptionsEditorPanel(List<Option> options, AddressFactoryService addressFactoryService) {
		super(new VerticalLayout(5));
		this.addressFactoryService = addressFactoryService;
		setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
		columns = options.stream().filter(o -> !o.isHidden()).count() > MAX_PER_COLUMN ? 2 : 1;

		Map<String, List<Option>> optionGroupMap = organizeByGroup(options);
		for (List<Option> optionGroup : optionGroupMap.values()) {
			add(buildOptionGroupPanel(optionGroup));
		}
	}

	private Component buildOptionGroupPanel(List<Option> optionGroup) {
		JPanel panel = new JPanel(new BorderLayout());

		JPanel innerPanel = buildInnerOptionsPanel(optionGroup);
		panel.add(innerPanel, BorderLayout.CENTER);

		if (needsSelectAllDeselectAllButton(optionGroup)) {
			panel.add(buildSelectAllDeselectAllButtonPanel(innerPanel), BorderLayout.SOUTH);
		}

		panel.setBorder(createBorder(optionGroup.get(0).getGroup()));
		return panel;
	}

	private Component buildSelectAllDeselectAllButtonPanel(JPanel innerPanel) {
		JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 5, 5));
		List<JCheckBox> list = findAllCheckBoxes(innerPanel);
		buttonPanel.add(buildSelectAll(list));
		buttonPanel.add(buildDeselectAll(list));
		buttonPanel.setBorder(BorderFactory.createEmptyBorder(5, 0, 0, 0));
		return buttonPanel;
	}

	private JPanel buildInnerOptionsPanel(List<Option> optionGroup) {
		JPanel panel = new JPanel(getBestLayout());

		for (Option option : optionGroup) {
			Component editorComponent = getEditorComponent(option);
			if (editorComponent != null) {
				// Editor not available - omit option from panel
				GLabel label = new GLabel(option.getName(), SwingConstants.RIGHT);
				panel.add(label);
				editorComponent.setName(option.getName()); // set the component name to the option name
				editorComponent.getAccessibleContext().setAccessibleName(option.getName());
				panel.add(editorComponent);
			}
		}
		return panel;
	}

	private LayoutManager getBestLayout() {
		if (columns == 2) {
			return new TwoColumnPairLayout(4, 50, 4, 0);
		}
		return new PairLayout(4, 4);
	}

	private Component buildSelectAll(List<JCheckBox> list) {
		JPanel panel = new JPanel(new FlowLayout(FlowLayout.CENTER));
		JButton button = new JButton("Select All");
		button.addActionListener(e -> {
			for (JCheckBox jCheckBox : list) {
				jCheckBox.setSelected(true);
			}
		});
		panel.add(button);
		return panel;
	}

	private Component buildDeselectAll(List<JCheckBox> list) {
		JPanel panel = new JPanel(new FlowLayout(FlowLayout.CENTER));
		JButton button = new JButton("Deselect All");
		button.addActionListener(e -> {
			for (JCheckBox jCheckBox : list) {
				jCheckBox.setSelected(false);
			}
		});
		panel.add(button);
		return panel;
	}

	private boolean needsSelectAllDeselectAllButton(List<Option> optionGroup) {
		int booleanCount = 0;
		for (Option option : optionGroup) {
			if (Boolean.class.isAssignableFrom(option.getValueClass())) {
				booleanCount++;
			}
		}
		return booleanCount > MAX_BOOLEANS_WITH_SELECT_ALL;
	}

	private Border createBorder(String group) {
		if (group != null) {
			return BorderFactory.createTitledBorder(group);
		}
		return BorderFactory.createEmptyBorder(10, 10, 10, 10);
	}

	private Map<String, List<Option>> organizeByGroup(List<Option> options) {
		Map<String, List<Option>> map =
			LazyMap.lazyMap(new LinkedHashMap<>(), () -> new ArrayList<>());

		for (Option option : options) {
			if (option.isHidden()) {
				continue;
			}
			String group = option.getGroup();
			List<Option> optionGroup = map.get(group);
			optionGroup.add(option);
		}
		return map;
	}

	private List<JCheckBox> findAllCheckBoxes(JPanel panel) {
		ArrayList<JCheckBox> list = new ArrayList<>();
		gatherCheckBoxes(panel, list);
		return list;
	}

	private void gatherCheckBoxes(Container container, ArrayList<JCheckBox> list) {
		Component[] comps = container.getComponents();
		for (Component element : comps) {
			if (element instanceof JCheckBox) {
				list.add((JCheckBox) element);
			}
			if (element instanceof Container) {
				Container subContainer = (Container) element;
				gatherCheckBoxes(subContainer, list);
			}
		}
	}

	/**
	 * Get the editor component for the specified option.
	 * @param option option to be edited
	 * @return option editor or null if prerequisite state not available to support
	 * editor (e.g., Address or AddressSpace editor when {@link AddressFactoryService} 
	 * is not available).
	 */
	private Component getEditorComponent(Option option) {

		Component customEditorComponent = option.getCustomEditorComponent();
		if (customEditorComponent != null) {
			return customEditorComponent;
		}

		Class<?> optionClass = option.getValueClass();
		if (Address.class.isAssignableFrom(optionClass)) {
			return getAddressEditorComponent(option);
		}
		else if (Boolean.class.isAssignableFrom(optionClass)) {
			return getBooleanEditorComponent(option);
		}
		else if (Long.class.isAssignableFrom(optionClass)) {
			return getLongEditorComponent(option);
		}
		else if (Integer.class.isAssignableFrom(optionClass)) {
			return getIntegerEditorComponent(option);
		}
		else if (HexLong.class.isAssignableFrom(optionClass)) {
			return getHexLongEditorComponent(option);
		}
		else if (String.class.isAssignableFrom(optionClass)) {
			return getStringEditorComponent(option);
		}
		else if (AddressSpace.class.isAssignableFrom(optionClass)) {
			return getAddressSpaceEditorComponent(option);
		}
		else {
			throw new AssertException(
				"Attempted to get default editor component for Option type: " +
					optionClass.getName() + ". Please register a custom editor");
		}
	}

	private Component getAddressSpaceEditorComponent(Option option) {
		if (addressFactoryService == null) {
			return null;
		}
		JComboBox<AddressSpace> combo = new GComboBox<>();
		AddressFactory addressFactory = addressFactoryService.getAddressFactory();
		AddressSpace[] spaces =
			addressFactory == null ? new AddressSpace[0] : addressFactory.getAddressSpaces();
		for (AddressSpace space : spaces) {
			combo.addItem(space);
		}
		AddressSpace space = (AddressSpace) option.getValue();
		if (space != null) {
			combo.setSelectedItem(space);
		}
		combo.addActionListener(e -> {
			// called whenever the combobox changes to push the value back to the Option that is
			// our 'model'
			option.setValue(combo.getSelectedItem());
		});
		return combo;
	}

	private Component getStringEditorComponent(Option option) {
		final SaveState state = option.getState();
		String defaultValue = (String) option.getValue();
		String value =
			state != null ? state.getString(option.getName(), defaultValue) : defaultValue;
		option.setValue(value);
		JTextField tf = new JTextField(5);
		tf.setName(option.getName());
		tf.getDocument().addDocumentListener(new ImporterDocumentListener(option, tf, state));
		tf.setText(value);
		return tf;
	}

	private Component getHexLongEditorComponent(Option option) {
		final SaveState state = option.getState();
		HexLong defaultValue = (HexLong) option.getValue();
		long value = state != null ? state.getLong(option.getName(), defaultValue.longValue())
				: defaultValue.longValue();
		option.setValue(new HexLong(value));
		IntegerTextField field = new IntegerTextField();
		field.setValue(value);
		field.setHexMode();
		field.addChangeListener(e -> {
			option.setValue(new HexLong(field.getLongValue()));
			if (state != null) {
				state.putLong(option.getName(), field.getLongValue());
			}
		});
		return field.getComponent();
	}

	private Component getIntegerEditorComponent(Option option) {
		final SaveState state = option.getState();
		int defaultValue = (int) option.getValue();
		int value = state != null ? state.getInt(option.getName(), defaultValue) : defaultValue;
		option.setValue(value);
		IntegerTextField field = new IntegerTextField();
		field.setValue(value);
		field.addChangeListener(e -> {
			option.setValue(field.getIntValue());
			if (state != null) {
				state.putInt(option.getName(), field.getIntValue());
			}
		});
		return field.getComponent();
	}

	private Component getLongEditorComponent(Option option) {
		final SaveState state = option.getState();
		long defaultValue = (long) option.getValue();
		long value =
			state != null ? state.getLong(option.getName(), defaultValue) : defaultValue;
		option.setValue(value);
		IntegerTextField field = new IntegerTextField();
		field.setValue(value);
		field.addChangeListener(e -> {
			option.setValue(field.getLongValue());
			if (state != null) {
				state.putLong(option.getName(), field.getLongValue());
			}
		});
		return field.getComponent();
	}

	private Component getBooleanEditorComponent(Option option) {
		final SaveState state = option.getState();
		boolean defaultValue = (boolean) option.getValue();
		boolean initialState =
			state != null ? state.getBoolean(option.getName(), defaultValue) : defaultValue;
		option.setValue(initialState);
		GCheckBox cb = new GCheckBox();
		cb.setName(option.getName());
		cb.setSelected(initialState);
		cb.addItemListener(e -> {
			option.setValue(cb.isSelected());
			if (state != null) {
				state.putBoolean(option.getName(), cb.isSelected());
			}
		});
		return cb;
	}

	private Component getAddressEditorComponent(Option option) {
		if (addressFactoryService == null) {
			return null;
		}
		AddressFactory addressFactory = addressFactoryService.getAddressFactory();
		AddressInput addressInput = new AddressInput();
		addressInput.setName(option.getName());
		Address addr = (Address) option.getValue();
		if (addr == null && addressFactory != null) {
			addr = addressFactory.getDefaultAddressSpace().getAddress(0);
			option.setValue(addr);
		}
		addressInput.setAddressFactory(addressFactory);
		addressInput.setAddress(addr);
		addressInput.addChangeListener(e -> option.setValue(addressInput.getAddress()));//		addressInput.addActionListener(e -> option.setValue(addressInput.getAddress()));
		return addressInput;
	}
}

class ImporterDocumentListener implements DocumentListener {
	private Option option;
	private JTextField textField;
	private SaveState state;

	ImporterDocumentListener(Option option, JTextField textField, SaveState state) {
		this.option = option;
		this.textField = textField;
		this.state = state;
	}

	@Override
	public void insertUpdate(DocumentEvent e) {
		updated();
	}

	@Override
	public void removeUpdate(DocumentEvent e) {
		updated();
	}

	@Override
	public void changedUpdate(DocumentEvent e) {
		updated();
	}

	private void updated() {
		String text = textField.getText();
		option.setValue(text);
		if (state != null) {
			state.putString(option.getName(), text);
		}
	}
}
