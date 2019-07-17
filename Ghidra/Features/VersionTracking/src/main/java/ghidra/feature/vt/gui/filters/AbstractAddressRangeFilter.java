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
package ghidra.feature.vt.gui.filters;

import java.awt.*;
import java.awt.event.*;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;

import javax.swing.*;
import javax.swing.event.EventListenerList;

import org.apache.commons.lang3.StringUtils;

import docking.widgets.checkbox.GCheckBox;
import docking.widgets.combobox.GhidraComboBox;
import docking.widgets.label.GDLabel;
import docking.widgets.label.GHtmlLabel;
import docking.widgets.textfield.HexIntegerFormatter;
import ghidra.feature.vt.api.main.VTAssociation;
import ghidra.feature.vt.gui.provider.matchtable.NumberRangeProducer;
import ghidra.feature.vt.gui.provider.matchtable.NumberRangeSubFilterChecker;
import ghidra.framework.options.SaveState;
import ghidra.program.model.address.Address;

public abstract class AbstractAddressRangeFilter<T> extends AncillaryFilter<T>
		implements NumberRangeSubFilterChecker, NumberRangeProducer {

	private static final String DELIMITER = ":";
	private static final String LOWER_RANGE_VALUES_KEY = "lower.range.values.key";
	private static final String UPPER_RANGE_VALUES_KEY = "upper.range.values.key";
	private static final String LOWER_RANGE_SELECTED_VALUE_KEY = "lower.range.selected.value.key";
	private static final String UPPER_RANGE_SELECTED_VALUE_KEY = "upper.range.selected.value.key";
	private static final String IS_ENABLED_VALUE_KEY = "is.enabled.value.key";

	private static final Integer BASE_COMPONENT_LAYER = 1;
	private static final Integer HOVER_COMPONENT_LAYER = 2;
	private static final Integer DISABLED_COMPONENT_LAYER = 3;

	private static final Long MIN_ADDRESS_VALUE = 0L;
	private static final Long MAX_ADDRESS_VALUE = Long.MAX_VALUE;

	private JComponent component;
	private FilterFormattedTextField lowerAddressRangeTextField;
	private FilterFormattedTextField upperAddressRangeTextField;
	private JComboBox<String> lowerRangeComboBox;
	private JComboBox<String> upperRangeComboBox;

	private boolean isEnabled;
	private JCheckBox enableCheckBox;
	private JComponent disabledScreen;
	private JPanel lowerRangePanel;
	private JPanel upperRangePanel;

	protected AbstractAddressRangeFilter() {
		component = createComponent();
	}

	private JComponent createComponent() {
		final JPanel panel = new JPanel();
		panel.setLayout(new BoxLayout(panel, BoxLayout.X_AXIS));
		panel.setBorder(BorderFactory.createTitledBorder("Address Range"));

		//
		// Enable panel
		// check box for enabled/disabled, so the user can keep previous values
		//
		enableCheckBox = new GCheckBox("enable", true);
		enableCheckBox.addItemListener(e -> enableFilter(enableCheckBox.isSelected()));
		enableCheckBox.setSelected(true);
		JPanel enablePanel = new JPanel(new BorderLayout());
		enablePanel.add(enableCheckBox, BorderLayout.NORTH);

		// begin address field (long input field with hex)
		lowerAddressRangeTextField = new FilterFormattedTextField(
			new IntegerFormatterFactory(new HexIntegerFormatter(), false), MIN_ADDRESS_VALUE);
		lowerAddressRangeTextField.setName("Lower Address Range Text Field"); // for tracking state
		lowerAddressRangeTextField.setColumns(15);
		lowerAddressRangeTextField.setMinimumSize(lowerAddressRangeTextField.getPreferredSize());

		// end address field (long input field with hex)
		upperAddressRangeTextField = new FilterFormattedTextField(
			new IntegerFormatterFactory(new HexIntegerFormatter(), false), MAX_ADDRESS_VALUE);
		upperAddressRangeTextField.setName("Upper Address Range Text Field"); // for tracking state
		upperAddressRangeTextField.setColumns(15);
		upperAddressRangeTextField.setMinimumSize(upperAddressRangeTextField.getPreferredSize());

		lowerAddressRangeTextField.setInputVerifier(new BoundedRangeInputVerifier(
			upperAddressRangeTextField, true, MAX_ADDRESS_VALUE, MIN_ADDRESS_VALUE));
		upperAddressRangeTextField.setInputVerifier(new BoundedRangeInputVerifier(
			lowerAddressRangeTextField, false, MAX_ADDRESS_VALUE, MIN_ADDRESS_VALUE));

		//
		// Put the textfields in combo boxes
		//
		String prototypeDisplay = "7fffffffffffffff"; // hex value of Long.MAX_VALUE
		lowerRangeComboBox =
			createComboBox(lowerAddressRangeTextField, MIN_ADDRESS_VALUE, prototypeDisplay);
		upperRangeComboBox =
			createComboBox(upperAddressRangeTextField, MAX_ADDRESS_VALUE, prototypeDisplay);

		JLabel rangeLabel = new GDLabel("<=");
		rangeLabel.setHorizontalAlignment(SwingConstants.CENTER);

		//
		// Lower Score Panel
		//
		lowerRangePanel = new JPanel(new GridLayout(2, 1));
		JLabel lowLabel = new GHtmlLabel("<html><font size=\"2\" color=\"808080\">low</font>");
		lowLabel.setHorizontalAlignment(SwingConstants.CENTER);
		lowLabel.setVerticalAlignment(SwingConstants.BOTTOM);
		lowerRangePanel.add(lowLabel);
		lowerRangePanel.add(lowerRangeComboBox);

		//
		// Status Panel Score Panel
		//
		JPanel labelPanel = new JPanel(new GridLayout(2, 1));
		labelPanel.add(Box.createVerticalStrut(5)); // space filler
		JLabel statusLabel = new GDLabel("<=");
		statusLabel.setHorizontalAlignment(SwingConstants.CENTER);
		labelPanel.add(statusLabel);

		//
		// Upper Score Panel
		//
		upperRangePanel = new JPanel(new GridLayout(2, 1));
		JLabel upperLabel = new GHtmlLabel("<html><font size=\"2\" color=\"808080\">high</font>");
		upperLabel.setHorizontalAlignment(SwingConstants.CENTER);
		upperLabel.setVerticalAlignment(SwingConstants.BOTTOM);
		upperRangePanel.add(upperLabel);
		upperRangePanel.add(upperRangeComboBox);

		panel.add(enablePanel);
		panel.add(Box.createHorizontalStrut(10));
		panel.add(lowerRangePanel);
		panel.add(labelPanel);
		panel.add(upperRangePanel);

		final int minHeight = 175;

		final JLayeredPane layeredPane = new JLayeredPane() {
			@Override
			public Dimension getMaximumSize() {
				Dimension preferredSize = panel.getPreferredSize();
				preferredSize.height = Math.max(preferredSize.height, minHeight);
				return preferredSize;
			}
		};

		FilterStatusListener notificationListener = status -> fireStatusChanged(status);

		StatusLabel lowerScoreStatusLabel =
			new StatusLabel(lowerAddressRangeTextField, MIN_ADDRESS_VALUE);
		lowerAddressRangeTextField.addFilterStatusListener(lowerScoreStatusLabel);
		lowerAddressRangeTextField.addFilterStatusListener(notificationListener);

		StatusLabel upperScoreStatusLabel =
			new StatusLabel(upperAddressRangeTextField, MAX_ADDRESS_VALUE);
		upperAddressRangeTextField.addFilterStatusListener(upperScoreStatusLabel);
		upperAddressRangeTextField.addFilterStatusListener(notificationListener);

		disabledScreen = createDisabledScreen(layeredPane);

		layeredPane.add(panel, BASE_COMPONENT_LAYER);
		layeredPane.add(lowerScoreStatusLabel, HOVER_COMPONENT_LAYER);
		layeredPane.add(upperScoreStatusLabel, HOVER_COMPONENT_LAYER);
		layeredPane.add(disabledScreen, DISABLED_COMPONENT_LAYER);

		layeredPane.setPreferredSize(panel.getPreferredSize());
		layeredPane.addComponentListener(new ComponentAdapter() {
			@Override
			public void componentResized(ComponentEvent e) {
				Dimension preferredSize = panel.getPreferredSize();
				panel.setBounds(0, 0, preferredSize.width, preferredSize.height);
				panel.validate();
			}
		});

		// initialize our enabled state
		enableFilter(enableCheckBox.isSelected());

		return layeredPane;
	}

	private JComponent createDisabledScreen(final Container parent) {
		final JComponent screen = new JComponent() {
			@Override
			protected void paintComponent(Graphics g) {
				Color bg = getBackground();
				Color disabledColor = new Color(bg.getRed(), bg.getGreen(), bg.getBlue(), 100);
				g.setColor(disabledColor);
				g.fillRect(0, 0, getWidth(), getHeight());
			}
		};

		parent.addComponentListener(new ComponentAdapter() {
			@Override
			public void componentResized(ComponentEvent e) {
				resizeDisabledScreen();
			}
		});

		return screen;
	}

	private void resizeDisabledScreen() {
		// Our screen only covers some of the components.  These components are either
		// the lower and upper panels or are in between those panels.  Also, those panels
		// are assumed to be the same size.
		Rectangle startBounds = lowerRangePanel.getBounds();
		Rectangle endBounds = upperRangePanel.getBounds();
		int x = startBounds.x;
		int y = startBounds.y;
		int panelOffset = endBounds.x - x;
		int width = panelOffset + endBounds.width;
		int height = endBounds.height;

		if (width <= 0 || height <= 0) {
			SwingUtilities.invokeLater(() -> resizeDisabledScreen());
			return; // not yet initialized
		}

		disabledScreen.setBounds(x, y, width, height);
		component.validate();
	}

	private JComboBox<String> createComboBox(FilterFormattedTextField field, Long defaultValue,
			String prototypeString) {
		GhidraComboBox<String> comboBox = new GhidraComboBox<>(new LimitedHistoryComboBoxModel()) {
			// overridden to paint seamlessly with out color changing text field
			@Override
			protected void paintComponent(Graphics g) {
				super.paintComponent(g);
				Rectangle bounds = getBounds();
				Color oldColor = g.getColor();
				g.setColor(getBackground());
				g.fillRect(0, 0, bounds.width, bounds.height);
				g.setColor(oldColor);
			}
		};
		comboBox.setEditor(new FormattedFieldComboBoxEditor(field));
		comboBox.setEditable(true);
		comboBox.setPrototypeDisplayValue(prototypeString);
		comboBox.addItem(Long.toHexString(defaultValue));
		comboBox.setSelectedIndex(0);
		comboBox.setBackground(field.getBackground());
		field.addPropertyChangeListener(new BackgroundColorChangeListener(comboBox));

		// no border, since we are inside of another component
		field.setBorder(BorderFactory.createEmptyBorder());

		return comboBox;
	}

	private void enableFilter(boolean enable) {
		lowerAddressRangeTextField.setEnabled(enable);
		upperAddressRangeTextField.setEnabled(enable);
		isEnabled = enable;
		disabledScreen.setVisible(!isEnabled);
		fireStatusChanged(getFilterStatus());
	}

	@Override
	public void clearFilter() {
		lowerAddressRangeTextField.setText(MIN_ADDRESS_VALUE.toString());
		upperAddressRangeTextField.setText(MAX_ADDRESS_VALUE.toString());
	}

	@Override
	public JComponent getComponent() {
		return component;
	}

	@Override
	public FilterEditingStatus getFilterStatus() {
		if (!isEnabled) {
			return FilterEditingStatus.NONE;
		}

		FilterEditingStatus lowerStatus = lowerAddressRangeTextField.getFilterStatus();
		FilterEditingStatus upperStatus = upperAddressRangeTextField.getFilterStatus();

		if (lowerStatus == FilterEditingStatus.ERROR || upperStatus == FilterEditingStatus.ERROR) {
			return FilterEditingStatus.ERROR;
		}

		if (lowerStatus == FilterEditingStatus.APPLIED ||
			upperStatus == FilterEditingStatus.APPLIED) {
			return FilterEditingStatus.APPLIED;
		}

		return FilterEditingStatus.NONE;
	}

	@Override
	public boolean passesFilter(T t) {
		return associationPassesFilter(getAssocation(t));
	}

	protected abstract VTAssociation getAssocation(T t);

	@Override
	public FilterShortcutState getFilterShortcutState() {
		if (!isEnabled) {
			return FilterShortcutState.ALWAYS_PASSES;
		}

		String lowerText = lowerAddressRangeTextField.getText();
		String upperText = upperAddressRangeTextField.getText();
		Long lowerValue = Long.valueOf(lowerText, 16);
		Long upperValue = Long.valueOf(upperText, 16);

		if (lowerValue.compareTo(MIN_ADDRESS_VALUE) == 0 &&
			upperValue.compareTo(MAX_ADDRESS_VALUE) == 0) {
			return FilterShortcutState.ALWAYS_PASSES;
		}

		return FilterShortcutState.REQUIRES_CHECK;
	}

	protected boolean associationPassesFilter(VTAssociation association) {
		if (!isEnabled) {
			return true;
		}

		if (lowerAddressRangeTextField.getFilterStatus() == FilterEditingStatus.ERROR ||
			upperAddressRangeTextField.getFilterStatus() == FilterEditingStatus.ERROR) {
			return true; // for an invalid filter state, we let all values through
		}

		Address sourceAddress = association.getSourceAddress();
		if (isAddressInRange(sourceAddress)) {
			return true;
		}

		Address destinationAddress = association.getDestinationAddress();
		return isAddressInRange(destinationAddress);
	}

	private boolean isAddressInRange(Address address) {
		String text = lowerAddressRangeTextField.getText();
		if (text == null || "".equals(text.trim())) {
			return true; // temporary transition; we will be called again
		}

		Long offset = address.getOffset();
		Long lowerAddressFilter = Long.valueOf(text, 16);
		if (offset.compareTo(lowerAddressFilter) < 0) {
			return false;
		}

		text = upperAddressRangeTextField.getText();
		if (text == null || "".equals(text)) {
			return true; // temporary transition; we will be called again
		}

		Long upperAddressFilter = Long.valueOf(text, 16);
		if (offset.compareTo(upperAddressFilter) > 0) {
			return false; // the match's score is higher than the upper range filter
		}
		return true; // we are within the score's filter range!
	}

	@Override
	public Number getUpperNumber() {
		String text = upperAddressRangeTextField.getText();
		if (StringUtils.isBlank(text)) {
			return null;
		}

		Long longValue = Long.valueOf(text, 16);
		return longValue;
	}

	@Override
	public Number getLowerNumber() {

		String text = lowerAddressRangeTextField.getText();
		if (StringUtils.isBlank(text)) {
			return null;
		}

		Long longValue = Long.valueOf(text, 16);
		return longValue;
	}

	@Override
	public FilterState getFilterState() {
		return new AddressRangeFilterState(this);
	}

	@SuppressWarnings("unchecked")
	@Override
	public void restoreFilterState(FilterState state) {
		((AddressRangeFilterState) state).restoreState();
	}

	@Override
	public void writeConfigState(SaveState saveState) {
		//
		// We have to save various states here:
		// 1) Previous user entries from the combo boxes
		// 2) The currently selected value from the combo boxes
		// 3) The enabled state of this filter
		//

		// 1) Lower Range Box
		String[] lowerValues = getComboBoxValues(lowerRangeComboBox);

		// 1) Upper Range Box
		String[] upperValues = getComboBoxValues(upperRangeComboBox);

		// 2) Lower selected value
		String lowerText = lowerAddressRangeTextField.getText();

		// 2) Upper selected value
		String upperText = upperAddressRangeTextField.getText();

		// 3) Enablement
		boolean enabledState = enableCheckBox.isSelected();

		String masterKey = getStateKey();
		saveState.putStrings(masterKey + DELIMITER + LOWER_RANGE_VALUES_KEY, lowerValues);
		saveState.putStrings(masterKey + DELIMITER + UPPER_RANGE_VALUES_KEY, upperValues);
		saveState.putString(masterKey + DELIMITER + LOWER_RANGE_SELECTED_VALUE_KEY, lowerText);
		saveState.putString(masterKey + DELIMITER + UPPER_RANGE_SELECTED_VALUE_KEY, upperText);
		saveState.putBoolean(masterKey + DELIMITER + IS_ENABLED_VALUE_KEY, enabledState);
	}

	private String getStateKey() {
		return AbstractAddressRangeFilter.class.getSimpleName() + DELIMITER + getClass().getName();
	}

	@Override
	public void readConfigState(SaveState saveState) {
		String masterKey = getStateKey();
		String[] lowerValues =
			saveState.getStrings(masterKey + DELIMITER + LOWER_RANGE_VALUES_KEY, null);
		String[] upperValues =
			saveState.getStrings(masterKey + DELIMITER + UPPER_RANGE_VALUES_KEY, null);
		String lowerText =
			saveState.getString(masterKey + DELIMITER + LOWER_RANGE_SELECTED_VALUE_KEY, null);
		String upperText =
			saveState.getString(masterKey + DELIMITER + UPPER_RANGE_SELECTED_VALUE_KEY, null);
		boolean enabledState =
			saveState.getBoolean(masterKey + DELIMITER + IS_ENABLED_VALUE_KEY, false);

		setComboBoxValues(lowerRangeComboBox, lowerValues);
		setComboBoxValues(upperRangeComboBox, upperValues);

		if (lowerText != null) {
			lowerRangeComboBox.setSelectedItem(lowerText);
		}

		if (upperText != null) {
			upperRangeComboBox.setSelectedItem(upperText);
		}

		enableCheckBox.setSelected(enabledState);
	}

	private String[] getComboBoxValues(JComboBox<String> comboBox) {
		ComboBoxModel<String> model = comboBox.getModel();
		int size = model.getSize();
		String[] values = new String[size];
		for (int i = 0; i < size; i++) {
			values[i] = model.getElementAt(i);
		}
		return values;
	}

	private void setComboBoxValues(JComboBox<String> comboBox, String[] values) {
		if (values == null) {
			return;
		}
		comboBox.removeAllItems();
		for (String value : values) {
			comboBox.addItem(value);
		}
	}

	@Override
	public boolean isSubFilterOf(Filter<T> otherFilter) {

		if (!(otherFilter instanceof NumberRangeProducer)) {
			return false;
		}

		return isSubFilterOf(this, (NumberRangeProducer) otherFilter);
	}

	@Override
	public String toString() {
		return getClass().getSimpleName() + " " + lowerAddressRangeTextField.getText() + " - " +
			upperAddressRangeTextField.getText();
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class AddressRangeFilterState extends FilterState {
		private final String ENABLED_KEY = "enabled";

		AddressRangeFilterState(Filter<?> filter) {
			super(filter);

			put(ENABLED_KEY, isEnabled);
			put(lowerAddressRangeTextField.getName(), lowerAddressRangeTextField.getText());
			put(upperAddressRangeTextField.getName(), upperAddressRangeTextField.getText());
		}

		void restoreState() {
			enableCheckBox.setSelected((Boolean) get(ENABLED_KEY));
			String lowerText = (String) get(lowerAddressRangeTextField.getName());
			String upperText = (String) get(upperAddressRangeTextField.getName());
			lowerAddressRangeTextField.setText(lowerText);
			upperAddressRangeTextField.setText(upperText);

			// also, we are using this method as a signal that we want to update our combo
			// boxes history with the current values
			lowerRangeComboBox.addItem(lowerText);
			upperRangeComboBox.addItem(upperText);
		}

		@Override
		public boolean isSame(FilterState other) {
			Boolean wasEnabled = (Boolean) other.get(ENABLED_KEY);
			if (!wasEnabled && !isEnabled) {
				// we were disabled and we are still disabled...so we are considered unchanged
				// for purposes of filtering
				return true;
			}

			if (wasEnabled && isEnabled) {
				// our enabled state hasn't changed, so we now must look at the text in our
				// range fields
				String oldLowerText = (String) other.get(lowerAddressRangeTextField.getName());
				String currentLowerText = lowerAddressRangeTextField.getText();
				if (!currentLowerText.equals(oldLowerText)) {
					return false; // lower range has changed
				}

				String oldUpperText = (String) other.get(upperAddressRangeTextField.getName());
				String currentUpperText = upperAddressRangeTextField.getText();
				if (!currentUpperText.equals(oldUpperText)) {
					return false; // upper range has changed
				}
				return true;
			}

			return false; // our enabled states have changed...we are different
		}
	}

	private class FormattedFieldComboBoxEditor implements ComboBoxEditor {

		private EventListenerList listeners = new EventListenerList();
		private final FilterFormattedTextField textField;
		private final Object defaultValue;

		FormattedFieldComboBoxEditor(FilterFormattedTextField textField) {
			this.textField = textField;
			defaultValue = textField.getValue();
		}

		@Override
		public Component getEditorComponent() {
			return textField;
		}

		@Override
		public Object getItem() {
			return textField.getText();
		}

		@Override
		public void selectAll() {
			textField.selectAll();
		}

		@Override
		public void setItem(Object anObject) {
			if (anObject == null) {
				textField.setValue(defaultValue);
				return;
			}
			textField.setText(anObject.toString());
		}

		@Override
		public void addActionListener(ActionListener l) {
			listeners.add(ActionListener.class, l);
		}

		@Override
		public void removeActionListener(ActionListener l) {
			listeners.remove(ActionListener.class, l);
		}
	}

	private class BackgroundColorChangeListener implements PropertyChangeListener {

		private final JComboBox<?> comboBox;

		BackgroundColorChangeListener(JComboBox<?> comboBox) {
			this.comboBox = comboBox;
		}

		@Override
		public void propertyChange(PropertyChangeEvent evt) {
			if ("background".equals(evt.getPropertyName())) {
				Color newColor = (Color) evt.getNewValue();
				comboBox.setBackground(newColor);
			}
		}
	}

	private static class LimitedHistoryComboBoxModel extends DefaultComboBoxModel<String> {

		private static final int MAX_SIZE = 10;

		@Override
		public void addElement(String anObject) {
			int index = getIndexOf(anObject);
			if (index != -1) {
				// already here, move up in the list
				super.insertElementAt(anObject, 0);
				removeElementAt(index + 1);
				return;
			}

			super.insertElementAt(anObject, 0);
			enforceSize();
		}

		@Override
		public void insertElementAt(String anObject, int index) {
			int currentIndex = getIndexOf(anObject);
			if (currentIndex != -1) {
				// already here, move up in the list
				super.insertElementAt(anObject, index);
				removeElementAt(currentIndex + 1);
				return;
			}

			super.insertElementAt(anObject, index);
			enforceSize();
		}

		private void enforceSize() {
			int size = getSize();
			if (size > MAX_SIZE) {
				removeElementAt(size - 1);
			}
		}
	}
}
