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
package ghidra.feature.vt.gui.provider.matchtable;

import java.awt.Dimension;
import java.awt.event.ComponentAdapter;

import javax.swing.*;
import javax.swing.border.BevelBorder;
import javax.swing.border.Border;

import org.apache.commons.lang3.StringUtils;

import docking.widgets.label.GDLabel;
import docking.widgets.numberformat.BoundedRangeDecimalFormatterFactory;
import ghidra.feature.vt.gui.filters.*;
import ghidra.framework.options.SaveState;
import ghidra.util.layout.HorizontalLayout;

public abstract class AbstractDoubleRangeFilter<T> extends Filter<T>
		implements NumberRangeSubFilterChecker, NumberRangeProducer {

	private static final Integer BASE_COMPONENT_LAYER = 1;
	private static final Integer HOVER_COMPONENT_LAYER = 2;
	private static final String FORMAT = "0.000";

	private final Double maxValue;
	private final Double minValue;

	private JComponent component;
	private FilterFormattedTextField upperBoundField;
	private FilterFormattedTextField lowerBoundField;
	private String filterName;

	AbstractDoubleRangeFilter(String filterName, Double minValue, Double maxValue) {
		this.filterName = filterName;
		this.minValue = minValue;
		this.maxValue = maxValue;

		component = createComponent();
	}

	private void createLowerBoundField() {
		lowerBoundField = new FilterFormattedTextField(
			new BoundedRangeDecimalFormatterFactory(maxValue, minValue, FORMAT), minValue);
		lowerBoundField.setName("Lower " + filterName + " Filter Field"); // for debugging
		lowerBoundField.setColumns(4);
		lowerBoundField.setMinimumSize(lowerBoundField.getPreferredSize());
		lowerBoundField.setHorizontalAlignment(SwingConstants.RIGHT);
	}

	private void createUpperBoundField() {
		upperBoundField = new FilterFormattedTextField(
			new BoundedRangeDecimalFormatterFactory(maxValue, minValue, FORMAT), maxValue);
		upperBoundField.setName("Upper " + filterName + " Filter Field"); // for debugging
		upperBoundField.setColumns(4);
		upperBoundField.setMinimumSize(upperBoundField.getPreferredSize());
		upperBoundField.setHorizontalAlignment(SwingConstants.RIGHT);

	}

	private JComponent createComponent() {
		createLowerBoundField();
		createUpperBoundField();
		lowerBoundField.setInputVerifier(
			new BoundedRangeInputVerifier(upperBoundField, true, maxValue, minValue));
		upperBoundField.setInputVerifier(
			new BoundedRangeInputVerifier(lowerBoundField, false, maxValue, minValue));

		final JPanel panel = new JPanel(new HorizontalLayout(4));
		Border paddingBorder = BorderFactory.createEmptyBorder(1, 5, 1, 5);
		Border outsideBorder = BorderFactory.createBevelBorder(BevelBorder.LOWERED);
		panel.setBorder(BorderFactory.createCompoundBorder(outsideBorder, paddingBorder));

		JLabel filterLabel = new GDLabel(filterName + " Filter: ");
		JLabel middleLabel = new GDLabel("to");

		panel.add(filterLabel);
		panel.add(lowerBoundField);
		panel.add(middleLabel);
		panel.add(upperBoundField);

		FilterStatusListener notificationListener = status -> fireStatusChanged(status);

		StatusLabel lowerBoundStatusLabel = new StatusLabel(lowerBoundField, minValue);
		lowerBoundField.addFilterStatusListener(lowerBoundStatusLabel);
		lowerBoundField.addFilterStatusListener(notificationListener);

		StatusLabel upperBoundStatusLabel = new StatusLabel(upperBoundField, maxValue);
		upperBoundField.addFilterStatusListener(upperBoundStatusLabel);
		upperBoundField.addFilterStatusListener(notificationListener);

		JLayeredPane layeredPane = new JLayeredPane();
		layeredPane.add(panel, BASE_COMPONENT_LAYER);
		layeredPane.add(lowerBoundStatusLabel, HOVER_COMPONENT_LAYER);
		layeredPane.add(upperBoundStatusLabel, HOVER_COMPONENT_LAYER);

		layeredPane.setPreferredSize(panel.getPreferredSize());
		layeredPane.addComponentListener(new ComponentAdapter() {
			@Override
			public void componentResized(java.awt.event.ComponentEvent e) {
				Dimension preferredSize = panel.getPreferredSize();
				panel.setBounds(0, 0, preferredSize.width, preferredSize.height);
				panel.validate();
			}
		});

		return layeredPane;

	}

	@Override
	public JComponent getComponent() {
		return component;
	}

	@Override
	public void clearFilter() {
		lowerBoundField.setText(minValue.toString());
		upperBoundField.setText(maxValue.toString());
	}

	@Override
	public FilterEditingStatus getFilterStatus() {
		FilterEditingStatus lowerStatus = lowerBoundField.getFilterStatus();
		FilterEditingStatus upperStatus = upperBoundField.getFilterStatus();

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
		if (lowerBoundField.getFilterStatus() == FilterEditingStatus.ERROR ||
			upperBoundField.getFilterStatus() == FilterEditingStatus.ERROR) {
			return true; // for an invalid filter state, we let all values through
		}

		String lowerBoundText = lowerBoundField.getText();
		if (lowerBoundText == null || "".equals(lowerBoundText.trim())) {
			return true; // temporary transition; we will be called again
		}

		String upperBoundText = upperBoundField.getText();
		if (upperBoundText == null || "".equals(upperBoundText)) {
			return true; // temporary transition; we will be called again
		}

		Double lowerBoundFilter = Double.valueOf(lowerBoundText);

		Double filterableValue = getFilterableValue(t);
		if (filterableValue.compareTo(lowerBoundFilter) < 0) {
			return false; // the filter value is lower than the lower range filter
		}

		Double upperBoundFilter = Double.valueOf(upperBoundText);
		if (filterableValue.compareTo(upperBoundFilter) > 0) {
			return false; // the filter value is higher than the upper range filter
		}

		return true;
	}

	/**
	 * Subclasses should return the Double value that is being filtered.
	 *
	 * @param t The t from which to extract the Double value
	 * @return the double value that is being filtered; convert T to a double
	 */
	protected abstract Double getFilterableValue(T t);

	@Override
	public FilterShortcutState getFilterShortcutState() {
		if (isDefaultFilterState()) {
			return FilterShortcutState.ALWAYS_PASSES;
		}

		return FilterShortcutState.REQUIRES_CHECK;
	}

	private boolean isDefaultFilterState() {
		String lowerText = lowerBoundField.getText();
		if (!minValue.equals(Double.valueOf(lowerText))) {
			return false;
		}

		String upperText = upperBoundField.getText();
		if (!maxValue.equals(Double.valueOf(upperText))) {
			return false;
		}

		return true;
	}

	@Override
	public void writeConfigState(SaveState saveState) {

		String stateKey = getStateKey();
		String[] values = new String[2];
		values[0] = lowerBoundField.getText();
		values[1] = upperBoundField.getText();

		saveState.putStrings(stateKey, values);
	}

	private String getStateKey() {
		return getClass().getName();
	}

	@Override
	public void readConfigState(SaveState saveState) {
		String[] values = saveState.getStrings(getStateKey(), null);
		if (values == null) {
			return;
		}

		lowerBoundField.setText(values[0]);
		upperBoundField.setText(values[1]);
	}

	@Override
	public boolean isSubFilterOf(Filter<T> otherFilter) {

		if (!(otherFilter instanceof NumberRangeProducer)) {
			return false;
		}
		return isSubFilterOf(this, (NumberRangeProducer) otherFilter);
	}

	@Override
	public Number getUpperNumber() {
		return upperBoundToDouble();
	}

	@Override
	public Number getLowerNumber() {
		return lowerBoundToDouble();
	}

	private Double lowerBoundToDouble() {
		return toDouble(lowerBoundField.getText());
	}

	private Double upperBoundToDouble() {
		return toDouble(upperBoundField.getText());
	}

	private Double toDouble(String s) {

		if (StringUtils.isBlank(s)) {
			return null;
		}

		try {
			return Double.parseDouble(s);
		}
		catch (NumberFormatException e) {
			return null;
		}
	}

	@Override
	public String toString() {
		return getClass().getSimpleName() + " " + lowerBoundField.getText() + " - " +
			upperBoundField.getText();
	}
}
