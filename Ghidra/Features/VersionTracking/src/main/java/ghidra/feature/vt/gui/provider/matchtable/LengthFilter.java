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

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.event.ComponentAdapter;
import java.util.Objects;

import javax.swing.*;
import javax.swing.border.BevelBorder;
import javax.swing.border.Border;

import org.apache.commons.lang3.StringUtils;

import docking.widgets.label.GDLabel;
import ghidra.feature.vt.api.main.VTMatch;
import ghidra.feature.vt.gui.filters.*;
import ghidra.framework.options.SaveState;

// this is a minimum length filter
public class LengthFilter extends Filter<VTMatch> {

	private static final Integer BASE_COMPONENT_LAYER = 1;
	private static final Integer HOVER_COMPONENT_LAYER = 2;
	private static final Integer DEFAULT_FILTER_VALUE = 0;

	private JComponent component;
	private FilterFormattedTextField textField;

	public LengthFilter() {
		component = createComponent();
	}

	private JComponent createComponent() {
		final JLabel label = new GDLabel("Length Filter: ");

		Integer defaultValue = DEFAULT_FILTER_VALUE;
		textField = new FilterFormattedTextField(new IntegerFormatterFactory(false), defaultValue);
		textField.setName("Length Filter Field"); // for debugging
		textField.setInputVerifier(new IntegerInputVerifier());
		textField.setHorizontalAlignment(SwingConstants.RIGHT);

		textField.setColumns(5);

		final JPanel panel = new JPanel(new BorderLayout());
		Border paddingBorder = BorderFactory.createEmptyBorder(1, 5, 1, 5);
		Border outsideBorder = BorderFactory.createBevelBorder(BevelBorder.LOWERED);
		panel.setBorder(BorderFactory.createCompoundBorder(outsideBorder, paddingBorder));

		panel.add(label, BorderLayout.WEST);
		panel.add(textField, BorderLayout.EAST);

		final JLayeredPane layeredPane = new JLayeredPane();

		StatusLabel statusLabel = new StatusLabel(textField, defaultValue);
		textField.addFilterStatusListener(statusLabel);
		textField.addFilterStatusListener(status -> fireStatusChanged(status));
		layeredPane.add(panel, BASE_COMPONENT_LAYER);
		layeredPane.add(statusLabel, HOVER_COMPONENT_LAYER);
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
		textField.setText(DEFAULT_FILTER_VALUE.toString());
	}

	@Override
	public FilterEditingStatus getFilterStatus() {
		return textField.getFilterStatus();
	}

	@Override
	public boolean passesFilter(VTMatch t) {
		String text = textField.getText();
		if (text == null || "".equals(text.trim())) {
			return true; // temporary transition; we will be called again
		}

		Integer lengthFilter = Integer.valueOf(text);
		Integer score = t.getSourceLength();
		if (score.compareTo(lengthFilter) < 0) {
			return false; // the match's score is lower than the filter
		}

		score = t.getDestinationLength();
		lengthFilter = Integer.valueOf(textField.getText());
		if (score.compareTo(lengthFilter) >= 0) {
			return true; // the match's score is higher than the filter
		}

		return false; // the value is below the cutoff
	}

	@Override
	public FilterShortcutState getFilterShortcutState() {
		String textFieldText = textField.getText();
		if (textFieldText.trim().isEmpty() || isDefaultValue(textFieldText)) {
			return FilterShortcutState.ALWAYS_PASSES;
		}

		return FilterShortcutState.REQUIRES_CHECK;
	}

	private boolean isDefaultValue(String textFieldText) {
		return DEFAULT_FILTER_VALUE.equals(Integer.valueOf(textFieldText));
	}

	@Override
	public void writeConfigState(SaveState saveState) {
		saveState.putString(getStateKey(), textField.getText());
	}

	private String getStateKey() {
		return getClass().getName();
	}

	@Override
	public void readConfigState(SaveState saveState) {
		textField.setText(saveState.getString(getStateKey(), "0"));
	}

	private Integer toInteger() {

		String s = textField.getText();
		if (StringUtils.isBlank(s)) {
			return null;
		}

		try {
			return Integer.parseInt(s);
		}
		catch (NumberFormatException e) {
			return null;
		}
	}

	@Override
	public boolean isSubFilterOf(Filter<VTMatch> otherFilter) {

		if (!(otherFilter instanceof LengthFilter)) {
			return false;
		}

		LengthFilter otherLengthFilter = (LengthFilter) otherFilter;
		Integer value = toInteger();
		Integer otherValue = otherLengthFilter.toInteger();

		if (Objects.equals(value, otherValue)) {
			return true;
		}

		if (value == null || otherValue == null) {
			return false;
		}

		//
		// This filter is a minimum length filter.  If we are a larger minimum length, then we 
		// are within the bounds of the smaller minimum length.
		//
		int result = value.compareTo(otherValue);
		return result > 0; // our value is larger; we are a sub-filter
	}
}
