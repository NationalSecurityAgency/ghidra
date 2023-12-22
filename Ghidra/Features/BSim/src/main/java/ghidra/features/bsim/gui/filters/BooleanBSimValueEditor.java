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
package ghidra.features.bsim.gui.filters;

import java.util.List;

import javax.swing.*;

import ghidra.util.Swing;
import utility.function.Callback;

/**
 * A BSimValueEditor for boolean filter values.
 */
public class BooleanBSimValueEditor implements BSimValueEditor {

	private Callback listener;
	private JRadioButton trueButton;
	private JRadioButton falseButton;
	private BSimFilterType filterType;
	private JPanel component;

	public BooleanBSimValueEditor(BSimFilterType filterType, List<String> initialValues,
		Callback listener) {
		this.filterType = filterType;
		this.listener = listener;
		this.component = createInputPanel();
		setValues(initialValues);
	}

	private void setValue(String value) {
		value = filterType.normalizeValue(value);
		if ("true".equals(value)) {
			trueButton.setSelected(true);
		}
		else if ("false".equals(value)) {
			falseButton.setSelected(true);
		}
	}

	@Override
	public void setValues(List<String> values) {
		String value = "true";
		if (values != null && !values.isEmpty()) {
			value = values.get(0);
		}
		setValue(value);
	}

	@Override
	public List<String> getValues() {
		if (trueButton.isSelected()) {
			return List.of("true");
		}
		return List.of("false");
	}

	@Override
	public JComponent getComponent() {
		return component;
	}

	private void valueChanged() {
		Swing.runLater(() -> listener.call());
	}

	private JPanel createInputPanel() {
		JPanel panel = new JPanel();
		panel.setLayout(new BoxLayout(panel, BoxLayout.X_AXIS));
		panel.setBorder(BorderFactory.createEmptyBorder());
		trueButton = new JRadioButton("True");
		falseButton = new JRadioButton("False");

		ButtonGroup group = new ButtonGroup();
		group.add(trueButton);
		group.add(falseButton);

		// Fire off a change event whenever the user selects a radio button.
		trueButton.addActionListener(e -> valueChanged());
		falseButton.addActionListener(e -> valueChanged());

		panel.add(trueButton);
		panel.add(falseButton);

		// Initialize the panel so the True radio button is selected. 
		setValue("true");
		return panel;
	}

	@Override
	public boolean hasValidValues() {
		return true;
	}
}
