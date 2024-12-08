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

import java.awt.BorderLayout;
import java.util.*;
import java.util.stream.Collectors;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import docking.DockingWindowManager;
import docking.widgets.button.BrowseButton;
import docking.widgets.textfield.HintTextField;
import ghidra.util.Swing;
import ghidra.util.layout.MiddleLayout;
import utility.function.Callback;

/**
 * Base class for BSimValueEditors that work on a list of possible choices
 */
public class MultiChoiceBSimValueEditor implements BSimValueEditor {
	private BSimFilterType filterType;
	private Callback listener;
	private HintTextField textField;
	private JComponent component;
	private List<String> choices;
	private String dataTitle;
	private boolean isValid;

	public MultiChoiceBSimValueEditor(BSimFilterType filterType, List<String> choices,
		List<String> initialValues, String dataTitle, Callback listener) {

		this.filterType = filterType;
		this.choices = choices;
		this.dataTitle = dataTitle;
		this.listener = Callback.dummyIfNull(listener);
		component = buildComponent();
		setValues(initialValues);
		checkValid();
	}

	private JComponent buildComponent() {
		JPanel panel = new JPanel(new BorderLayout());
		textField = createTextField();
		panel.add(textField, BorderLayout.CENTER);
		panel.add(buildChooserButton(), BorderLayout.EAST);
		return panel;
	}

	private JPanel buildChooserButton() {
		JPanel panel = new JPanel(new MiddleLayout());
		JButton button = new BrowseButton();
		button.addActionListener(e -> showChooser());
		panel.add(button);
		return panel;
	}

	private void showChooser() {
		Set<String> selected = new HashSet<>(getValues());
		MultiChoiceSelectionDialog<String> dialog =
			new MultiChoiceSelectionDialog<>(dataTitle, choices, selected);
		DockingWindowManager.showDialog(dialog);
		List<String> selectedChoices = dialog.getSelectedChoices();
		if (selectedChoices != null) {
			setValues(selectedChoices);
		}
	}

	private HintTextField createTextField() {
		HintTextField hintField = new HintTextField(filterType.getHint());
		hintField.setColumns(20);
		hintField.getDocument().addDocumentListener(new DocumentListener() {

			@Override
			public void removeUpdate(DocumentEvent e) {
				documentChanged();
			}

			@Override
			public void insertUpdate(DocumentEvent e) {
				documentChanged();
			}

			@Override
			public void changedUpdate(DocumentEvent e) {
				documentChanged();
			}
		});
		return hintField;
	}

	protected void documentChanged() {
		Swing.runLater(() -> {
			checkValid();
			listener.call();
		});
	}

	@Override
	public void setValues(List<String> values) {
		if (values == null) {
			textField.setText("");
		}
		else {
			String value = values.stream().collect(Collectors.joining(", "));
			textField.setText(value);
		}

	}

	@Override
	public List<String> getValues() {
		String text = textField.getText().trim();
		if (text.contains(",")) {
			List<String> values = new ArrayList<>();
			String[] vals = text.split(FILTER_DELIMETER);
			for (String val : vals) {
				if (val == null || val.isBlank()) {
					continue;
				}
				values.add(val.trim());
			}
			return values;
		}
		return List.of(text);
	}

	@Override
	public JComponent getComponent() {
		return component;
	}

	public boolean hasValidValues() {
		return isValid;
	}

	private void checkValid() {
		isValid = checkForValidValues();
		textField.setBackground(isValid ? VALID_COLOR : INVALID_COLOR);
	}

	private boolean checkForValidValues() {
		List<String> values = getValues();
		if (values == null || values.size() == 0) {
			return filterType.isValidValue("");
		}
		for (String string : values) {
			if (!filterType.isValidValue(string)) {
				return false;
			}
		}
		return true;
	}

}
