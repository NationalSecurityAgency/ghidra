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

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import javax.swing.JComponent;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import docking.widgets.textfield.HintTextField;
import ghidra.util.Swing;
import utility.function.Callback;

/**
 * A BSimValueEditor for filters with arbitrary string values. Supports comma separated values.
 */
public class StringBSimValueEditor implements BSimValueEditor {

	private BSimFilterType filterType;
	private Callback listener;
	private HintTextField textField;
	private boolean isValid;

	public StringBSimValueEditor(BSimFilterType filterType, List<String> initialValues,
		Callback listener) {
		this.filterType = filterType;
		this.listener = Callback.dummyIfNull(listener);
		textField = new HintTextField(filterType.getHint());
		textField.setColumns(20);
		setValues(initialValues);
		textField.getDocument().addDocumentListener(new DocumentListener() {

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
		checkValid();
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
		return textField;
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
