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
package ghidra.app.plugin.core.analysis;

import java.awt.Component;
import java.awt.Container;
import java.beans.PropertyEditorSupport;
import java.util.Objects;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import docking.widgets.checkbox.GCheckBox;
import ghidra.framework.options.CustomOptionsEditor;
import ghidra.util.layout.HorizontalLayout;
import ghidra.util.layout.VerticalLayout;

public class GnuDemanglerOptionsPropertyEditor extends PropertyEditorSupport
		implements CustomOptionsEditor {

	private static final String USE_DEPRECATED_DEMANGLER = "Use Deprecated Demangler";
	private static final String USE_DEMANGLER_PARAMETERS = "Use Demangler Program Parameters";

	private static final String USE_DEPRECATED_DEMANGLER_TOOLTIP =
		"Signals to use the deprecated demangler when the modern demangler cannot demangle a " +
			"given string";
	private static final String USE_DEMANGLER_PARAMETERS_TOOLTIP =
		"Signals to use pass the given parameters to the demangler program";

	private static final String[] NAMES =
		{ USE_DEPRECATED_DEMANGLER, USE_DEMANGLER_PARAMETERS };

	private static final String[] DESCRIPTIONS = { USE_DEPRECATED_DEMANGLER_TOOLTIP,
		USE_DEMANGLER_PARAMETERS_TOOLTIP };

	private GnuDemanglerWrappedOption wrappedOption;

	private Component editorComponent;

	private GCheckBox useDeprecatedDemanglerBox;
	private GCheckBox useDemanglerParametersBox;
	private JTextField demanglerParametersTextField;

	public GnuDemanglerOptionsPropertyEditor() {
		editorComponent = buildEditor();
	}

	private Component buildEditor() {

		// we want to have a panel with our options so that we may group them together
		JPanel panel = new JPanel(new VerticalLayout(3));

		useDeprecatedDemanglerBox = new GCheckBox(USE_DEPRECATED_DEMANGLER);
		useDeprecatedDemanglerBox.setSelected(false);
		useDeprecatedDemanglerBox.setToolTipText(USE_DEPRECATED_DEMANGLER_TOOLTIP);
		useDeprecatedDemanglerBox.addItemListener(e -> firePropertyChange());
		panel.add(useDeprecatedDemanglerBox);

		createParameterComponent(panel);

		return panel;
	}

	private void createParameterComponent(Container parent) {

		JPanel textFieldPanel = new JPanel(new HorizontalLayout(0));
		JTextField textField = new JTextField(15);
		useDemanglerParametersBox = new GCheckBox(USE_DEMANGLER_PARAMETERS);
		useDemanglerParametersBox.setToolTipText(USE_DEMANGLER_PARAMETERS_TOOLTIP);
		useDemanglerParametersBox.addItemListener(e -> {
			textField.setEnabled(useDemanglerParametersBox.isSelected());
			firePropertyChange();
		});

		textField.getDocument().addDocumentListener(new DocumentListener() {
			@Override
			public void changedUpdate(DocumentEvent e) {
				firePropertyChange();
			}

			@Override
			public void insertUpdate(DocumentEvent e) {
				firePropertyChange();
			}

			@Override
			public void removeUpdate(DocumentEvent e) {
				firePropertyChange();
			}
		});

		textField.setEnabled(false);

		textFieldPanel.add(useDemanglerParametersBox);
		textFieldPanel.add(Box.createHorizontalStrut(10));
		textFieldPanel.add(textField);

		parent.add(textFieldPanel);

		demanglerParametersTextField = textField;
	}

	@Override
	public void setValue(Object value) {

		if (!(value instanceof GnuDemanglerWrappedOption)) {
			return;
		}

		wrappedOption = (GnuDemanglerWrappedOption) value;
		setLocalValues(wrappedOption);
		firePropertyChange();
	}

	private void setLocalValues(GnuDemanglerWrappedOption newOption) {

		if (newOption.useDeprecatedDemangler() != useDeprecatedDemanglerBox.isSelected()) {
			useDeprecatedDemanglerBox.setSelected(newOption.useDeprecatedDemangler());
		}

		if (newOption.useDemanglerParameters() != useDemanglerParametersBox.isSelected()) {
			useDemanglerParametersBox.setSelected(newOption.useDemanglerParameters());
		}

		String newText = newOption.getDemanglerParametersText();
		String currentText = demanglerParametersTextField.getText();
		if (!Objects.equals(newText, currentText)) {
			demanglerParametersTextField.setText(newText);
		}
	}

	@Override
	public Object getValue() {
		return cloneNamespaceValues();
	}

	private GnuDemanglerWrappedOption cloneNamespaceValues() {

		GnuDemanglerWrappedOption newOption = new GnuDemanglerWrappedOption();
		newOption.setUseDeprecatedDemangler(useDeprecatedDemanglerBox.isSelected());
		newOption.setUseDemanglerParameters(useDemanglerParametersBox.isSelected());
		newOption.setDemanglerParametersText(demanglerParametersTextField.getText());
		return newOption;
	}

	@Override
	public String[] getOptionNames() {
		return NAMES;
	}

	@Override
	public String[] getOptionDescriptions() {
		return DESCRIPTIONS;
	}

	@Override
	public Component getCustomEditor() {
		return editorComponent;
	}

	@Override
	public boolean supportsCustomEditor() {
		return true;
	}
}
