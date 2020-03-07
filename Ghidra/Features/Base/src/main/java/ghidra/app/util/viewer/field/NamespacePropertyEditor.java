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
package ghidra.app.util.viewer.field;

import java.awt.Component;
import java.awt.Container;
import java.beans.PropertyEditorSupport;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import docking.widgets.checkbox.GCheckBox;
import ghidra.framework.options.CustomOptionsEditor;
import ghidra.util.HTMLUtilities;
import ghidra.util.layout.VerticalLayout;

public class NamespacePropertyEditor extends PropertyEditorSupport implements CustomOptionsEditor {

	private static final String DISPLAY_LOCAL_NAMESPACE_LABEL = "Display Local Namespace";
	private static final String DISPLAY_NON_LOCAL_NAMESPACE_LABEL = "Display Non-local Namespace";
	private static final String LOCAL_NAMESPACE_PREFIX_LABEL = "Local namespace prefix";
	private static final String DISPLAY_LIBRARY_IN_NAMESPACE_LABEL = "Display library in namespace";

	private static final String[] NAMES =
		{ DISPLAY_LOCAL_NAMESPACE_LABEL, DISPLAY_NON_LOCAL_NAMESPACE_LABEL,
			LOCAL_NAMESPACE_PREFIX_LABEL, DISPLAY_LIBRARY_IN_NAMESPACE_LABEL };

	// help tooltips
	private static final String SHOW_NON_LOCAL_NAMESPACE_TOOLTIP = HTMLUtilities.toWrappedHTML(
		"Prepends namespaces to fields that are not in the local namespace.", 75);
	private static final String SHOW_LOCAL_NAMESPACE_TOOLTIP = HTMLUtilities.toWrappedHTML(
		"Prepends namespaces to fields that are in the local namespace.", 75);
	private static final String LOCAL_PREFIX_TOOLTIP = HTMLUtilities.toWrappedHTML(
		"The prefix value prepended to fields instead of the local namespace of the " +
			"containing function.",
		75);
	private static final String SHOW_LIBRARY_IN_NAMESPACE_TOOLTIP =
		HTMLUtilities.toWrappedHTML("Includes library in namespace when displayed in fields.", 75);

	private static final String[] DESCRIPTIONS = { SHOW_LOCAL_NAMESPACE_TOOLTIP,
		SHOW_NON_LOCAL_NAMESPACE_TOOLTIP, LOCAL_PREFIX_TOOLTIP, SHOW_LIBRARY_IN_NAMESPACE_TOOLTIP };

	private NamespaceWrappedOption namespaceWrappedOption;

	private Component editorComponent;
	private JCheckBox showNonLocalCheckBox;
	private JCheckBox showLocalCheckBox;
	private JCheckBox useLocalPrefixCheckBox;
	private JTextField localPrefixField;
	private JCheckBox showLibraryInNamespaceCheckBox;

	public NamespacePropertyEditor() {
		editorComponent = buildEditor();
	}

	private Component buildEditor() {
		// we want to have a panel with our options so that we may group them together
		JPanel panel = new JPanel(new VerticalLayout(3));

		// the namespace checkbox will disable the text field options when it is not used
		showNonLocalCheckBox = new GCheckBox(DISPLAY_NON_LOCAL_NAMESPACE_LABEL);
		showNonLocalCheckBox.setSelected(false);
		showNonLocalCheckBox.setToolTipText(SHOW_NON_LOCAL_NAMESPACE_TOOLTIP);

		showLocalCheckBox = new GCheckBox(DISPLAY_LOCAL_NAMESPACE_LABEL);
		showLocalCheckBox.setSelected(false);
		showLocalCheckBox.setToolTipText(SHOW_LOCAL_NAMESPACE_TOOLTIP);

		showLibraryInNamespaceCheckBox = new GCheckBox(DISPLAY_LIBRARY_IN_NAMESPACE_LABEL);
		showLibraryInNamespaceCheckBox.setSelected(true);
		showLibraryInNamespaceCheckBox.setToolTipText(SHOW_LIBRARY_IN_NAMESPACE_TOOLTIP);

		panel.add(showNonLocalCheckBox);
		panel.add(showLibraryInNamespaceCheckBox);
		panel.add(showLocalCheckBox);

		localPrefixField =
			createLocalPrefixTextField(LOCAL_NAMESPACE_PREFIX_LABEL, LOCAL_PREFIX_TOOLTIP, panel);

		showLocalCheckBox.addItemListener(e -> {
			boolean enabled = showLocalCheckBox.isSelected();
			// only enable the text field if we are showing namespaces AND we are 
			// overriding the display value
			localPrefixField.setEnabled(enabled && useLocalPrefixCheckBox.isSelected());
			useLocalPrefixCheckBox.setEnabled(enabled);
			firePropertyChange();
		});
		showNonLocalCheckBox.addItemListener(e -> firePropertyChange());
		showLibraryInNamespaceCheckBox.addItemListener(e -> firePropertyChange());
		panel.setBorder(BorderFactory.createCompoundBorder(
			BorderFactory.createEmptyBorder(10, 0, 10, 0), new TitledBorder("Namespace Options")));

		return panel;
	}

	private JTextField createLocalPrefixTextField(String labelText, String tooltipText,
			Container parent) {
		final JTextField textField = new JTextField(20);
		textField.setEnabled(false);

		JPanel textFieldPanel = new JPanel();
		textFieldPanel.setBorder(BorderFactory.createEmptyBorder(0, 10, 0, 0));

		useLocalPrefixCheckBox = new GCheckBox("Use Local Namespace Override");
		useLocalPrefixCheckBox.setToolTipText(tooltipText);
		useLocalPrefixCheckBox.addItemListener(e -> {
			textField.setEnabled(useLocalPrefixCheckBox.isSelected());
			firePropertyChange();
		});

		textFieldPanel.add(useLocalPrefixCheckBox);
		textFieldPanel.add(textField);

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

		// add to the main panel
		parent.add(textFieldPanel);

		return textField;
	}

	@Override
	public void setValue(Object value) {
		if (!(value instanceof NamespaceWrappedOption)) {
			return;
		}

		namespaceWrappedOption = (NamespaceWrappedOption) value;
		setLocalValues(namespaceWrappedOption);
		firePropertyChange();
	}

	private void setLocalValues(NamespaceWrappedOption namespaceOption) {
		if (namespaceOption.isShowNonLocalNamespace() != showNonLocalCheckBox.isSelected()) {
			showNonLocalCheckBox.setSelected(namespaceOption.isShowNonLocalNamespace());
		}
		if (namespaceOption.isShowLocalNamespace() != showLocalCheckBox.isSelected()) {
			showLocalCheckBox.setSelected(namespaceOption.isShowLocalNamespace());
		}
		if (namespaceOption.isShowLibraryInNamespace() != showLibraryInNamespaceCheckBox
				.isSelected()) {
			showLibraryInNamespaceCheckBox.setSelected(namespaceOption.isShowLibraryInNamespace());
		}
		if (namespaceOption.isUseLocalPrefixOverride() != useLocalPrefixCheckBox.isSelected()) {
			useLocalPrefixCheckBox.setSelected(namespaceOption.isUseLocalPrefixOverride());
		}
		if (!localPrefixField.getText().equals(namespaceOption.getLocalPrefixText())) {
			localPrefixField.setText(namespaceOption.getLocalPrefixText());
		}
		boolean localNamespaceEnabled = showLocalCheckBox.isSelected();
		useLocalPrefixCheckBox.setEnabled(localNamespaceEnabled);
		localPrefixField.setEnabled(localNamespaceEnabled && useLocalPrefixCheckBox.isSelected());
		boolean nonLocalNamespaceEnabled = showNonLocalCheckBox.isSelected();
		showLibraryInNamespaceCheckBox.setEnabled(nonLocalNamespaceEnabled);
	}

	private NamespaceWrappedOption cloneNamespaceValues() {
		NamespaceWrappedOption newOption = new NamespaceWrappedOption();
		newOption.setShowLocalNamespace(showLocalCheckBox.isSelected());
		newOption.setShowNonLocalNamespace(showNonLocalCheckBox.isSelected());
		newOption.setShowLibraryInNamespace(showLibraryInNamespaceCheckBox.isSelected());
		newOption.setUseLocalPrefixOverride(useLocalPrefixCheckBox.isSelected());
		newOption.setLocalPrefixText(localPrefixField.getText());
		return newOption;
	}

	@Override
	public String[] getOptionDescriptions() {
		return DESCRIPTIONS;
	}

	@Override
	public String[] getOptionNames() {
		return NAMES;
	}

	@Override
	public Object getValue() {
		return cloneNamespaceValues();
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
