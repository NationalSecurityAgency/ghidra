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
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.beans.PropertyEditorSupport;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import docking.widgets.checkbox.GCheckBox;
import docking.widgets.label.GDLabel;
import docking.widgets.textfield.IntegerTextField;
import ghidra.framework.options.CustomOptionsEditor;
import ghidra.util.HTMLUtilities;
import ghidra.util.layout.VerticalLayout;

public class ArrayElementPropertyEditor extends PropertyEditorSupport
		implements CustomOptionsEditor {

	private static final String SHOW_MULTI_ELEMENTS_LABEL = "Group Array Elements";
	private static final String GROUP_SIZE_LABEL = "Elements Per Line";

	private static final String[] NAMES = { SHOW_MULTI_ELEMENTS_LABEL, GROUP_SIZE_LABEL };

	// help tooltips
	private static final String SHOW_MULTI_ELEMENTS_TOOLTIP =
		HTMLUtilities.toWrappedHTML("Groups multiple array elements on the same listing line", 75);
	private static final String GROUP_SIZE_LABEL_TOOLTIP =
		HTMLUtilities.toWrappedHTML("Number of array elements to show on a line", 75);

	private static final String[] DESCRIPTIONS =
		{ SHOW_MULTI_ELEMENTS_TOOLTIP, GROUP_SIZE_LABEL_TOOLTIP };

	private ArrayElementWrappedOption elementWrappedOption;

	private Component editorComponent;
	private JCheckBox groupElementsCheckBox;
	private IntegerTextField elementsPerLineField;
	private JComponent elementsLabel;

	public ArrayElementPropertyEditor() {
		editorComponent = buildEditor();
	}

	private Component buildEditor() {
		// we want to have a panel with our options so that we may group them together
		JPanel panel = new JPanel(new VerticalLayout(3));

		// the namespace checkbox will disable the text field options when it is not used
		groupElementsCheckBox = new GCheckBox(SHOW_MULTI_ELEMENTS_LABEL);
		groupElementsCheckBox.setSelected(true);
		groupElementsCheckBox.setToolTipText(SHOW_MULTI_ELEMENTS_TOOLTIP);

		panel.add(groupElementsCheckBox);

		elementsPerLineField =
			createLocalPrefixTextField(GROUP_SIZE_LABEL, GROUP_SIZE_LABEL_TOOLTIP, panel);
		elementsLabel.setToolTipText(GROUP_SIZE_LABEL_TOOLTIP);

		groupElementsCheckBox.addItemListener(new ItemListener() {
			@Override
			public void itemStateChanged(ItemEvent e) {
				boolean enabled = groupElementsCheckBox.isSelected();
				// only enable the text field if we are showing namespaces AND we are 
				// overriding the display value
				elementsPerLineField.setEnabled(enabled);
				elementsLabel.setEnabled(enabled);
				firePropertyChange();
			}
		});
		panel.setBorder(BorderFactory.createCompoundBorder(
			BorderFactory.createEmptyBorder(10, 0, 10, 0), new TitledBorder("Grouping")));

		return panel;
	}

	private IntegerTextField createLocalPrefixTextField(String labelText, String tooltipText,
			Container parent) {

		IntegerTextField textField = new IntegerTextField(10);
		textField.setAllowNegativeValues(false);
		textField.setEnabled(true);

		JPanel textFieldPanel = new JPanel();
		textFieldPanel.setBorder(BorderFactory.createEmptyBorder(0, 10, 0, 0));

		elementsLabel = new GDLabel(labelText);
		textFieldPanel.add(elementsLabel);
		textFieldPanel.add(textField.getComponent());
		textField.addChangeListener(new ChangeListener() {

			@Override
			public void stateChanged(ChangeEvent e) {
				firePropertyChange();
			}
		});

		// add to the main panel
		parent.add(textFieldPanel);

		return textField;
	}

	@Override
	public void setValue(Object value) {
		if (!(value instanceof ArrayElementWrappedOption)) {
			return;
		}

		elementWrappedOption = (ArrayElementWrappedOption) value;
		setLocalValues(elementWrappedOption);
		firePropertyChange();
	}

	private void setLocalValues(ArrayElementWrappedOption namespaceOption) {
		if (namespaceOption.showMultipleArrayElementPerLine() != groupElementsCheckBox.isSelected()) {
			groupElementsCheckBox.setSelected(namespaceOption.showMultipleArrayElementPerLine());
		}
		if (namespaceOption.getArrayElementsPerLine() != elementsPerLineField.getIntValue()) {
			elementsPerLineField.setValue(namespaceOption.getArrayElementsPerLine());
		}
		boolean enabled = groupElementsCheckBox.isSelected();
		elementsPerLineField.setEnabled(enabled);
	}

	private ArrayElementWrappedOption cloneNamespaceValues() {
		ArrayElementWrappedOption newOption = new ArrayElementWrappedOption();
		newOption.setShowMultipleArrayElementPerLine(groupElementsCheckBox.isSelected());
		newOption.setArrayElementsPerLine(elementsPerLineField.getIntValue());
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
