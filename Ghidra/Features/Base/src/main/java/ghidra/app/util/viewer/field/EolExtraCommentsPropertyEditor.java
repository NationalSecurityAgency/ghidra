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
import java.awt.event.ItemListener;
import java.beans.PropertyEditorSupport;

import javax.swing.*;
import javax.swing.border.TitledBorder;

import docking.widgets.checkbox.GCheckBox;
import docking.widgets.combobox.GComboBox;
import ghidra.framework.options.CustomOptionsEditor;
import ghidra.util.layout.PairLayout;

public class EolExtraCommentsPropertyEditor extends PropertyEditorSupport
		implements CustomOptionsEditor {

	private static final String REPEATABLE_LABEL = "Repeatable Comment";
	private static final String REF_REPEATABLE_LABEL = "Referenced Repeatable Comments";
	private static final String AUTO_DATA_LABEL = "Auto Data Comment";
	private static final String AUTO_FUNCTION_LABEL = "Auto Function Comment";
	private static final String ABBREVIATED_LABEL = "Use Abbreviated Comments";

	private static final String REPEATABLE_TOOLTIP =
		"<HTML>For repeatable comments:" +
			"<UL>" +
			"	<LI>ALWAYS - show even if an EOL comment exists</LI>" +
			"	<LI>DEFAULT - show only when no EOL comment exists</LI>" +
			"	<LI>NEVER - do not show</LI>" +
			"</UL>";

	private static final String REF_REPEATABLE_TOOLTIP =
		"<HTML>For referenced repeatable comments:" +
			"<UL>" +
			"	<LI>ALWAYS - show even if a higher priority comment exists</LI>" +
			"	<LI>DEFAULT - show only when no higher priority comment exists</LI>" +
			"	<LI>NEVER - do not show</LI>" +
			"</UL>";

	private static final String AUTO_TOOLTIP =
		"<HTML>For automatic comments:" +
			"<UL>" +
			"	<LI>ALWAYS - show even if a higher priority comment exists</LI>" +
			"	<LI>DEFAULT - show only when no higher priority comment exists</LI>" +
			"	<LI>NEVER - do not show</LI>" +
			"</UL>";

	private static final String ABBREVIATED_TOOLTIP =
		"When showing automatic comments, show the smallest amount of information possible";

	private static final String[] NAMES =
		{ REPEATABLE_LABEL, REF_REPEATABLE_LABEL, AUTO_DATA_LABEL, AUTO_FUNCTION_LABEL,
			ABBREVIATED_LABEL };

	private static final String[] DESCRIPTIONS = {
		REPEATABLE_TOOLTIP, REF_REPEATABLE_TOOLTIP, AUTO_TOOLTIP, AUTO_TOOLTIP,
		ABBREVIATED_TOOLTIP
	};

	private Component editorComponent;

	private GComboBox<EolEnablement> repeatableCombo;
	private GComboBox<EolEnablement> refRepeatableCombo;
	private GComboBox<EolEnablement> autoDataCombo;
	private GComboBox<EolEnablement> autoFunctionCombo;
	private JCheckBox abbreviatedCheckbox;

	private EolExtraCommentsOption commentsOption;

	public EolExtraCommentsPropertyEditor() {
		editorComponent = buildEditor();
	}

	private Component buildEditor() {

		// values picked through trial-and-error
		int vgap = 3;
		int hgap = 5;
		int minRightSize = 150; // big enough to match other items in the external options panel
		JPanel panel = new JPanel(new PairLayout(vgap, hgap, minRightSize));

		JLabel label = new JLabel(REPEATABLE_LABEL);
		label.setToolTipText(REPEATABLE_TOOLTIP);
		repeatableCombo = new GComboBox<>(EolEnablement.values());
		repeatableCombo.setSelectedItem(EolEnablement.DEFAULT);
		repeatableCombo.addItemListener(e -> firePropertyChange());

		panel.add(label);
		panel.add(repeatableCombo);

		label = new JLabel(REF_REPEATABLE_LABEL);
		label.setToolTipText(REF_REPEATABLE_TOOLTIP);
		refRepeatableCombo = new GComboBox<>(EolEnablement.values());
		refRepeatableCombo.setSelectedItem(EolEnablement.DEFAULT);
		refRepeatableCombo.addItemListener(e -> firePropertyChange());

		panel.add(label);
		panel.add(refRepeatableCombo);

		label = new JLabel(AUTO_DATA_LABEL);
		label.setToolTipText(AUTO_TOOLTIP);
		autoDataCombo = new GComboBox<>(EolEnablement.values());
		autoDataCombo.setSelectedItem(EolEnablement.DEFAULT);
		autoDataCombo.addItemListener(e -> firePropertyChange());

		panel.add(label);
		panel.add(autoDataCombo);

		label = new JLabel(AUTO_FUNCTION_LABEL);
		label.setToolTipText(AUTO_TOOLTIP);
		autoFunctionCombo = new GComboBox<>(EolEnablement.values());
		autoFunctionCombo.setSelectedItem(EolEnablement.DEFAULT);
		autoFunctionCombo.addItemListener(e -> firePropertyChange());

		panel.add(label);
		panel.add(autoFunctionCombo);

		abbreviatedCheckbox = new GCheckBox(ABBREVIATED_LABEL);
		abbreviatedCheckbox.setSelected(true);
		abbreviatedCheckbox.setToolTipText(ABBREVIATED_TOOLTIP);

		ItemListener listener = e -> firePropertyChange();
		repeatableCombo.addItemListener(listener);
		refRepeatableCombo.addItemListener(listener);
		autoDataCombo.addItemListener(listener);
		autoFunctionCombo.addItemListener(listener);
		abbreviatedCheckbox.addItemListener(listener);

		panel.setBorder(BorderFactory.createCompoundBorder(
			new TitledBorder("Additional Comment Types"),
			BorderFactory.createEmptyBorder(10, 10, 10, 10)));

		return panel;
	}

	private Object cloneOptionValues() {
		EolExtraCommentsOption newOption = new EolExtraCommentsOption();
		newOption.setRepeatable((EolEnablement) repeatableCombo.getSelectedItem());
		newOption.setRefRepeatable((EolEnablement) refRepeatableCombo.getSelectedItem());
		newOption.setAutoData((EolEnablement) autoDataCombo.getSelectedItem());
		newOption.setAutoFunction((EolEnablement) autoFunctionCombo.getSelectedItem());
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
	public Object getValue() {
		return cloneOptionValues();
	}

	@Override
	public Component getCustomEditor() {
		return editorComponent;
	}

	@Override
	public boolean supportsCustomEditor() {
		return true;
	}

	@Override
	public void setValue(Object value) {
		if (!(value instanceof EolExtraCommentsOption)) {
			return;
		}

		commentsOption = (EolExtraCommentsOption) value;
		setLocalValues(commentsOption);
		firePropertyChange();
	}

	private void setLocalValues(EolExtraCommentsOption sourceOption) {

		EolEnablement currentPriority = (EolEnablement) repeatableCombo.getSelectedItem();
		EolEnablement newPriority = sourceOption.getRepeatable();
		if (currentPriority != newPriority) {
			repeatableCombo.setSelectedItem(newPriority);
		}

		currentPriority = (EolEnablement) refRepeatableCombo.getSelectedItem();
		newPriority = sourceOption.getRefRepeatable();
		if (currentPriority != newPriority) {
			refRepeatableCombo.setSelectedItem(newPriority);
		}

		currentPriority = (EolEnablement) autoDataCombo.getSelectedItem();
		newPriority = sourceOption.getAutoData();
		if (currentPriority != newPriority) {
			autoDataCombo.setSelectedItem(newPriority);
		}

		currentPriority = (EolEnablement) autoFunctionCombo.getSelectedItem();
		newPriority = sourceOption.getAutoFunction();
		if (currentPriority != newPriority) {
			autoFunctionCombo.setSelectedItem(newPriority);
		}
	}
}
