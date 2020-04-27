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
package ghidra.framework.analysis.gui;

import java.awt.*;

import javax.swing.*;
import javax.swing.border.Border;

import docking.widgets.*;
import docking.widgets.button.GRadioButton;
import docking.widgets.label.GLabel;
import docking.widgets.textfield.IntegerTextField;
import generic.jar.ResourceFile;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.app.services.AnalyzerType;
import ghidra.util.layout.HorizontalLayout;
import ghidra.util.layout.VerticalLayout;

public class GhidraScriptSelectionDialog extends ListSelectionDialog<ResourceFile> {
	private ButtonGroup buttonGroup;
	private IntegerTextField priorityField;

	public GhidraScriptSelectionDialog() {
		super("Create Script Based Analyzer", "Script Name:",
			GhidraScriptUtil.getScriptSourceDirectories(), new ScriptNameConverter(),
			new ScriptDescriptionConverter());
	}

	@Override
	protected JComponent buildWorkPanel(String label,
			DropDownTextFieldDataModel<ResourceFile> model) {
		JPanel panel = new JPanel(new VerticalLayout(5));
		panel.add(super.buildWorkPanel(label, model));
		panel.add(buildTypePanel());
		panel.add(buildPriorityPanel());
		return panel;
	}

	private Component buildPriorityPanel() {
		JPanel panel = new JPanel();
		panel.setBorder(BorderFactory.createEmptyBorder(0, 40, 20, 0));
		panel.add(new GLabel("Priority:  "));
		priorityField = new IntegerTextField(5, 0L);
		panel.add(priorityField.getComponent());
		return panel;
	}

	private JComponent createButtonComponent(AnalyzerType type) {
		JPanel panel = new JPanel(new HorizontalLayout(1));
		Icon icon = AnalyzerUtil.getIcon(type);
		GRadioButton button = new GRadioButton();
		button.setActionCommand(type.name());
		button.setToolTipText(type.getDescription());
		if (buttonGroup == null) {
			buttonGroup = new ButtonGroup();
		}
		buttonGroup.add(button);
		panel.add(button, BorderLayout.WEST);
		JLabel label = new GLabel(type.getName(), icon, SwingConstants.LEFT);
		label.setToolTipText(type.getDescription());
		panel.add(label);
		return panel;
	}

	private JComponent buildTypePanel() {
		JPanel panel = new JPanel(new GridLayout(0, 2, 10, 10));
		panel.add(createButtonComponent(AnalyzerType.ONE_SHOT_ANALYZER));
		buttonGroup.setSelected(buttonGroup.getElements().nextElement().getModel(), true);
		panel.add(createButtonComponent(AnalyzerType.FUNCTION_ANALYZER));
		panel.add(createButtonComponent(AnalyzerType.BYTE_ANALYZER));
		panel.add(createButtonComponent(AnalyzerType.FUNCTION_MODIFIERS_ANALYZER));
		panel.add(createButtonComponent(AnalyzerType.INSTRUCTION_ANALYZER));
		panel.add(createButtonComponent(AnalyzerType.FUNCTION_SIGNATURES_ANALYZER));
		panel.add(createButtonComponent(AnalyzerType.DATA_ANALYZER));
		Border inner = BorderFactory.createTitledBorder("Analyzer Type");
		Border outer = BorderFactory.createEmptyBorder(0, 20, 20, 20);
		panel.setBorder(BorderFactory.createCompoundBorder(outer, inner));
		return panel;
	}

	public AnalyzerType getAnalyzerType() {
		ButtonModel selection = buttonGroup.getSelection();
		String actionCommand = selection.getActionCommand();
		return AnalyzerType.valueOf(actionCommand);
	}

	public int getPriority() {
		return priorityField.getIntValue();
	}

	public ResourceFile getScriptFile() {
		return getSelectedItem();
	}

	private static class ScriptNameConverter implements DataToStringConverter<ResourceFile> {
		@Override
		public String getString(ResourceFile resourceFile) {
			return resourceFile.getName();
		}
	}

	private static class ScriptDescriptionConverter implements DataToStringConverter<ResourceFile> {
		@Override
		public String getString(ResourceFile resourceFile) {
			return GhidraScriptUtil.newScriptInfo(resourceFile).getDescription();
		}
	}

}
