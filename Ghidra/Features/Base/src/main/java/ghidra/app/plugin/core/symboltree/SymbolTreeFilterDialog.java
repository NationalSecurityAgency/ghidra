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
package ghidra.app.plugin.core.symboltree;

import java.awt.Component;

import javax.swing.*;
import javax.swing.border.Border;

import docking.DialogComponentProvider;
import docking.widgets.checkbox.GCheckBox;
import ghidra.util.HelpLocation;
import ghidra.util.MessageType;
import ghidra.util.layout.VerticalLayout;

public class SymbolTreeFilterDialog extends DialogComponentProvider {

	private SymbolTreeFilterState filterState;
	private SymbolTreeFilterState originalFilterState;
	private SymbolTreeProvider provider;

	protected SymbolTreeFilterDialog(SymbolTreeProvider provider,
			SymbolTreeFilterState filterState) {
		super("Configure Symbol Tree");
		this.provider = provider;
		this.originalFilterState = filterState;
		this.filterState = filterState;

		setHelpLocation(new HelpLocation("SymbolTreePlugin", "Symbol_Tree_Settings"));
		addWorkPanel(buildMainPanel());
		addOKButton();
		addDismissButton();
		setRememberSize(false);
		updateButtonEnablement();
	}

	@Override
	protected void okCallback() {
		provider.setSymbolTreeSettings(filterState);
		close();
	}

	private void updateButtonEnablement() {
		boolean isChanged = !originalFilterState.equals(filterState);
		boolean isValid = checkValid();
		boolean isEnabled = isChanged && isValid;
		okButton.setEnabled(isEnabled);
	}

	private boolean checkValid() {
		clearStatusText();
		if (!filterState.includesAtLeastOneCateogry()) {
			setStatusText("You must select at least one category", MessageType.ERROR);
			return false;
		}
		return true;
	}

	private JComponent buildMainPanel() {
		JPanel panel = new JPanel(new VerticalLayout(20));
		panel.setBorder(BorderFactory.createEmptyBorder(20, 60, 20, 60));
		panel.add(buildColumnPanel());
		panel.add(buildSymbolTypesPanel());
		return panel;
	}

	private Component buildColumnPanel() {
		JPanel panel = new JPanel(new VerticalLayout(5));
		Border outerBorder = BorderFactory.createTitledBorder("Symbol Categories");
		Border innerBorder = BorderFactory.createEmptyBorder(10, 30, 5, 30);
		panel.setBorder(BorderFactory.createCompoundBorder(outerBorder, innerBorder));
		JCheckBox importsCb = new GCheckBox("Imports", filterState.showImports());
		JCheckBox exportsCb = new GCheckBox("Exports", filterState.showExports());
		JCheckBox globalsCb = new GCheckBox("Globals", filterState.showGlobals());
		JCheckBox namespacesCb = new GCheckBox("Namespaces", filterState.showNamespaces());

		importsCb.addActionListener(e -> {
			filterState = filterState.withImports(importsCb.isSelected());
			updateButtonEnablement();
		});

		exportsCb.addActionListener(e -> {
			filterState = filterState.withExports(exportsCb.isSelected());
			updateButtonEnablement();
		});

		globalsCb.addActionListener(e -> {
			filterState = filterState.withGlobals(globalsCb.isSelected());
			updateButtonEnablement();
		});

		namespacesCb.addActionListener(e -> {
			filterState = filterState.withNamespaces(namespacesCb.isSelected());
			updateButtonEnablement();
		});

		panel.add(importsCb);
		panel.add(exportsCb);
		panel.add(globalsCb);
		panel.add(namespacesCb);

		return panel;
	}

	private Component buildSymbolTypesPanel() {
		JPanel panel = new JPanel(new VerticalLayout(5));
		Border outerBorder = BorderFactory.createTitledBorder("Symbol Types");
		Border innerBorder = BorderFactory.createEmptyBorder(10, 30, 5, 30);
		panel.setBorder(BorderFactory.createCompoundBorder(outerBorder, innerBorder));
		JCheckBox labelsCb = new GCheckBox("Labels", filterState.includeLabels());
		JCheckBox functionsCb = new GCheckBox("Functions", filterState.includeFunctions());

		labelsCb.addActionListener(e -> {
			filterState = filterState.withLabels(labelsCb.isSelected());
			updateButtonEnablement();
		});

		functionsCb.addActionListener(e -> {
			filterState = filterState.withFunctions(functionsCb.isSelected());
			updateButtonEnablement();
		});

		panel.add(labelsCb);
		panel.add(functionsCb);

		return panel;
	}

}
