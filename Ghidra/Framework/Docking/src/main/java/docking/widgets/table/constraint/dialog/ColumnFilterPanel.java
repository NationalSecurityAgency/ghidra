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
package docking.widgets.table.constraint.dialog;

import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Vector;

import javax.swing.*;
import javax.swing.border.BevelBorder;

import docking.widgets.EmptyBorderButton;
import docking.widgets.combobox.GhidraComboBox;
import docking.widgets.label.GDLabel;
import docking.widgets.list.GListCellRenderer;
import ghidra.util.layout.VerticalLayout;
import resources.ResourceManager;

/**
 * Panel for displaying a single column filter entry.  This consists of multiple ConstraintFilterPanels
 * for each "OR" condition in this column filter entry.
 */
class ColumnFilterPanel extends JPanel {

	private static final int BUTTON_ICON_SIZE = 16;
	private DialogFilterRow filterEntry;
	private JComboBox<ColumnFilterData<?>> columnFilterComboBox;
	private List<ConstraintFilterPanel> filterPanels = new ArrayList<>(2);

	ColumnFilterPanel(DialogFilterRow filterEntry) {
		this.filterEntry = filterEntry;

		setLayout(new BorderLayout());
		add(buildConstraintPanels(), BorderLayout.CENTER);
		add(buildButtonPanel(), BorderLayout.EAST);
		setBorder(
			BorderFactory.createCompoundBorder(BorderFactory.createBevelBorder(BevelBorder.LOWERED),
				BorderFactory.createEmptyBorder(3, 3, 3, 3)));

	}

	private Component buildButtonPanel() {
		JPanel panel = new JPanel(new BorderLayout());
		ImageIcon icon = ResourceManager.loadImage("images/Plus.png");
		icon = ResourceManager.getScaledIcon(icon, BUTTON_ICON_SIZE, BUTTON_ICON_SIZE);

		JButton button = new EmptyBorderButton(icon);
		button.setToolTipText("Add a column condition");
		button.addActionListener(e -> filterEntry.addFilterCondition());
		panel.add(button, BorderLayout.NORTH);

		return panel;
	}

	private Component buildColumnComboBox() {
		Vector<ColumnFilterData<?>> v = new Vector<>(filterEntry.getAllColumnData());

		DefaultComboBoxModel<ColumnFilterData<?>> model = new DefaultComboBoxModel<>(v);
		columnFilterComboBox = new GhidraComboBox<>(model);
		columnFilterComboBox.setRenderer(new GListCellRenderer<>() {

			@Override
			protected String getItemText(ColumnFilterData<?> value) {
				return value == null ? "" : value.getName();
			}

			@Override
			public boolean shouldAlternateRowBackgroundColor() {
				// alternating colors look odd in this combo box
				return false;
			}
		});

		columnFilterComboBox.setSelectedItem(filterEntry.getColumnFilterData());

		columnFilterComboBox.addItemListener(e -> columnChanged());
		columnFilterComboBox.addActionListener(e -> columnChanged());
		return columnFilterComboBox;
	}

	private Component buildConstraintPanels() {
		JPanel panel = new JPanel(new VerticalLayout(0));
		setBorder(BorderFactory.createEmptyBorder(5, 2, 2, 2));
		buildColumnComboBox();

		List<DialogFilterCondition<?>> filterConditions = filterEntry.getFilterConditions();

		// The first item includes a combobox for choosing the column.
		ConstraintFilterPanel filterPanel =
			new ConstraintFilterPanel(filterConditions.get(0), columnFilterComboBox);
		filterPanels.add(filterPanel);
		panel.add(filterPanel);

		// All other items have an "<OR>" label in place of the column comboBox.
		for (int i = 1; i < filterConditions.size(); i++) {
			filterPanel = new ConstraintFilterPanel(filterConditions.get(i), createOrLabel());
			filterPanels.add(filterPanel);
			panel.add(filterPanel);
		}
		return panel;
	}

	private Component createOrLabel() {
		JLabel jLabel = new GDLabel("<OR>", SwingConstants.CENTER);
		jLabel.setForeground(Color.GRAY);
		return jLabel;
	}

	private void columnChanged() {
		int selectedIndex = columnFilterComboBox.getSelectedIndex();
		ColumnFilterData<?> selectedColumnData = columnFilterComboBox.getItemAt(selectedIndex);
		filterEntry.setColumnData(selectedColumnData);
	}

	boolean hasValidFilterValue() {
		return filterEntry.hasValidFilterValue();
	}

	DialogFilterRow getColumnFilterEntry() {
		return filterEntry;
	}
}
