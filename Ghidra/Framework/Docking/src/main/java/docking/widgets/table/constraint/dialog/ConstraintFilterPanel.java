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

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.event.ActionListener;

import javax.swing.*;

import docking.widgets.EmptyBorderButton;
import docking.widgets.combobox.GComboBox;
import docking.widgets.list.GListCellRenderer;
import docking.widgets.table.constraint.ColumnConstraint;
import resources.Icons;

/**
 * Panel for display a single constraint entry within a column.
 */
public class ConstraintFilterPanel extends JPanel {

	private DialogFilterCondition<?> constraintEntry;
	private Component firstColumnComponent;
	private JComboBox<ColumnConstraint<?>> constraintComboBox;
	private JPanel inlineEditorPanel;
	private ActionListener constraintComboBoxListener = e -> constraintChanged();
	private Component detailEditorComponent;

	ConstraintFilterPanel(DialogFilterCondition<?> constraintEntry,
			Component firstColumnComponent) {
		this.constraintEntry = constraintEntry;
		this.firstColumnComponent = firstColumnComponent;

		setLayout(new BorderLayout());
		add(buildMainPanel(), BorderLayout.CENTER);
		add(buildButtonPanel(), BorderLayout.EAST);

		Component detailPanel = buildDetailEditorPanel();
		if (detailPanel != null) {
			add(detailPanel, BorderLayout.SOUTH);
		}
	}

	private Component buildMainPanel() {
		JPanel panel = new JPanel(new FilterPanelLayout(200, 5));

		panel.add(firstColumnComponent);
		panel.add(buildConstraintCombo());
		panel.add(buildInlineEditorPanel());

		return panel;
	}

	private Component buildDetailEditorPanel() {
		detailEditorComponent = constraintEntry.getDetailEditorComponent();
		if (detailEditorComponent == null) {
			return null;
		}
		JPanel panel = new JPanel(new BorderLayout());
		panel.setBorder(BorderFactory.createEmptyBorder(4, 50, 14, 20));
		panel.add(detailEditorComponent);
		return panel;
	}

	private Component buildInlineEditorPanel() {
		inlineEditorPanel = new JPanel(new BorderLayout());
		inlineEditorPanel.add(constraintEntry.getInlineEditorComponent(), BorderLayout.CENTER);
		return inlineEditorPanel;
	}

	private Component buildConstraintCombo() {
		JPanel panel = new JPanel(new BorderLayout());
		constraintComboBox = new GComboBox<>();
		constraintComboBox.setRenderer(new ConstraintComboBoxCellRenderer());
		constraintComboBox.addActionListener(constraintComboBoxListener);
		panel.add(constraintComboBox, BorderLayout.CENTER);
		updateConstraintComboBoxModel();
		return panel;
	}

	private Component buildButtonPanel() {
		JPanel panel = new JPanel(new BorderLayout());
		ImageIcon icon = Icons.DELETE_ICON;

		JButton button = new EmptyBorderButton(icon);
		button.setToolTipText("Delete entry");
		button.addActionListener(e -> constraintEntry.delete());
		panel.add(button, BorderLayout.NORTH);
		return panel;
	}

	private void constraintChanged() {
		int selectedIndex = constraintComboBox.getSelectedIndex();
		ColumnConstraint<?> selectedConstraint = constraintComboBox.getItemAt(selectedIndex);
		String constraintName = selectedConstraint.getName();
		constraintEntry.setSelectedConstraint(constraintName);
	}

	private void updateConstraintComboBoxModel() {
		constraintComboBox.removeActionListener(constraintComboBoxListener);

		ColumnConstraint<?>[] constraints = constraintEntry.getColumnConstraints();
		constraintComboBox.setModel(new DefaultComboBoxModel<>(constraints));
		constraintComboBox.setSelectedItem(constraintEntry.getSelectedConstraint());

		constraintComboBox.addActionListener(constraintComboBoxListener);
	}

	private class ConstraintComboBoxCellRenderer extends GListCellRenderer<ColumnConstraint<?>> {

		@Override
		protected String getItemText(ColumnConstraint<?> value) {
			return value.getName();
		}

		@Override
		public boolean shouldAlternateRowBackgroundColor() {
			// alternating colors look odd in this combo box
			return false;
		}
	}
}
