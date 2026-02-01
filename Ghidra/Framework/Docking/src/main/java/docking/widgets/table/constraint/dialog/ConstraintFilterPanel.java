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
import docking.widgets.list.GComboBoxCellRenderer;
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
		constraintComboBox.getAccessibleContext().setAccessibleName("Filter");
		constraintComboBox.setRenderer(new ConstraintComboBoxCellRenderer());
		constraintComboBox.addActionListener(constraintComboBoxListener);
		panel.add(constraintComboBox, BorderLayout.CENTER);
		updateConstraintComboBoxModel();
		return panel;
	}

	private Component buildButtonPanel() {
		JPanel panel = new JPanel(new BorderLayout());
		Icon icon = Icons.DELETE_ICON;

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

	/**
	 * Gets the column value for the given component.  The column value is relative to the dialog's
	 * grid of components.  This returns -1 if the given component is not inside the component 
	 * hierarchy of this filter panel.
	 * 
	 * @param component the component
	 * @return the column
	 * @see #getActiveComponent(int)
	 */
	int getActiveComponentColumn(Component component) {

		// Note: we provide a combo for choosing a condition and a field for entering a value.
		// The client of this class has a combo that is first in the row.  We will allow that parent
		// widget to be column 0, so we will use column 1 and 2 for our widgets.
		if (constraintComboBox == component) {
			return 1;
		}
		else if (SwingUtilities.isDescendingFrom(component, inlineEditorPanel)) {
			return 2;
		}

		return -1;
	}

	/**
	 * Gets the component for the given column value.
	 * @param col the column value
	 * @return the component
	 * @see #getActiveComponentColumn(Component)
	 */
	Component getActiveComponent(int col) {
		if (col == 1) {
			return constraintComboBox;
		}
		else if (col == 2) {
			return inlineEditorPanel;
		}
		return null;
	}

	private class ConstraintComboBoxCellRenderer
			extends GComboBoxCellRenderer<ColumnConstraint<?>> {
		@Override
		protected String getItemText(ColumnConstraint<?> value) {
			return value.getName();
		}
	}

}
