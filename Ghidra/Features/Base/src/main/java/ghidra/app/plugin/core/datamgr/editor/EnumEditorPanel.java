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
package ghidra.app.plugin.core.datamgr.editor;

import java.awt.*;
import java.awt.event.*;
import java.util.*;

import javax.swing.*;
import javax.swing.event.*;
import javax.swing.table.TableCellEditor;
import javax.swing.table.TableModel;

import docking.widgets.OptionDialog;
import docking.widgets.combobox.GhidraComboBox;
import docking.widgets.label.GDLabel;
import docking.widgets.label.GLabel;
import docking.widgets.table.GTableCellRenderer;
import docking.widgets.table.GTableTextCellEditor;
import docking.widgets.textfield.GValidatedTextField;
import docking.widgets.textfield.GValidatedTextField.LongField.LongValidator;
import docking.widgets.textfield.GValidatedTextField.ValidationFailedException;
import docking.widgets.textfield.GValidatedTextField.ValidationMessageListener;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.DataTypeArchive;
import ghidra.program.model.listing.Program;
import ghidra.util.InvalidNameException;
import ghidra.util.Msg;
import ghidra.util.table.GhidraTable;

/**
 * Panel for editing enumeration data types.
 * 
 * 
 */
class EnumEditorPanel extends JPanel {

	// Normal color for selecting components in the table.
	//private static final Color SELECTION_COLOR = Color.YELLOW.brighter().brighter();

	private JTable table;
	private JTextField nameField;
	private JTextField descField;
	private JLabel descLabel;
	private JTextField categoryField;
	private GhidraComboBox sizeComboBox;

	private EnumTableModel tableModel;
	private EnumEditorProvider provider;
	private DocumentListener docListener;

	private EnumDataType originalEnumDT;
	private EnumDataType editedEnumDT;

	EnumEditorPanel(EnumDataType enumDT, EnumEditorProvider provider) {
		super(new BorderLayout());
		this.originalEnumDT = enumDT;
		this.editedEnumDT = (EnumDataType) enumDT.copy(enumDT.getDataTypeManager());
		this.provider = provider;
		create(editedEnumDT);
		setFieldInfo(editedEnumDT);
		createDocumentListener();
		nameField.getDocument().addDocumentListener(docListener);
		descField.getDocument().addDocumentListener(docListener);
	}

	EnumDataType getEnum() {
		return editedEnumDT;
	}

	Class<?> getTableClass() {
		return EnumTable.class;
	}

	JTable getTable() {
		return table;
	}

	/**
	 * Get the selected row numbers in the model.
	 * @return
	 */
	int[] getSelectedRows() {
		return table.getSelectedRows();
	}

	boolean needsSave() {
		return originalEnumDT.getDataTypeManager() != editedEnumDT.getDataTypeManager() ||
			!editedEnumDT.getCategoryPath().equals(originalEnumDT.getCategoryPath()) ||
			!editedEnumDT.getName().equals(originalEnumDT.getName()) ||
			!editedEnumDT.isEquivalent(originalEnumDT) ||
			!editedEnumDT.getDescription().equals(originalEnumDT.getDescription());
	}

	void restoreSelection(final String name, boolean modelChanged) {

		if (modelChanged) {
			tableModel.fireTableDataChanged();
		}

		// invoke later because the key press on the table causes the selection
		// to change
		SwingUtilities.invokeLater(() -> {
			try {
				if (table.isEditing()) {
					return; // don't change the selection if a new edit is in progress
				}

				int row = tableModel.getRow(name);
				if (row >= 0 && row < tableModel.getRowCount()) {
					table.setRowSelectionInterval(row, row);
					Rectangle rect = table.getCellRect(row, 0, false);
					table.scrollRectToVisible(rect);
				}
			}
			catch (NoSuchElementException e) {
				// ignore
			}
		});
	}

	void domainObjectRestored(DataTypeManagerDomainObject domainObject, EnumDataType enuum) {

		stopCellEditing();
		this.originalEnumDT = enuum;
		this.editedEnumDT = (EnumDataType) enuum.copy(enuum.getDataTypeManager());
		DataTypeManager objectDataTypeManager = domainObject.getDataTypeManager();
		DataTypeManager providerDataTypeManager = provider.getDataTypeManager();
		if (objectDataTypeManager != providerDataTypeManager) {
			return; // The editor isn't associated with the restored domain object.
		}
		String objectType = "domain object";
		if (domainObject instanceof Program) {
			objectType = "program";
		}
		else if (domainObject instanceof DataTypeArchive) {
			objectType = "data type archive";
		}
		if (tableModel.hasChanges()) {
			if (OptionDialog.showYesNoDialogWithNoAsDefaultButton(this, "Reload Enum Editor?",
				"The " + objectType + " \"" + objectDataTypeManager.getName() +
					"\" has been restored.\n" + "\"" + tableModel.getEnum().getDisplayName() +
					"\" may have changed outside this editor.\n" +
					"Do you want to discard edits and reload the Enum?") == OptionDialog.OPTION_TWO) {

				// no
				categoryField.setText(provider.getCategoryText());
				return; // Don't reload.
			}
		}
		// Reloading the enum.
		setFieldInfo(editedEnumDT);
		tableModel.setEnum(editedEnumDT, false);
	}

	String getDescription() {
		String desc = descField.getText();
		if (desc.length() == 0) {
			desc = null;
		}
		return desc;
	}

	String getEnumName() {
		return nameField.getText();
	}

	void stateChanged(ChangeEvent e) {
		provider.stateChanged(e);
	}

	void setStatusMessage(String msg) {
		provider.setStatusMessage(msg);
	}

	void setEnum(EnumDataType enumDT) {
		this.originalEnumDT = enumDT;
		this.editedEnumDT = (EnumDataType) enumDT.copy(enumDT.getDataTypeManager());
		tableModel.setEnum(editedEnumDT, false);
	}

	void enumChanged(EnumDataType enuum) {
		originalEnumDT = enuum;
		EnumDataType myEnum = editedEnumDT;
		if (!enuum.getName().equals(myEnum.getName())) {
			updateNameField(enuum.getName());
		}

		updateDescription(enuum);
		sizeComboBox.setSelectedItem(enuum.getLength());

		if (!enuum.isEquivalent(myEnum)) {
			myEnum.replaceWith(enuum);
			tableModel.setEnum(myEnum, true);
		}
	}

	private void updateDescription(EnumDataType enuum) {
		String descr = editedEnumDT.getDescription();
		String otherDesc = enuum.getDescription();
		boolean doUpdate = false;
		if (descr != null && !descr.equals(otherDesc)) {
			doUpdate = true;
		}
		else if (otherDesc != null && !otherDesc.equals(descr)) {
			doUpdate = true;
		}
		if (doUpdate) {
			editedEnumDT.setDescription(otherDesc);
			descField.getDocument().removeDocumentListener(docListener);
			descField.setText(otherDesc != null ? otherDesc : "");
			descField.getDocument().addDocumentListener(docListener);
		}
	}

	void deleteSelectedEntries() {
		EnumDataType enuum = getEnum();
		int[] rows = getSelectedRows();
		for (int row : rows) {
			String name = tableModel.getNameAt(row);
			enuum.remove(name);
		}
		tableModel.setEnum(enuum, true);
		provider.stateChanged(null);

		// select the next row based on what was selected
		Arrays.sort(rows);
		int row = rows[rows.length - 1] + 1 - rows.length;
		int count = enuum.getCount();
		if (row >= count) {
			row = count - 1;
		}
		if (row >= 0) {
			table.setRowSelectionInterval(row, row);
		}
	}

	/**
	 * Add new entry for the enum.
	 */
	void addEntry() {
		stopCellEditing();
		final int newRow = tableModel.addEntry(table.getSelectedRow());
		if (newRow < 0) {
			Msg.showError(this, this, "Enum is full",
				"All possible Enum values have already been used");
			return;
		}
		SwingUtilities.invokeLater(() -> {
			table.setRowSelectionInterval(newRow, newRow);
			table.editCellAt(newRow, EnumTableModel.NAME_COL);
			Rectangle r = table.getCellRect(newRow, 0, true);
			table.scrollRectToVisible(r);
			provider.stateChanged(null);
		});
	}

	void dispose() {
		tableModel.dispose();
	}

	void updateNameField(String newName) {
		try {
			originalEnumDT.setName(newName);
			editedEnumDT.setName(newName);
			provider.setTitle(newName);
			nameField.getDocument().removeDocumentListener(docListener);
			nameField.setText(newName);
			nameField.getDocument().addDocumentListener(docListener);
		}
		catch (InvalidNameException e) {
			// ignore; the name comes from an already validated external update
		}
	}

	void updateCategoryField(String categoryPath) {
		categoryField.setText(categoryPath);
	}

	void stopCellEditing() {
		TableCellEditor cellEditor = table.getCellEditor();
		if (cellEditor != null) {
			cellEditor.stopCellEditing();
		}
	}

	private void create(EnumDataType enumDT) {
		tableModel = new EnumTableModel(enumDT, this);

		table = new EnumTable(tableModel);

		JScrollPane sp = new JScrollPane(table);
		table.setPreferredScrollableViewportSize(new Dimension(300, 120));
		table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
		add(sp, BorderLayout.CENTER);

		EnumCellRenderer cellRenderer = new EnumCellRenderer();
		table.setRowHeight(table.getRowHeight() + 4);
		table.setDefaultEditor(String.class, new EnumStringCellEditor());
		table.getColumnModel()
				.getColumn(EnumTableModel.VALUE_COL)
				.setCellEditor(
					new EnumLongCellEditor());
		table.setDefaultRenderer(String.class, cellRenderer);
		add(createInfoPanel(), BorderLayout.SOUTH);

	}

	private void createDocumentListener() {
		docListener = new DocumentListener() {
			@Override
			public void changedUpdate(DocumentEvent e) {
				changed();
			}

			@Override
			public void insertUpdate(DocumentEvent e) {
				changed();
			}

			@Override
			public void removeUpdate(DocumentEvent e) {
				changed();
			}

			private void changed() {
				String name = nameField.getText().trim();
				if (name.length() == 0) {
					return;
				}

				if (!name.equals(editedEnumDT.getName())) {
					try {
						editedEnumDT.setName(name);
					}
					catch (InvalidNameException e) {
						setStatusMessage("'" + name + "' is not a valid name");
					}
				}

				String description = descField.getText();
				if (!description.equals(editedEnumDT.getDescription())) {
					editedEnumDT.setDescription(description);
				}

				provider.stateChanged(null);
			}
		};
	}

	private JPanel createInfoPanel() {

		JPanel outerPanel = new JPanel();
		outerPanel.setLayout(new BoxLayout(outerPanel, BoxLayout.Y_AXIS));
		outerPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
		JPanel descPanel = createDescriptionPanel();
		outerPanel.add(createNamePanel());
		outerPanel.add(Box.createVerticalStrut(2));
		outerPanel.add(descPanel);
		outerPanel.add(Box.createVerticalStrut(2));
		outerPanel.add(createCategoryPanel());

		return outerPanel;
	}

	private JPanel createNamePanel() {
		nameField = new JTextField(20);
		nameField.setName("Name");

		JPanel panel = new JPanel();
		panel.setLayout(new BoxLayout(panel, BoxLayout.X_AXIS));

		JLabel label = new GLabel("Name:", SwingConstants.RIGHT);
		label.setPreferredSize(new Dimension(descLabel.getPreferredSize()));
		panel.add(label);
		panel.add(Box.createHorizontalStrut(2));
		panel.add(nameField);

		return panel;
	}

	private JPanel createDescriptionPanel() {
		descField = new JTextField(20);
		descField.setName("Description");

		JPanel panel = new JPanel();
		panel.setLayout(new BoxLayout(panel, BoxLayout.X_AXIS));

		descLabel = new GDLabel("Description:", SwingConstants.RIGHT);

		panel.add(descLabel);
		panel.add(Box.createHorizontalStrut(2));
		panel.add(descField);

		return panel;
	}

	private JPanel createCategoryPanel() {
		JPanel panel = new JPanel();
		panel.setLayout(new BoxLayout(panel, BoxLayout.X_AXIS));

		categoryField = new JTextField(24);
		categoryField.setEditable(false);
		categoryField.setName("Category");

		sizeComboBox = new GhidraComboBox(new Integer[] { 1, 2, 4, 8 });
		sizeComboBox.setName("Size");
		sizeComboBox.addItemListener(e -> {
			Integer length = (Integer) sizeComboBox.getSelectedItem();
			if (!validateNewLength(length)) {
				return;
			}

			setStatusMessage("");
			tableModel.setLength(length);
			provider.stateChanged(null);
		});

		JLabel label = new GLabel("Category:", SwingConstants.RIGHT);
		label.setPreferredSize(new Dimension(descLabel.getPreferredSize()));
		panel.add(label);
		panel.add(Box.createHorizontalStrut(2));
		panel.add(categoryField);
		panel.add(Box.createHorizontalStrut(20));
		panel.add(new GLabel("Size:"));
		panel.add(Box.createHorizontalStrut(5));
		panel.add(sizeComboBox);

		return panel;
	}

	private boolean validateNewLength(Integer length) {
		EnumDataType enuum = tableModel.getEnum();
		String[] names = enuum.getNames();
		for (String name : names) {
			long value = enuum.getValue(name);
			if (tableModel.isValueTooBigForLength(value, length)) {
				vetoSizeChange(length, enuum.getLength(), value);
				return false;
			}
		}
		return true;
	}

	private boolean validateNewValue(Long value) {
		EnumDataType enuum = tableModel.getEnum();
		int length = enuum.getLength();
		return !tableModel.isValueTooBigForLength(value, length);
	}

	private void vetoSizeChange(final int newLength, final int currentLength, final long badValue) {
		SwingUtilities.invokeLater(() -> {
			setStatusMessage("Enum size of " + newLength + " cannot contain the value " + "0x" +
				Long.toHexString(badValue));
			sizeComboBox.setSelectedItem(new Integer(currentLength));
		});
	}

	public String getValidValuesMessage() {
		EnumDataType enuum = tableModel.getEnum();
		int length = enuum.getLength();
		long maxValue = length == 8 ? -1 : (1L << (8 * length)) - 1;
		return "Valid values are from 0x0 to 0x" + Long.toHexString(maxValue);

	}

	private void setFieldInfo(EnumDataType enuum) {
		nameField.setText(enuum.getDisplayName());
		sizeComboBox.setSelectedItem(enuum.getLength());
		String description = enuum.getDescription();
		if (description == null) {
			description = "";
		}
		descField.setText(description);
		categoryField.setText(provider.getCategoryText());
	}

	private void focus(final JTextField field) {
		SwingUtilities.invokeLater(() -> {
			field.requestFocusInWindow();
			field.selectAll();
		});
	}

//==================================================================================================
// Inner Classes
//==================================================================================================	

	private class EnumTable extends GhidraTable {
		EnumTable(TableModel model) {
			super(model);
			setAutoEditEnabled(true);
		}
	}

	public class RangeValidator extends LongValidator {
		@Override
		public void validateLong(long oldLong, long newLong) throws ValidationFailedException {
			if (!validateNewValue(newLong)) {
				throw new ValidationFailedException(getValidValuesMessage());
			}
		}
	}

	public class StatusBarValidationMessageListener implements ValidationMessageListener {
		@Override
		public void message(String msg) {
			setStatusMessage(msg);
		}
	}

	private abstract class EnumCellEditor extends GTableTextCellEditor {
		public EnumCellEditor(JTextField textField) {
			super(textField);
			textField.addKeyListener(editingKeyListener);
			textField.addActionListener(e -> table.editingStopped(null));
		}

		@Override
		public Component getTableCellEditorComponent(JTable table1, Object value,
				boolean isSelected, int row, int column) {
			setStatusMessage("");
			focus((JTextField) getComponent());
			return super.getTableCellEditorComponent(table1, value, isSelected, row, column);
		}

		@Override
		public boolean isCellEditable(EventObject e) {
			if (e instanceof KeyEvent) {
				KeyEvent ke = (KeyEvent) e;
				if (ke.getKeyCode() == KeyEvent.VK_F2) {
					return true;
				}
			}
			return super.isCellEditable(e);
		}

		private KeyListener editingKeyListener = new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				int keycode = e.getKeyCode();

				if (!table.isEditing()) {
					return;
				}

				int row = table.getEditingRow();
				int col = table.getEditingColumn();

				int rowCount = table.getRowCount();
				int columnCount = table.getColumnCount();

				switch (keycode) {
					case KeyEvent.VK_TAB:
						if (e.isShiftDown()) {
							if (--col < 0) {
								col = columnCount - 1;
								if (--row < 0) {
									row = rowCount - 1;
									col = columnCount - 1;
								}
							}
						}
						else {
							if (++col == columnCount) {
								col = 0;

								if (++row == rowCount) {
									row = 0;
								}
							}
						}
						break;
					case KeyEvent.VK_DOWN:
						if (++row == rowCount) {
							row = 0;
						}
						break;
					case KeyEvent.VK_UP:
						if (--row < 0) {
							row = rowCount - 1;
						}
						break;
					default:
						return;
				}

				e.consume();

				table.setRowSelectionInterval(row, row);
				table.editCellAt(row, col);
			}
		};
	}

	private class EnumStringCellEditor extends EnumCellEditor {
		public EnumStringCellEditor() {
			super(new JTextField());
		}
	}

	private class EnumLongCellEditor extends EnumCellEditor {
		public EnumLongCellEditor() {
			super(new GValidatedTextField.LongField(8));
			GValidatedTextField f = (GValidatedTextField) getComponent();
			f.addValidator(new RangeValidator());
			f.addValidationMessageListener(new StatusBarValidationMessageListener());
		}
	}

	private class EnumCellRenderer extends GTableCellRenderer {
		// Might just be kruft, now...
	}
}
