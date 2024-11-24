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
import java.util.Arrays;
import java.util.EventObject;

import javax.swing.*;
import javax.swing.event.*;
import javax.swing.table.TableCellEditor;
import javax.swing.table.TableModel;

import docking.widgets.OptionDialog;
import docking.widgets.combobox.GhidraComboBox;
import docking.widgets.label.GDLabel;
import docking.widgets.label.GLabel;
import docking.widgets.table.*;
import docking.widgets.textfield.GValidatedTextField;
import docking.widgets.textfield.GValidatedTextField.LongField.LongValidator;
import docking.widgets.textfield.GValidatedTextField.ValidationFailedException;
import docking.widgets.textfield.GValidatedTextField.ValidationMessageListener;
import ghidra.docking.settings.Settings;
import ghidra.program.model.data.*;
import ghidra.util.*;
import ghidra.util.table.GhidraTable;

class EnumEditorPanel extends JPanel {

	private JTable table;
	private JTextField nameField;
	private JTextField descField;
	private JLabel descLabel;
	private JTextField categoryField;
	private GhidraComboBox<?> sizeComboBox;

	private EnumTableModel tableModel;
	private EnumEditorProvider provider;
	private DocumentListener docListener;

	private EnumDataType originalEnumDT;
	private EnumDataType editedEnumDT;
	boolean showValuesAsHex = true;

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

		// invoke later because the key press on the table causes the selection to change
		Swing.runLater(() -> {
			if (table.isEditing()) {
				return; // don't change the selection if a new edit is in progress
			}

			int row = tableModel.getRow(name);
			if (row >= 0 && row < tableModel.getRowCount()) {
				table.setRowSelectionInterval(row, row);
				Rectangle rect = table.getCellRect(row, 0, false);
				table.scrollRectToVisible(rect);
			}
		});
	}

	void domainObjectRestored(EnumDataType enuum, boolean exists) {

		stopCellEditing();

		DataTypeManager enumDtMgr = enuum.getDataTypeManager();
		String objectType = "domain object";
		if (enumDtMgr instanceof ProgramBasedDataTypeManager) {
			objectType = "program";
		}
		else {
			objectType = "data type archive";
		}
		String archiveName = enumDtMgr.getName();
		this.originalEnumDT = enuum;

		if (!exists) {
			if (OptionDialog.showOptionNoCancelDialog(this, "Close Enum Editor?",
				"The " + objectType + " \"" + archiveName + "\" has been restored.\n" + "\"" +
					enuum.getDisplayName() + "\" may no longer exist outside the editor.\n" +
					"Do you want to close editor?",
				"Close", "Continue Edit",
				OptionDialog.WARNING_MESSAGE) == OptionDialog.OPTION_ONE) {
				provider.dispose();
			}
			else {
				provider.stateChanged(null);
			}
			return;
		}

		if (exists && tableModel.hasChanges()) {
			if (OptionDialog.showYesNoDialogWithNoAsDefaultButton(this, "Reload Enum Editor?",
				"The " + objectType + " \"" + archiveName + "\" has been restored.\n" + "\"" +
					enuum.getDisplayName() + "\" may have changed outside this editor.\n" +
					"Do you want to discard edits and reload the Enum?") == OptionDialog.OPTION_TWO) {

				// 'No'; do not discard
				categoryField.setText(provider.getCategoryText());
				return; // don't reload
			}
		}

		// reload the enum
		this.editedEnumDT = (EnumDataType) enuum.copy(enuum.getDataTypeManager());
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

	void addEntry() {
		stopCellEditing();
		int newRow = tableModel.addEntry(table.getSelectedRow());
		if (newRow < 0) {
			Msg.showError(this, this, "Enum is full",
				"All possible Enum values have already been used");
			return;
		}

		Swing.runLater(() -> {
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

		table.setRowHeight(table.getRowHeight() + 4);
		table.setDefaultEditor(String.class, new EnumStringCellEditor());
		table.getColumnModel()
				.getColumn(EnumTableModel.VALUE_COL)
				.setCellEditor(new EnumLongCellEditor());
		table.setDefaultRenderer(String.class, new GTableCellRenderer());
		table.setDefaultRenderer(Long.class, new EnumValueRenderer());
		add(createInfoPanel(), BorderLayout.SOUTH);
	}

	private String getValueAsString(long value) {
		if (showValuesAsHex) {
			int length = editedEnumDT.getLength();
			if (editedEnumDT.isSigned()) {
				return NumericUtilities.toSignedHexString(value);
			}
			return NumericUtilities.toHexString(value, length);
		}
		return Long.toString(value);

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

		sizeComboBox = new GhidraComboBox<>(new Integer[] { 1, 2, 4, 8 });
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
		int minLength = enuum.getMinimumPossibleLength();
		if (length < minLength) {
			vetoSizeChange(length, minLength, enuum.getLength());
			return false;
		}
		return true;
	}

	private void vetoSizeChange(int newLength, int minLength, int currentLength) {
		Swing.runLater(() -> {
			setStatusMessage(
				"Enum size of " + newLength + " is smaller than minimum enum size of " + minLength);
			sizeComboBox.setSelectedItem(Integer.valueOf(currentLength));
		});
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

	private void focus(JTextField field) {
		Swing.runLater(() -> {
			field.requestFocusInWindow();
			field.selectAll();
		});
	}

	void setHexDisplayMode(boolean showHex) {
		showValuesAsHex = showHex;
		tableModel.fireTableDataChanged();
	}

	String getSelectedFieldName() {

		int row = table.getSelectedRow();
		if (row < 0) {
			return null;
		}
		EnumEntry enumEntry = tableModel.getRowObject(row);
		return enumEntry.getName();
	}

	private void edit(int row, int col) {
		scrollToCell(row, col);
		table.setRowSelectionInterval(row, row);
		table.editCellAt(row, col);
	}

	private void scrollToCell(int row, int col) {
		if (table.getAutoscrolls()) {
			Rectangle cellRect = table.getCellRect(row, col, false);
			if (cellRect != null) {
				table.scrollRectToVisible(cellRect);
			}
		}
	}

	private int getRow(EnumEntry entry) {
		return tableModel.getRowIndex(entry);
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
		private long min;
		private long max;

		public void setOriginalValue(long originalLong) {
			EnumDataType enuum = tableModel.getEnum();
			EnumDataType copy = (EnumDataType) enuum.copy(enuum.getDataTypeManager());
			String name = copy.getName(originalLong);
			copy.remove(name);
			min = copy.getMinPossibleValue();
			max = copy.getMaxPossibleValue();
		}

		@Override
		public void validateLong(long oldValue, long newValue) throws ValidationFailedException {
			if (newValue < min || newValue > max) {
				String minValue = getValueAsString(min);
				String maxValue = getValueAsString(max);
				String message =
					"Valid values are in the range (" + minValue + ", " + maxValue + ")";
				throw new ValidationFailedException(message);
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

				if (!table.isEditing()) {
					return;
				}

				int code = e.getKeyCode();
				boolean moveEdit =
					code == KeyEvent.VK_TAB || code == KeyEvent.VK_UP || code == KeyEvent.VK_DOWN;
				if (!moveEdit) {
					return;
				}

				e.consume();

				int row = table.getEditingRow();
				int col = table.getEditingColumn();

				// 
				// The user has attempted to edit a new cell while there is an edit in progress. The
				// table may get re-sorted when this happens, as the current edit may get committed, 
				// which can affect the table's sort.  In this case, we need to find where the 
				// currently edited cell is moved to so that we can correctly move to the user's 
				// requested cell, which is relative to the current cell being edited.
				//
				EnumEntry editedEntry = tableModel.getRowObject(row);

				TableCellEditor editor = table.getCellEditor();
				editor.stopCellEditing();

				CellEditRequest cellEditRequest =
					new CellEditRequest(EnumEditorPanel.this, editedEntry, col, e);
				Swing.runLater(cellEditRequest);
			}
		};

		private record CellEditRequest(EnumEditorPanel editorPanel, EnumEntry editedEntry,
				int editCol, KeyEvent e) implements Runnable {

			@Override
			public void run() {

				JTable table = editorPanel.table;

				// note: this lookup works because equals() is *not* overridden and any edits are
				// applied to the object in memory so that the default '==' lookup works.
				int row = editorPanel.getRow(editedEntry);
				int col = editCol;
				int rowCount = table.getRowCount();
				switch (e.getKeyCode()) {
					case KeyEvent.VK_TAB:
						boolean forward = !e.isShiftDown();
						editNextCell(table, forward, row, col);
						return;
					case KeyEvent.VK_DOWN:
						if (++row == rowCount) {
							row = 0;
						}
						editorPanel.edit(row, col);
						return;
					case KeyEvent.VK_UP:
						if (--row < 0) {
							row = rowCount - 1;
						}
						editorPanel.edit(row, col);
						return;
					default:
						return;
				}

			}

			private void editNextCell(JTable table, boolean forward, int row, int col) {

				int columnCount = table.getColumnCount();
				int rowCount = table.getRowCount();
				if (forward) {

					int nextRow = row;
					int nextCol = col + 1;
					if (nextCol == columnCount) {

						// wrap to the next row
						nextCol = 0;
						nextRow++;
						if (nextRow == rowCount) {
							// wrap to the first row
							nextRow = 0;
						}
					}

					editorPanel.edit(nextRow, nextCol);
					return;
				}

				// going backward
				int nextRow = row;
				int nextCol = col - 1;
				if (nextCol < 0) {
					nextCol = columnCount - 1;

					nextRow--;
					if (nextRow < 0) {
						nextRow = rowCount - 1;
						nextCol = columnCount - 1;
					}
				}

				editorPanel.edit(nextRow, nextCol);
			}

		}
	}

	private class EnumStringCellEditor extends EnumCellEditor {
		public EnumStringCellEditor() {
			super(new JTextField());
		}
	}

	private class EnumLongCellEditor extends EnumCellEditor {
		private RangeValidator validator;

		public EnumLongCellEditor() {
			super(new GValidatedTextField.LongField(8));
			GValidatedTextField f = (GValidatedTextField) getComponent();
			validator = new RangeValidator();
			f.addValidator(validator);
			f.addValidationMessageListener(new StatusBarValidationMessageListener());
		}

		@Override
		public Component getTableCellEditorComponent(JTable table1, Object value,
				boolean isSelected, int row, int column) {
			Long longValue = (Long) value;
			validator.setOriginalValue(longValue);
			String s = getValueAsString(longValue);
			return super.getTableCellEditorComponent(table1, s, isSelected, row, column);
		}

	}

	private class EnumValueRenderer extends GTableCellRenderer {
		EnumValueRenderer() {
			setFont(getFixedWidthFont());
		}

		@Override
		public Component getTableCellRendererComponent(GTableCellRenderingData data) {
			JLabel renderer = (JLabel) super.getTableCellRendererComponent(data);
			renderer.setHorizontalAlignment(SwingConstants.RIGHT);
			return renderer;
		}

		@Override
		protected String formatNumber(Number value, Settings settings) {
			if (value instanceof Long longValue) {
				return getValueAsString(longValue);
			}
			return "";
		}
	}

}
