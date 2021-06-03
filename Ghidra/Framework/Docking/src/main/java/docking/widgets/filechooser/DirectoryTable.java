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
/*
 * Created on May 18, 2006
 */
package docking.widgets.filechooser;

import java.awt.*;
import java.awt.event.*;
import java.io.File;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;
import javax.swing.event.ChangeEvent;
import javax.swing.table.TableColumn;

import docking.event.mouse.GMouseListenerAdapter;
import docking.widgets.AutoLookup;
import docking.widgets.GenericDateCellRenderer;
import docking.widgets.table.*;
import utilities.util.FileUtilities;

class DirectoryTable extends GTable implements GhidraFileChooserDirectoryModelIf {

	private GhidraFileChooser chooser;
	private DirectoryTableModel model;
	private int rowToEdit = -1;
	private FileEditor editor;

	DirectoryTable(GhidraFileChooser chooser, DirectoryTableModel model) {
		super(model);
		this.chooser = chooser;
		this.model = model;
		build();
	}

	private void build() {
		setAutoLookupColumn(DirectoryTableModel.FILE_COL);

		setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		setShowGrid(false);

		addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				// always end editing on a mouse click of any kind
				editingCanceled(null);
				requestFocus();
			}
		});

		addMouseListener(new GMouseListenerAdapter() {

			@Override
			public boolean shouldConsume(MouseEvent e) {
				if (e.isPopupTrigger() && isEditing()) {
					return true;
				}
				return false;
			}

			@Override
			public void popupTriggered(MouseEvent e) {
				maybeSelectItem(e);
			}

			@Override
			public void doubleClickTriggered(MouseEvent e) {
				handleDoubleClick();
			}
		});

		addKeyListener(new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				if (e.getKeyCode() != KeyEvent.VK_ENTER) {
					return;
				}
				e.consume();

				int[] selectedRows = getSelectedRows();
				if (selectedRows.length == 0) {
					chooser.okCallback();
					// this implies the user has somehow put focus into the table, but has not
					// made a selection...just let the chooser decide what to do
					return;
				}

				if (selectedRows.length > 1) {
					// let the chooser decide what to do with multiple rows selected
					chooser.okCallback();
					return;
				}

				File file = model.getFile(selectedRows[0]);
				if (chooser.getModel().isDirectory(file)) {
					chooser.setCurrentDirectory(file);
				}
				else {
					chooser.userChoseFile(file);
				}
			}
		});

		// add a listener to keep the chooser in sync with user selections
		getSelectionModel().addListSelectionListener(e -> {
			if (e.getValueIsAdjusting()) {
				return;
			}
			updateChooserForSelection();
		});

		editor = new FileEditor(chooser, this, model);

		TableColumn column;

		column = columnModel.getColumn(DirectoryTableModel.FILE_COL);
		column.setCellRenderer(new FileTableCellRenderer(chooser));
		column.setCellEditor(editor);

		column = columnModel.getColumn(DirectoryTableModel.SIZE_COL);
		column.setCellRenderer(new FileSizeRenderer());

		column = columnModel.getColumn(DirectoryTableModel.TIME_COL);
		column.setCellRenderer(new GenericDateCellRenderer());
	}

	@Override
	protected AutoLookup createAutoLookup() {
		return new GTableAutoLookup(this) {
			@Override
			protected boolean canBinarySearchColumn(int column) {
				if (column == DirectoryTableModel.FILE_COL) {
					return false;
				}
				return super.canBinarySearchColumn(column);
			}
		};
	}

	private void maybeSelectItem(MouseEvent e) {
		Point point = e.getPoint();
		int row = rowAtPoint(point);
		if (row < 0) {
			return;
		}
		selectRow(row);
	}

	private void updateChooserForSelection() {
		List<File> selectedFiles = new ArrayList<>();
		int[] selectedRows = getSelectedRows();
		for (int i : selectedRows) {
			selectedFiles.add(model.getFile(i));
		}

		chooser.userSelectedFiles(selectedFiles);
	}

	private void handleDoubleClick() {
		List<File> selectedFiles = new ArrayList<>();
		int[] selectedRows = getSelectedRows();
		for (int i : selectedRows) {
			selectedFiles.add(model.getFile(i));
		}

		if (selectedFiles.size() == 0 || selectedFiles.size() > 1) {
			return; // not sure if this can happen, maybe with the Ctrl key pressed
		}

		File file = selectedFiles.get(0);
		if (chooser.getModel().isDirectory(file)) {
			chooser.setCurrentDirectory(file); // the user wants to navigate into the directory 
		}
		else {
			chooser.userChoseFile(file); // the user has chosen the file
		}
	}

	void setRowToEdit(int rowToEdit) {
		this.rowToEdit = rowToEdit;
	}

	@Override
	public File getSelectedFile() {
		int row = getSelectedRow();
		if (row < 0) {
			return null;
		}
		return model.getFile(row);
	}

	@Override
	public File getFile(int row) {
		return model.getFile(row);
	}

	@Override
	public void edit() {
		int row = getSelectedRow();
		setRowToEdit(row);
		editCellAt(row, DirectoryTableModel.FILE_COL);
	}

	@Override
	public void setSelectedFile(File file) {
		int[] selectedIndices = getSelectedRows();
		if (selectedIndices.length == 1) {
			File selectedFile = model.getFile(selectedIndices[0]);
			if (selectedFile.equals(file)) {
				return; // selection hasn't changed; nothing to do
			}
		}

		for (int i = 0; i < model.getRowCount(); i++) {
			File aFile = model.getFile(i);
			if ((aFile != null) && aFile.equals(file)) {
				setRowSelectionInterval(i, i);
				Rectangle rect = getCellRect(i, DirectoryTableModel.FILE_COL, true);
				scrollRectToVisible(rect);
				return;
			}
		}
	}

	@Override
	public boolean editCellAt(int row, int column) {
		boolean edit = super.editCellAt(row, column);
		repaint();
		return edit;
	}

	@Override
	public boolean isCellEditable(int row, int column) {
		return row == rowToEdit && column == DirectoryTableModel.FILE_COL;
	}

	@Override
	public void editingCanceled(ChangeEvent e) {
		rowToEdit = -1;
		super.editingCanceled(e);
	}

	@Override
	public void editingStopped(ChangeEvent e) {
		super.editingStopped(e);
		Object source = e.getSource();
		final FileEditor fileCellEditor = (FileEditor) source;
		SwingUtilities.invokeLater(() -> {
			File newFile = (File) fileCellEditor.getCellEditorValue();
			chooser.setSelectedFileAndUpdateDisplay(newFile);
			rowToEdit = -1;
		});
	}

	/**
	 * Table cell renderer to display file sizes in more friendly terms 
	 */
	private class FileSizeRenderer extends GTableCellRenderer {
		@Override
		public Component getTableCellRendererComponent(GTableCellRenderingData data) {

			JLabel label = (JLabel) super.getTableCellRendererComponent(data);

			Object sz = data.getValue();

			if (sz == null) {
				return label;
			}

			Long size = (Long) sz;

			setText(FileUtilities.formatLength(size));

			return label;
		}

	}
}
