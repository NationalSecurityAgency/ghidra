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
package docking.widgets.filechooser;

import java.awt.*;
import java.awt.event.*;
import java.io.File;

import javax.swing.*;
import javax.swing.event.ChangeEvent;
import javax.swing.table.TableCellEditor;

import docking.widgets.label.GDLabel;
import ghidra.util.Msg;
import ghidra.util.filechooser.GhidraFileChooserModel;

class FileEditor extends AbstractCellEditor implements TableCellEditor {

	private GhidraFileChooser chooser;
	private DirectoryTable directoryTable;
	private DirectoryTableModel model;
	private JPanel editor;
	private JLabel iconLabel;
	private JTextField nameField;

	private File originalFile;
	private File editedFile;

	FileEditor(GhidraFileChooser chooser, DirectoryTable table, DirectoryTableModel model) {
		this.chooser = chooser;
		this.directoryTable = table;
		this.model = model;

		iconLabel = new GDLabel();
		iconLabel.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseReleased(MouseEvent e) {
				if (e.getClickCount() == 2) {
					handleDoubleClick(e.getPoint());
				}
			}
		});

		nameField = new JTextField();
		nameField.setName("TABLE_EDITOR_FIELD");
		nameField.addKeyListener(new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				if (e.getKeyCode() == KeyEvent.VK_ESCAPE) {
					directoryTable.editingCanceled(new ChangeEvent(FileEditor.this));
					e.consume();
				}
				else if (e.getKeyCode() == KeyEvent.VK_ENTER) {
					String invalidFilenameMessage =
						chooser.getInvalidFilenameMessage(nameField.getText());
					if (invalidFilenameMessage != null) {
						chooser.setStatusText(invalidFilenameMessage);
						e.consume();
					}
				}
			}

			@Override
			public void keyReleased(KeyEvent e) {
				if (e.getKeyCode() == KeyEvent.VK_ESCAPE) {
					directoryTable.editingCanceled(new ChangeEvent(FileEditor.this));
					e.consume();
				}
				else if (e.getKeyCode() == KeyEvent.VK_ENTER) {
					String invalidFilenameMessage =
						chooser.getInvalidFilenameMessage(nameField.getText());
					if (invalidFilenameMessage != null) {
						chooser.setStatusText(invalidFilenameMessage);
					}
					else {
						directoryTable.editingStopped(new ChangeEvent(FileEditor.this));
					}
					e.consume();
				}
			}
		});

		nameField.setBorder(BorderFactory.createEmptyBorder(2, 2, 2, 2));

		editor = new JPanel(new BorderLayout()) {

			// make sure the name field gets the focus, not the container
			@Override
			public void requestFocus() {
				SwingUtilities.invokeLater(new Runnable() {
					@Override
					public void run() {
						nameField.requestFocus();
					}
				});
			}
		};

		editor.add(iconLabel, BorderLayout.WEST);
		editor.add(nameField, BorderLayout.CENTER);

		// match the spacing of non-editing cells
		editor.setBorder(
			BorderFactory.createCompoundBorder(BorderFactory.createEmptyBorder(0, 5, 0, 0),
				BorderFactory.createLineBorder(Color.GRAY)));
	}

	private void handleDoubleClick(Point p) {
		directoryTable.editingCanceled(null);
		int row = directoryTable.rowAtPoint(p);
		File file = model.getFile(row);
		chooser.setCurrentDirectory(file);
	}

	@Override
	public Component getTableCellEditorComponent(JTable table, Object value, boolean isSelected,
			int row, int column) {

		editedFile = null;
		originalFile = model.getFile(row);
		String name = originalFile.getName();
		Icon icon = chooser.getModel().getIcon(originalFile);
		iconLabel.setIcon(icon);
		nameField.setText(name);
		nameField.requestFocus();
		if (name.length() > 0) {
			nameField.setCaretPosition(name.length());
			nameField.selectAll();
		}
		nameField.repaint();
		editor.setVisible(true);
		return editor;
	}

	@Override
	public Object getCellEditorValue() {
		if (originalFile == null) {
			return null;
		}

		if (editedFile != null) {
			return editedFile;
		}

		editedFile = getNewFile();
		return editedFile;
	}

	private File getNewFile() {
		String invalidFilenameMessage = chooser.getInvalidFilenameMessage(nameField.getText());
		if (invalidFilenameMessage != null) {
			chooser.setStatusText("Rename aborted - " + invalidFilenameMessage);
			return originalFile;
		}
		GhidraFileChooserModel fileChooserModel = chooser.getModel();
		File newFile = new GhidraFile(originalFile.getParentFile(), nameField.getText(),
			fileChooserModel.getSeparator());
		if (fileChooserModel.renameFile(originalFile, newFile)) {
			return newFile;
		}

		Msg.showError(this, chooser.getComponent(), "Rename Failed",
			"Unable to rename file: " + originalFile);
		return null;
	}
}
