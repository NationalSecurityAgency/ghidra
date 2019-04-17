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

import docking.event.mouse.GMouseListenerAdapter;
import docking.widgets.list.GList;
import ghidra.util.exception.AssertException;

class DirectoryList extends GList<File> implements GhidraFileChooserDirectoryModelIf {

	private GhidraFileChooser chooser;
	private DirectoryListModel model;
	private JLabel listEditorLabel;
	private JTextField listEditorText;
	private JPanel listEditor;

	/** The file being edited */
	private File editedFile;

	DirectoryList(GhidraFileChooser chooser, DirectoryListModel model) {
		super(model);
		this.chooser = chooser;
		this.model = model;
		build();
	}

	private void build() {
		setLayoutOrientation(JList.VERTICAL_WRAP);
		setCellRenderer(new FileListCellRenderer(chooser));

		addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				// always end editing on a mouse click of any kind
				listEditor.setVisible(false);
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
			public void keyReleased(KeyEvent e) {
				if (e.getKeyCode() != KeyEvent.VK_ENTER) {
					return;
				}
				e.consume();

				int[] selectedIndices = getSelectedIndices();
				if (selectedIndices.length == 0) {
					chooser.okCallback();
					// this implies the user has somehow put focus into the table, but has not
					// made a selection...just let the chooser decide what to do
					return;
				}

				if (selectedIndices.length > 1) {
					// let the chooser decide what to do with multiple rows selected
					chooser.okCallback();
					return;
				}

				File file = model.getFile(selectedIndices[0]);
				if (chooser.getModel().isDirectory(file)) {
					chooser.setCurrentDirectory(file);
				}
				else {
					chooser.userChoseFile(file);
				}
			}
		});

		addListSelectionListener(e -> {
			if (e.getValueIsAdjusting()) {
				return;
			}
			updateChooserForSelection();
		});

		listEditorLabel = new JLabel();
		listEditorLabel.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseReleased(MouseEvent e) {
				int index = locationToIndex(new Point(listEditor.getX(), listEditor.getY()));
				File file = model.getFile(index);
				if (e.getClickCount() == 2) {
					if (chooser.getModel().isDirectory(file)) {
						chooser.setCurrentDirectory(file);
					}
					cancelListEdit();
				}
			}
		});

		listEditorText = new JTextField();
		listEditorText.setName("LIST_EDITOR_FIELD");
		listEditorText.addKeyListener(new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				if (e.getKeyCode() == KeyEvent.VK_ESCAPE) {
					cancelListEdit();
					e.consume();
				}
			}

			@Override
			public void keyReleased(KeyEvent e) {
				if (e.getKeyCode() == KeyEvent.VK_ESCAPE) {
					listEditor.setVisible(false);
					e.consume();
				}
				else if (e.getKeyCode() == KeyEvent.VK_ENTER) {
					stopListEdit();
					e.consume();
				}
			}
		});

		listEditorText.addFocusListener(new FocusAdapter() {
			@Override
			public void focusLost(FocusEvent e) {
				// Tracker SCR 3358 - Keep changes on focus lost
				stopListEdit();
			}
		});

		listEditor = new JPanel(new BorderLayout());
		listEditor.setBorder(BorderFactory.createLineBorder(Color.GRAY));

		listEditor.add(listEditorLabel, BorderLayout.WEST);
		listEditor.add(listEditorText, BorderLayout.CENTER);

		listEditor.setBackground(Color.WHITE);
		listEditorText.setBorder(BorderFactory.createEmptyBorder(2, 2, 2, 2));

		add(listEditor);
	}

	private void maybeSelectItem(MouseEvent e) {
		Point point = e.getPoint();
		int index = locationToIndex(point);
		if (index < 0) {
			return;
		}
		setSelectedIndex(index);
	}

	private void handleDoubleClick() {
		List<File> selectedFiles = new ArrayList<>();
		int[] selectedIndices = getSelectedIndices();
		for (int i : selectedIndices) {
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

	private void updateChooserForSelection() {
		List<File> selectedFiles = new ArrayList<>();
		int[] selectedIndices = getSelectedIndices();
		for (int index : selectedIndices) {
			selectedFiles.add(model.getFile(index));
		}
		chooser.userSelectedFiles(selectedFiles);
	}

	@Override
	public int[] getSelectedRows() {
		return getSelectedIndices();
	}

	@Override
	public File getSelectedFile() {
		int index = getSelectedIndex();
		if (index < 0) {
			return null;
		}
		return model.getFile(index);
	}

	@Override
	public File getFile(int row) {
		return model.getFile(row);
	}

	@Override
	public void edit() {
		int index = getSelectedIndex();
		editListCell(index);
	}

	@Override
	public void setSelectedFile(File file) {
		int[] selectedIndices = getSelectedIndices();
		if (selectedIndices.length == 1) {
			File selectedFile = model.getFile(selectedIndices[0]);
			if (selectedFile.equals(file)) {
				return; // selection hasn't changed; nothing to do
			}
		}

		for (int i = 0; i < model.getSize(); i++) {
			File aFile = model.getFile(i);
			if ((aFile != null) && aFile.equals(file)) {
				setSelectedIndex(i);
				Rectangle rect = getCellBounds(i, i);
				scrollRectToVisible(rect);
				return;
			}
		}
	}

	void setSelectedFiles(Iterable<File> files) {

		List<Integer> indexes = new ArrayList<>();
		for (File f : files) {
			indexes.add(model.indexOfFile(f));
		}

		int[] indices = new int[indexes.size()];
		for (int i = 0; i < indices.length; i++) {
			indices[i] = indexes.get(i);
		}

		setSelectedIndices(indices);
	}

	private boolean isEditing() {
		return (editedFile != null);
	}

	void editListCell(int index) {
		if (index == -1) {
			return;
		}
		add(listEditor);
		Rectangle r = getCellBounds(index, index);
		editedFile = model.getFile(index);
		if (editedFile == null) {
			throw new AssertException(
				"Unexpected condition - asked to edit file that " + "does not exist in model");
		}

		listEditor.setBounds(r.x, r.y, r.width, r.height);
		listEditor.setVisible(true);
		listEditorLabel.setIcon(chooser.getModel().getIcon(editedFile));
		listEditorText.setText(editedFile.getName());
		listEditorText.requestFocus();
		listEditorText.selectAll();
	}

	void cancelListEdit() {
		editedFile = null;
		remove(listEditor);
		listEditor.setVisible(false);
		listEditorLabel.setIcon(null);
		listEditorText.setText("");
		repaint();
	}

	void stopListEdit() {
		// this method can be called even when we are not editing
		if (!isEditing()) {
			return;
		}

		File editedFileCopy = editedFile;
		int index = model.indexOfFile(editedFileCopy);
		if (index < 0) {
			throw new AssertException("Somehow editing file not in our model.");
		}
		File dest = new File(editedFileCopy.getParentFile(), listEditorText.getText());
		cancelListEdit();
		if (chooser.getModel().renameFile(editedFileCopy, dest)) {
			model.set(index, dest);
			//chooser.updateFiles(chooser.getCurrentDirectory(), true);
			chooser.setSelectedFileAndUpdateDisplay(dest);
		}
		else {
			chooser.setStatusText("Unable to rename " + editedFileCopy);
		}
	}

	/*junit*/ JTextField getListEditorText() {
		return listEditorText;
	}
}
