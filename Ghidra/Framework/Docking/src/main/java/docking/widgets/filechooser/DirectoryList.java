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
import docking.widgets.AutoLookup;
import docking.widgets.label.GDLabel;
import docking.widgets.list.GList;
import docking.widgets.list.GListAutoLookup;
import ghidra.util.exception.AssertException;

class DirectoryList extends GList<File> implements GhidraFileChooserDirectoryModelIf {
	private static final int DEFAULT_ICON_SIZE = 16;
	private static final int MIN_HEIGHT_PADDING = 5;

	private GhidraFileChooser chooser;
	private DirectoryListModel model;
	private JLabel listEditorLabel;
	private JTextField listEditorField;
	private JPanel listEditor;

	/** The file being edited */
	private File editedFile;

	/**
	 * Create a new DirectoryList instance.
	 * 
	 * @param chooser the {@link GhidraFileChooser} this instance is nested in
	 * @param model the {@link DirectoryListModel}
	 * @param font the parent component's font, used to calculate row height in the list once
	 */
	DirectoryList(GhidraFileChooser chooser, DirectoryListModel model, Font font) {
		super(model);
		this.chooser = chooser;
		this.model = model;
		build(font);
	}

	private void build(Font font) {

		setLayoutOrientation(JList.VERTICAL_WRAP);

		FileListCellRenderer cellRenderer = new FileListCellRenderer(chooser);
		setCellRenderer(cellRenderer);

		// Enable the list to calculate the width of the cells on its own, but manually
		// specify the height to ensure some padding between rows.
		// We need the parent component's Font instead of using our
		// own #getFont() because we are not a child of the parent yet and
		// the font may be set to something other than the default.
		// Use 1/3 of the line height of the font to ensure visually consistent
		// padding between rows.  (historically, 5px was used as the padding
		// between the default 12pt (15px lineht) rows, so 15px lineht/5px padding
		// equals .333 ratio.) 
		FontMetrics metrics = cellRenderer.getFontMetrics(font);
		setFixedCellHeight(
			Math.max(metrics.getHeight(), DEFAULT_ICON_SIZE) +
				Math.max(metrics.getHeight() / 3, MIN_HEIGHT_PADDING));
		setFixedCellWidth(-1);

		addMouseListener(new GMouseListenerAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				super.mouseClicked(e);

				// always end editing on a mouse click of any kind
				listEditor.setVisible(false);
				requestFocus();
			}

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
				if (e.getKeyCode() == KeyEvent.VK_ENTER) {
					e.consume();
					handleEnterKey();
				}
			}
		});

		addListSelectionListener(e -> {
			if (e.getValueIsAdjusting()) {
				return;
			}
			updateChooserForSelection();
		});

		listEditorLabel = new GDLabel();
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

		listEditorField = new JTextField();
		listEditorField.setName("LIST_EDITOR_FIELD");
		listEditorField.addKeyListener(new KeyAdapter() {
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
					String invalidFilenameMessage =
						chooser.getInvalidFilenameMessage(listEditorField.getText());
					if (invalidFilenameMessage != null) {
						chooser.setStatusText(invalidFilenameMessage);
						// keep the user in the field by not stopping the current edit
					}
					else {
						stopListEdit();
					}
					e.consume();
				}
			}
		});

		listEditorField.addFocusListener(new FocusAdapter() {
			@Override
			public void focusLost(FocusEvent e) {
				// Tracker SCR 3358 - Keep changes on focus lost
				stopListEdit();
			}
		});

		listEditor = new JPanel(new BorderLayout());
		listEditor.setBorder(BorderFactory.createLineBorder(Color.GRAY));

		listEditor.add(listEditorLabel, BorderLayout.WEST);
		listEditor.add(listEditorField, BorderLayout.CENTER);

		listEditor.setBackground(Color.WHITE);
		listEditorField.setBorder(BorderFactory.createEmptyBorder(2, 2, 2, 2));

		add(listEditor);
	}

	private void handleEnterKey() {

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
	protected AutoLookup createAutoLookup() {
		return new GListAutoLookup<>(this) {
			@Override
			protected boolean canBinarySearchColumn(int column) {
				return false;
			}
		};
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
		listEditorField.setText(editedFile.getName());
		listEditorField.requestFocus();
		listEditorField.selectAll();
	}

	void cancelListEdit() {
		editedFile = null;
		remove(listEditor);
		listEditor.setVisible(false);
		listEditorLabel.setIcon(null);
		listEditorField.setText("");
		repaint();
	}

	void stopListEdit() {
		// this method can be called even when we are not editing
		if (!isEditing()) {
			return;
		}

		String invalidFilenameMessage =
			chooser.getInvalidFilenameMessage(listEditorField.getText());
		if (invalidFilenameMessage != null) {
			chooser.setStatusText("Rename aborted - " + invalidFilenameMessage);
			cancelListEdit();
			return;
		}

		File editedFileCopy = editedFile;
		int index = model.indexOfFile(editedFileCopy);
		if (index < 0) {
			throw new AssertException("Somehow editing file not in our model.");
		}
		File dest = new File(editedFileCopy.getParentFile(), listEditorField.getText());
		cancelListEdit();
		if (chooser.getModel().renameFile(editedFileCopy, dest)) {
			chooser.setStatusText("");
			model.set(index, dest);
			//chooser.updateFiles(chooser.getCurrentDirectory(), true);
			chooser.setSelectedFileAndUpdateDisplay(dest);
		}
		else {
			chooser.setStatusText("Unable to rename " + editedFileCopy);
		}
	}

	/*junit*/ JTextField getListEditorText() {
		return listEditorField;
	}
}
