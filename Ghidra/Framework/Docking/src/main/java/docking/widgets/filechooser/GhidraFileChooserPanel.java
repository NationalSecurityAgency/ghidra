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
import java.awt.datatransfer.DataFlavor;
import java.awt.dnd.*;
import java.io.File;
import java.util.List;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import docking.dnd.DropTgtAdapter;
import docking.dnd.Droppable;
import docking.widgets.OptionDialog;
import docking.widgets.label.GLabel;
import ghidra.framework.preferences.Preferences;
import ghidra.util.filechooser.GhidraFileFilter;

/**
 * Panel for entering a file name that includes a title border, a text field
 * for entering a filename, and a button for bringing up a file chooser dialog.
 */
public class GhidraFileChooserPanel extends JPanel implements Droppable {
	private static final long serialVersionUID = 1L;

	/**
	 * This mode denotes that only existing files will
	 * be chosen for the purpose of reading.
	 */
	public final static int INPUT_MODE = 0;
	/**
	 * This mode denotes that existing files (or new files)
	 * will be chosen for the purpose of writing.
	 * If an existing file is selected the user will
	 * be prompted to confirm overwrite.
	 */
	public final static int OUTPUT_MODE = 1;

	private GhidraFileChooser fileChooser;
	private GhidraFileFilter filter = GhidraFileFilter.ALL;
	private JTextField filenameTextField;
	private JButton chooseButton;
	private String title;
	private String propertyName;
	private String defaultFileName;
	private boolean createBorder;
	private int mode = OUTPUT_MODE;
	private GhidraFileChooserPanelListener listener;
	private DropTarget dropTarget;
	private DropTgtAdapter dropTargetAdapter;
	private DataFlavor[] acceptableFlavors; // data flavors that this
	private GhidraFileChooserMode selectionMode = GhidraFileChooserMode.FILES_ONLY;

	/**
	 * Constructs a new GhidraFileChooserPanel
	 * @param title the title for this panel
	 * @param propertyName the property name to save state
	 * @param defaultFileName the default file name.
	 * @param createBorder flag to create the border or not.
	 */
	public GhidraFileChooserPanel(String title, String propertyName, String defaultFileName,
			boolean createBorder, int mode) {

		this.title = title;
		this.propertyName = propertyName;
		this.defaultFileName = defaultFileName;
		this.createBorder = createBorder;
		this.mode = mode;
		build();
		setupDragAndDrop();
	}

	/**
	 * Sets the listener.
	 * @param listener the new listener
	 */
	public void setListener(GhidraFileChooserPanelListener listener) {
		this.listener = listener;
	}

	/**
	 * Sets the file filter.
	 * @param filter the new file filter
	 */
	public void setFileFilter(GhidraFileFilter filter) {
		this.filter = filter;
	}

	private void build() {
		if (createBorder) {
			setBorder(BorderFactory.createTitledBorder(BorderFactory.createEtchedBorder(1), title));
		}

		filenameTextField = new JTextField(20);
		filenameTextField.setText(defaultFileName);
		filenameTextField.getDocument().addDocumentListener(new DocumentListener() {
			@Override
			public void changedUpdate(DocumentEvent e) {
				fileChanged();
			}

			@Override
			public void insertUpdate(DocumentEvent e) {
				fileChanged();
			}

			@Override
			public void removeUpdate(DocumentEvent e) {
				fileChanged();
			}
		});

		chooseButton = new JButton("...");

		chooseButton.addActionListener(evt -> {
			File log = chooseFile(chooseButton, "Select " + (title == null ? "" : title));
			if (log != null) {
				boolean ok = true;
				if (mode == OUTPUT_MODE && log.exists()) {
					String questionTitle = "Overwrite Existing File?";
					String questionText = "The file " + log.getAbsolutePath() + " already exists." +
						"\n" + "Do you wish to overwrite it?";
					String buttonText = "Yes";
					int response = OptionDialog.showOptionDialog(chooseButton, questionTitle,
						questionText, buttonText, OptionDialog.QUESTION_MESSAGE);
					ok = response == OptionDialog.OPTION_ONE;
				}
				if (ok) {
					filenameTextField.setText(log.getAbsolutePath());
				}
				else {
					filenameTextField.setText("");
				}
				filenameTextField.requestFocus();
				filenameTextField.selectAll();
			}
		});

		setLayout(new GridBagLayout());
		GridBagConstraints gbc = new GridBagConstraints();
		gbc.gridx = 0;
		gbc.gridy = 0;

		if (!createBorder && title != null) {
			add(new GLabel(title), gbc);
		}

		gbc.fill = GridBagConstraints.HORIZONTAL;
		gbc.weightx = 1.0;
		gbc.insets = new Insets(5, 5, 5, 5);
		gbc.gridx++;
		add(filenameTextField, gbc);

		gbc.fill = GridBagConstraints.NONE;
		gbc.weightx = 0.0;
		gbc.gridx++;
		gbc.insets = new Insets(5, 5, 5, 5);
		add(chooseButton, gbc);
	}

	private void fileChanged() {
		if (listener != null) {
			String file = filenameTextField.getText();
			if (file.length() == 0) {
				listener.fileChanged(null);
			}
			else {
				listener.fileChanged(new File(file));
			}
		}
	}

	/**
	 * Adds a document listener to the text field.
	 * @param dl the document listener to add.
	 */
	public void addDocumentListener(DocumentListener dl) {
		filenameTextField.getDocument().addDocumentListener(dl);
	}

	/**
	 * Returns the filename currently in the text field.
	 * @return the filename currently in the text field
	 */
	public String getFileName() {
		return filenameTextField.getText();
	}

	public String getCurrentDirectory() {
		if (fileChooser == null) {
			return "";
		}
		return fileChooser.getCurrentDirectory().getAbsolutePath();
	}

	/**
	 * Sets the textfield with the given filename.
	 * @param path the name of the file to put in the text field.
	 */
	public void setFileName(String path) {
		filenameTextField.setText(path);
	}

	/**
	 * @see java.awt.Component#setEnabled(boolean)
	 */
	@Override
	public void setEnabled(boolean enabled) {
		super.setEnabled(enabled);
		filenameTextField.setEnabled(enabled);
		filenameTextField.setOpaque(enabled);
		chooseButton.setEnabled(enabled);
	}

	private File chooseFile(Component parent, String buttonText) {
		if (fileChooser == null) {
			fileChooser = new GhidraFileChooser(parent);
		}

		fileChooser.setFileFilter(filter);
		fileChooser.setFileSelectionMode(selectionMode);

		// start the browsing in the user's preferred directory
		//
		File directory =
			new File(Preferences.getProperty(propertyName, System.getProperty("user.home")));
		fileChooser.setCurrentDirectory(directory);
		fileChooser.setSelectedFile(directory);

		File file = fileChooser.getSelectedFile();
		if (file != null) {
			// record where we last exported a file from to the user's preferences
			Preferences.setProperty(propertyName, file.getAbsolutePath());
		}

		return file;
	}

	private void setupDragAndDrop() {
		acceptableFlavors = new DataFlavor[] { DataFlavor.javaFileListFlavor, };

		// set up drop stuff
		dropTargetAdapter =
			new DropTgtAdapter(this, DnDConstants.ACTION_COPY_OR_MOVE, acceptableFlavors);
		dropTarget = new DropTarget(filenameTextField, DnDConstants.ACTION_COPY_OR_MOVE,
			dropTargetAdapter, true);
		dropTarget.setActive(true);
	}

	/**
	 * @see docking.dnd.Droppable#add(java.lang.Object, java.awt.dnd.DropTargetDropEvent, java.awt.datatransfer.DataFlavor)
	 */
	@Override
	public void add(Object obj, DropTargetDropEvent e, DataFlavor f) {
		if (f == DataFlavor.javaFileListFlavor) {
			List<?> files = (java.util.List<?>) obj;
			if (files.size() > 0) {
				File file = (File) files.get(0);
				filenameTextField.setText(file.getAbsolutePath());
				if (listener != null) {
					listener.fileDropped(file);
				}
			}
		}
	}

	/**
	 * Sets the <code>GhidraFileChooser</code> to allow the user to just
	 * select files, just select
	 * directories, or select both files and directories.  The default is
	 * <code>GhidraFileChooserMode.FILES_ONLY</code>.
	 *
	 * @param mode the type of files to be displayed
	 * @exception IllegalArgumentException  if <code>mode</code> is an
	 *				illegal Dialog mode
	 */
	public void setFileSelectionMode(GhidraFileChooserMode mode) {
		this.selectionMode = mode;
	}

	/**
	 * @see docking.dnd.Droppable#dragUnderFeedback(boolean, java.awt.dnd.DropTargetDragEvent)
	 */
	@Override
	public void dragUnderFeedback(boolean ok, DropTargetDragEvent e) {
		// don't care
	}

	/**
	 * @see docking.dnd.Droppable#isDropOk(java.awt.dnd.DropTargetDragEvent)
	 */
	@Override
	public boolean isDropOk(DropTargetDragEvent e) {
		return true;
	}

	/**
	 * @see docking.dnd.Droppable#undoDragUnderFeedback()
	 */
	@Override
	public void undoDragUnderFeedback() {
		// don't care
	}

}
