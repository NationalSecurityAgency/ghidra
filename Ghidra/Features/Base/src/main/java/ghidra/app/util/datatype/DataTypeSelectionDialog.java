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
package ghidra.app.util.datatype;

import java.awt.BorderLayout;

import javax.swing.*;
import javax.swing.event.*;

import docking.DialogComponentProvider;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.util.HelpLocation;
import ghidra.util.data.DataTypeParser;
import ghidra.util.data.DataTypeParser.AllowedDataTypes;

/**
 * A dialog that allows the user to choose from available data types or create new ones.
 */
public class DataTypeSelectionDialog extends DialogComponentProvider {

	private DataTypeSelectionEditor editor;
	private PluginTool pluginTool;
	private DataType userChoice;
	private int maxSize = -1;
	private DataTypeManager dtm;
	private final AllowedDataTypes allowedTypes;

	public DataTypeSelectionDialog(PluginTool pluginTool, DataTypeManager dtm, int maxSize,
			DataTypeParser.AllowedDataTypes allowedTypes) {
		super("Data Type Chooser Dialog", true, true, true, false);

		this.pluginTool = pluginTool;
		this.dtm = dtm;
		this.maxSize = maxSize;
		this.allowedTypes = allowedTypes;
		init();

		setHelpLocation(new HelpLocation("DataTypeEditors", "DataTypeSelectionDialog"));
	}

	private void init() {
		buildEditor();

		addOKButton();
		addCancelButton();
	}

	private void buildEditor() {
		removeWorkPanel();

		editor = new DataTypeSelectionEditor(pluginTool, allowedTypes);
		editor.setPreferredDataTypeManager(dtm);
		editor.setConsumeEnterKeyPress(false); // we want to handle Enter key presses
		editor.addCellEditorListener(new CellEditorListener() {
			@Override
			public void editingCanceled(ChangeEvent e) {
				if (isVisible()) {
					cancelCallback();
				}
			}

			@Override
			public void editingStopped(ChangeEvent e) {
				if (isVisible()) {
					okCallback();
				}
			}
		});
		editor.addDocumentListener(new DocumentListener() {

			@Override
			public void changedUpdate(DocumentEvent e) {
				clearStatusText();
			}

			@Override
			public void insertUpdate(DocumentEvent e) {
				clearStatusText();
			}

			@Override
			public void removeUpdate(DocumentEvent e) {
				clearStatusText();
			}

		});

		JComponent mainPanel = createEditorPanel(editor);
		addWorkPanel(mainPanel);

		rootPanel.validate();
	}

	protected JComponent createEditorPanel(DataTypeSelectionEditor dtEditor) {
		JPanel mainPanel = new JPanel(new BorderLayout());
		mainPanel.add(editor.getEditorComponent(), BorderLayout.NORTH);
		return mainPanel;
	}

	@Override
	protected void dialogShown() {
		SwingUtilities.invokeLater(() -> editor.requestFocus());
	}

	// overridden to set the user choice to null
	@Override
	protected void cancelCallback() {
		userChoice = null;
		super.cancelCallback();
	}

	// overridden to perform validation and to get the user's choice
	@Override
	protected void okCallback() {

		// validate the data type
		DataType dt;
		try {
			if (!editor.validateUserSelection()) {
				// users can only select existing data types
				setStatusText("Unrecognized data type of \"" + editor.getCellEditorValueAsText() +
					"\" entered.");
				return;
			}
			dt = (DataType) editor.getCellEditorValue();
			int dtLen = dt.getLength();
			if (maxSize >= 0 && dtLen > maxSize) {
				setStatusText(dt.getDisplayName() + " doesn't fit within " + maxSize +
					" bytes, need " + dtLen + " bytes");
				return;
			}
		}
		catch (Exception e) {
			setStatusText(e.getMessage());
			return;
		}
		clearStatusText();

		userChoice = dt;
		close();
	}

	// overridden to re-create the editor each time we are closed so that the editor's windows
	// are properly parented for each new dialog
	@Override
	public void close() {
		buildEditor();
		setStatusText("");
		super.close();
	}

	/**
	 * If true then a Tab key press will work the same as pressing the Enter key.  If false, then
	 * a Tab key press will trigger navigation, as is normally done in Java.  
	 * <p>
	 * This method is useful for widgets that have embedded editors that launch this dialog.  For
	 * these editors, like tables, it is nice to be able to tab through various editors.  This
	 * method allows these editors to keep this functionality, even though a new dialog was shown.
	 * @param doesCommit true commits edits on Tab press
	 */
	public void setTabCommitsEdit(boolean doesCommit) {
		editor.setTabCommitsEdit(doesCommit);
	}

	/**
	 * Sets the value that this dialog will display in it's editor when initially shown.
	 * @param dataType The initial data type to use for editing.
	 */
	public void setInitialDataType(DataType dataType) {
		editor.setCellEditorValue(dataType);
	}

	/**
	 * Clears the last user selection.  This is useful if this dialog is reused and the call
	 * wants to make sure that old selections do not appear later.
	 */
	public void clearUserChosenDataType() {
		userChoice = null;
	}

	/**
	 * The data type choice of the user or null if the dialog was cancelled.
	 * @return The data type choice of the user or null if the dialog was cancelled.
	 */
	public DataType getUserChosenDataType() {
		return userChoice;
	}

	public DataTypeSelectionEditor getEditor() {
		return this.editor;
	}
}
