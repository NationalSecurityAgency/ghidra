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
package ghidra.plugins.fsbrowser;

import java.awt.Dimension;
import java.awt.Font;
import java.awt.event.KeyEvent;
import java.io.*;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.text.Document;
import javax.swing.undo.UndoableEdit;

import docking.*;
import docking.action.*;
import docking.actions.KeyBindingUtils;
import docking.options.editor.FontEditor;
import docking.widgets.OptionDialog;
import docking.widgets.filechooser.GhidraFileChooser;
import generic.theme.*;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.util.Msg;
import ghidra.util.datastruct.FixedSizeStack;
import resources.Icons;

public class TextEditorComponentProvider extends ComponentProviderAdapter {
	private static final String TITLE = "Text Editor";
	private static final String FONT_ID = "font.plugin.service.text.editor";
	private static final int MAX_UNDO_REDO_SIZE = 50;
	private static final String LAST_SAVED_TEXT_FILE_DIR = "LastSavedTextFileDirectory";

	private File textFile;
	private String textFileName;
	private DockingAction saveAction;
	private DockingAction saveAsAction;
	private DockingAction undoAction;
	private DockingAction redoAction;
	private DockingAction fontAction;
	private JTextArea textarea;
	private JScrollPane scrollpane;
	private boolean isChanged = false;
	private String title;
	private FixedSizeStack<UndoableEdit> undoStack = new FixedSizeStack<>(MAX_UNDO_REDO_SIZE);
	private FixedSizeStack<UndoableEdit> redoStack = new FixedSizeStack<>(MAX_UNDO_REDO_SIZE);

	public TextEditorComponentProvider(FileSystemBrowserPlugin plugin, String textFileName,
			String text) {
		super(plugin.getTool(), TITLE, "TextEditorComponentProvider");
		this.textFileName = textFileName;
		initialize(text);
	}

	public String getText() {
		return textarea.getText();
	}

	private void initialize(String textContents) {
		title = textFileName + (isReadOnly() ? " (Read-Only) " : "");
		setTitle(title);

		textarea = new KeyMasterTextArea(textContents);

		scrollpane = new JScrollPane(textarea);
		scrollpane.setPreferredSize(new Dimension(400, 400));

		addToTool();
		setVisible(true);

		createActions();

		contextChanged();
	}

	private boolean isReadOnly() {
		return textFile != null;
	}

	private void clearUndoRedoStack() {
		undoStack.clear();
		redoStack.clear();
		contextChanged();
	}

	private void undo() {
		UndoableEdit item = undoStack.pop();
		redoStack.push(item);
		item.undo();
		contextChanged();
	}

	private void redo() {
		UndoableEdit item = redoStack.pop();
		undoStack.push(item);
		item.redo();
		contextChanged();
	}

	boolean isChanged() {
		return isChanged;
	}

	private void setChanged(boolean changed) {
		if (isChanged == changed) {
			return;
		}
		if (!changed) {
			clearUndoRedoStack();
		}
		isChanged = changed;
		if (saveAction != null && !isReadOnly()) {
			saveAction.setEnabled(isChanged);
		}
		if (isChanged) {
			setTitle("*" + title);
		}
		else {
			setTitle(title);
		}
	}

	private void createActions() {
		undoAction = new DockingAction("Undo", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				undo();
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return !undoStack.isEmpty();
			}
		};
		undoAction.setDescription("Undo");
		undoAction.setToolBarData(new ToolBarData(new GIcon("icon.undo"), "UndoRedo"));
		undoAction.setKeyBindingData(new KeyBindingData("ctrl z"));
		addLocalAction(undoAction);

		redoAction = new DockingAction("Redo", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				redo();
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return !redoStack.isEmpty();
			}
		};
		redoAction.setDescription("Redo");
		redoAction.setToolBarData(new ToolBarData(new GIcon("icon.redo"), "UndoRedo"));
		redoAction.setKeyBindingData(new KeyBindingData("ctrl shift z"));
		addLocalAction(redoAction);

		saveAction = new DockingAction("Save File", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				save();
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return isChanged;
			}
		};
		saveAction.setDescription("Save");
		saveAction.setToolBarData(new ToolBarData(Icons.SAVE_ICON, "Save"));
		saveAction.setKeyBindingData(new KeyBindingData("ctrl-s"));
		addLocalAction(saveAction);

		saveAsAction = new DockingAction("Save File As", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				saveAs();
			}
		};
		saveAsAction.setDescription("Save As...");
		saveAsAction.setToolBarData(new ToolBarData(Icons.SAVE_AS_ICON, "Save"));
		addLocalAction(saveAsAction);

		fontAction = new DockingAction("Select Font", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				doSelectFont();
			}
		};
		fontAction.setToolBarData(new ToolBarData(new GIcon("icon.font"), "ZZFont"));
		fontAction.setDescription("Select Font");
		addLocalAction(fontAction);

		/****************************************************************/
		// DO NOT REMOVE THIS CODE!!
		// We need to override certain keybindings so that no other components in
		// Ghidra receive them

		ActionContextProvider acp = e -> {
			ComponentProvider p = TextEditorComponentProvider.this;
			return new DefaultActionContext(p);
		};

		KeyBindingUtils.registerAction(textarea, saveAction, acp);
		KeyBindingUtils.registerAction(textarea, redoAction, acp);
		KeyBindingUtils.registerAction(textarea, undoAction, acp);
		/****************************************************************/
	}

	protected void doSelectFont() {
		FontEditor editor = new FontEditor();
		editor.setValue(Gui.getFont(FONT_ID));
		editor.showDialog();
		ThemeManager.getInstance().setFont(FONT_ID, (Font) editor.getValue());
	}

	private void save() {
		String text = textarea.getText();
		if (textFile == null) {
			saveAs();
		}
		else {
			try {
				PrintWriter writer = new PrintWriter(new FileWriter(textFile));
				writer.print(text);
				writer.close();
				setChanged(false);
			}
			catch (IOException e) {
				if (textFile.canWrite()) {
					Msg.showError(getClass(), getComponent(), "Error Saving File",
						"Unable to save file", e);
				}
				else {
					Msg.showError(getClass(), getComponent(), "Error Saving File",
						"The file is not writable");
				}
			}
		}
	}

	private void saveAs() {

		GhidraFileChooser chooser = new GhidraFileChooser(getComponent());

		chooser.setLastDirectoryPreference(LAST_SAVED_TEXT_FILE_DIR);

		File saveAsFile = chooser.getSelectedFile();
		chooser.dispose();
		if (saveAsFile == null) {
			return;
		}
		boolean exists = saveAsFile.exists();
		if (exists) {
			int result = OptionDialog.showYesNoDialog(getComponent(), getName(),
				"Do you want to OVERWRITE the following file:\n" + saveAsFile.getName());
			if (result != OptionDialog.OPTION_ONE) {
				return;
			}
		}
		try {
			String str = textarea.getText();

			PrintWriter writer = new PrintWriter(new FileWriter(saveAsFile));
			writer.print(str);
			writer.close();

			saveAction.setEnabled(false);

			textFile = saveAsFile;

			title = saveAsFile.getName();

			setChanged(false);
		}
		catch (IOException e) {
			Msg.showError(getClass(), getComponent(), "Error Saving File As...", e.getMessage());
		}
	}

//==================================================================================================
// ComponentProvider Methods
//==================================================================================================

	@Override
	public void closeComponent() {
		clearUndoRedoStack();
		super.closeComponent();
		getTool().removeComponentProvider(this);
	}

	@Override
	public JComponent getComponent() {
		return scrollpane;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class KeyMasterTextArea extends JTextArea {

		private KeyMasterTextArea(String text) {
			super(text);
			Gui.registerFont(this, FONT_ID);
			setName("EDITOR");
			setWrapStyleWord(false);
			Document document = getDocument();
			document.addDocumentListener(new DocumentListener() {
				@Override
				public void changedUpdate(DocumentEvent e) {
					setChanged(true);
				}

				@Override
				public void insertUpdate(DocumentEvent e) {
					setChanged(true);
				}

				@Override
				public void removeUpdate(DocumentEvent e) {
					setChanged(true);
				}
			});
			document.addUndoableEditListener(e -> {
				UndoableEdit item = e.getEdit();
				undoStack.push(item);
				redoStack.clear();
				contextChanged();
			});
			setCaretPosition(0);
		}

		/**
		 * Overridden so that our text area will properly consume key events for registered
		 * actions.  By default the JComponents will not process a keystroke with an
		 * assigned keybinding *if the assigned action is not enabled*.  We want to always
		 * process registered keystrokes so that they do not get handled elsewhere in
		 * Ghidra accidentally. For example, Ctrl-S is bound to save for this text area.  If
		 * there have been no changes in the data, then the save action is not enabled.  So,
		 * when the user presses Ctrl-S in this window, then, by default, the text area will
		 * not consume the event and the event will end up moving up to the tool level and
		 * executing a save there, which is clearly not the intended effect.  In this example
		 * we really just want this window to do nothing if the save is not enabled.
		 */
		@Override
		protected boolean processKeyBinding(KeyStroke ks, KeyEvent e, int condition,
				boolean pressed) {

			InputMap map = getInputMap(condition);
			ActionMap am = getActionMap();
			if (map != null && am != null && isEnabled()) {
				Object binding = map.get(ks);
				Action action = (binding == null) ? null : am.get(binding);
				if (action != null) {
					if (!action.isEnabled()) {
						// we want to consume the event here, so Ghidra doesn't get to
						// process it when the actions are disabled
						e.consume();
						return true;
					}

					return SwingUtilities.notifyAction(action, ks, e, this, e.getModifiersEx());
				}
			}
			return false;
		}
	}
}
