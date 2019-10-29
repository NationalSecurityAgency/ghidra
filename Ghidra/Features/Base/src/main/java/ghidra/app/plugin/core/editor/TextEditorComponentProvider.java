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
package ghidra.app.plugin.core.editor;

import java.awt.Dimension;
import java.awt.Font;
import java.awt.event.KeyEvent;
import java.io.*;
import java.util.Iterator;
import java.util.List;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.text.Document;
import javax.swing.undo.UndoableEdit;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.*;
import docking.actions.KeyBindingUtils;
import docking.options.editor.FontPropertyEditor;
import docking.widgets.OptionDialog;
import docking.widgets.filechooser.GhidraFileChooser;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.datastruct.FixedSizeStack;
import resources.ResourceManager;

public class TextEditorComponentProvider extends ComponentProviderAdapter {
	private static final String TITLE = "Text Editor";

	private static final int MAX_UNDO_REDO_SIZE = 50;

	static Font defaultFont = new Font("monospaced", Font.PLAIN, 12);

	static void restoreState(SaveState saveState) {
		String name = saveState.getString("DEFAULT_FONT_NAME", "Monospaced");
		int style = saveState.getInt("DEFAULT_FONT_STYLE", Font.PLAIN);
		int size = saveState.getInt("DEFAULT_FONT_SIZE", 12);
		defaultFont = new Font(name, style, size);
	}

	static void saveState(SaveState saveState) {
		saveState.putString("DEFAULT_FONT_NAME", defaultFont.getName());
		saveState.putInt("DEFAULT_FONT_STYLE", defaultFont.getStyle());
		saveState.putInt("DEFAULT_FONT_SIZE", defaultFont.getSize());
	}

	private TextEditorManagerPlugin plugin;
	private GhidraFileChooser chooser;
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

	TextEditorComponentProvider(TextEditorManagerPlugin plugin, String textFileName,
			InputStream inputStream) throws IOException {
		super(plugin.getTool(), TITLE, plugin.getName());
		this.textFileName = textFileName;
		String textContents = loadTextFile(inputStream);
		initialize(plugin, textContents);
	}

	public String getText() {
		return textarea.getText();
	}

	private void initialize(TextEditorManagerPlugin p, String textContents) {
		this.plugin = p;

		setHelpLocation(new HelpLocation(p.getName(), p.getName()));

		title = textFileName + (isReadOnly() ? " (Read-Only) " : "");
		setTitle(title);

		textarea = new KeyMasterTextArea(textContents);

		scrollpane = new JScrollPane(textarea);
		scrollpane.setPreferredSize(new Dimension(400, 400));

		addToTool();
		setVisible(true);
		p.getTool().setStatusInfo("Press F1 for help.");

		createActions();
	}

	private boolean isReadOnly() {
		return textFile != null;
	}

	private void clearUndoRedoStack() {
		undoStack.clear();
		redoStack.clear();
		updateUndoRedoAction();
	}

	private void updateUndoRedoAction() {
		undoAction.setEnabled(!undoStack.isEmpty());
		redoAction.setEnabled(!redoStack.isEmpty());
	}

	private void undo() {
		UndoableEdit item = undoStack.pop();
		redoStack.push(item);
		item.undo();
		updateUndoRedoAction();
	}

	private void redo() {
		UndoableEdit item = redoStack.pop();
		undoStack.push(item);
		item.redo();
		updateUndoRedoAction();
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

	private String loadTextFile(InputStream inputStream) throws IOException {
		BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
		try {
			return loadTextFile(reader);
		}
		finally {
			reader.close();
		}
	}

	private String loadTextFile(BufferedReader reader) throws IOException {
		StringBuffer buffer = new StringBuffer();
		while (true) {
			String line = reader.readLine();
			if (line == null) {
				break;
			}
			buffer.append(line);
			buffer.append('\n');
		}
		return buffer.toString();
	}

	private void createActions() {
		undoAction = new DockingAction("Undo", plugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				undo();
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				Object contextObject = context.getContextObject();
				return contextObject == TextEditorComponentProvider.this;
			}
		};
		undoAction.setDescription("Undo");
		undoAction.setToolBarData(
			new ToolBarData(ResourceManager.loadImage("images/undo.png"), "UndoRedo"));
		undoAction.setEnabled(false);
		plugin.getTool().addLocalAction(this, undoAction);

		redoAction = new DockingAction("Redo", plugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				redo();
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				Object contextObject = context.getContextObject();
				return contextObject == TextEditorComponentProvider.this;
			}
		};
		redoAction.setDescription("Redo");
		redoAction.setToolBarData(
			new ToolBarData(ResourceManager.loadImage("images/redo.png"), "UndoRedo"));
		redoAction.setEnabled(false);
		plugin.getTool().addLocalAction(this, redoAction);

		saveAction = new DockingAction("Save File", plugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				save();
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				Object contextObject = context.getContextObject();
				return contextObject == TextEditorComponentProvider.this;
			}
		};
		saveAction.setDescription("Save");
		saveAction.setToolBarData(
			new ToolBarData(ResourceManager.loadImage("images/disk.png"), "Save"));
		saveAction.setEnabled(false);
		plugin.getTool().addLocalAction(this, saveAction);

		saveAsAction = new DockingAction("Save File As", plugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				saveAs();
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				Object contextObject = context.getContextObject();
				return contextObject == TextEditorComponentProvider.this;
			}
		};
		saveAsAction.setDescription("Save As...");
		saveAsAction.setToolBarData(
			new ToolBarData(ResourceManager.loadImage("images/disk_save_as.png"), "Save"));
		saveAsAction.setEnabled(true);
		plugin.getTool().addLocalAction(this, saveAsAction);

		fontAction = new DockingAction("Select Font", plugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				doSelectFont();
			}
		};
		fontAction.setToolBarData(
			new ToolBarData(ResourceManager.loadImage("images/text_lowercase.png"), "ZZFont"));
		fontAction.setDescription("Select Font");
		fontAction.setEnabled(true);
		plugin.getTool().addLocalAction(this, fontAction);

		/****************************************************************/
		// DO NOT REMOVE THIS CODE!!
		// We need to override certain keybindings so that no other components in
		// Ghidra receive them

		ActionContextProvider acp = e -> {
			ComponentProvider p = TextEditorComponentProvider.this;
			return new ActionContext(p);
		};

		KeyBindingUtils.registerAction(textarea, saveAction, acp);
		KeyBindingUtils.registerAction(textarea, redoAction, acp);
		KeyBindingUtils.registerAction(textarea, undoAction, acp);
		/****************************************************************/
	}

	protected void doSelectFont() {
		FontPropertyEditor editor = new FontPropertyEditor();
		editor.setValue(defaultFont);
		editor.showDialog();
		defaultFont = (Font) editor.getValue();

		List<TextEditorComponentProvider> values = plugin.getEditors();
		Iterator<TextEditorComponentProvider> iterator = values.iterator();
		while (iterator.hasNext()) {
			TextEditorComponentProvider editorComponent = iterator.next();
			editorComponent.textarea.setFont(defaultFont);
		}
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
					Msg.showError(getClass(), getComponent(), "Error saving file", e.getMessage());
				}
				else {
					Msg.showError(getClass(), getComponent(), "Error Saving File",
						"The file is not writable.");
				}
			}
		}
	}

	private void saveAs() {
		if (chooser == null) {
			chooser = new GhidraFileChooser(getComponent());
		}
		File saveAsFile = chooser.getSelectedFile();
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
		if (plugin.removeTextFile(this, textFileName)) {
			clearUndoRedoStack();
			plugin.getTool().removeComponentProvider(this);
		}
	}

	@Override
	public JComponent getComponent() {
		return scrollpane;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	/**
	 * Special JTextArea that knows how to properly handle it's key events.
	 * @see #processKeyBinding(KeyStroke, KeyEvent, int, boolean)
	 */
	private class KeyMasterTextArea extends JTextArea {
		private static final long serialVersionUID = 1L;

		private KeyMasterTextArea(String text) {
			super(text);

			setFont(defaultFont);
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
				updateUndoRedoAction();
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
