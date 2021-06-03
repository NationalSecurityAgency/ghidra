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
package ghidra.app.plugin.core.script;

import java.awt.Dimension;
import java.awt.Font;
import java.awt.event.KeyEvent;
import java.awt.event.MouseEvent;
import java.io.*;
import java.util.Collection;
import java.util.Iterator;

import javax.swing.*;
import javax.swing.text.Document;
import javax.swing.undo.UndoableEdit;

import docking.*;
import docking.action.*;
import docking.actions.KeyBindingUtils;
import docking.options.editor.FontPropertyEditor;
import docking.widgets.OptionDialog;
import generic.jar.ResourceFile;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.framework.options.SaveState;
import ghidra.util.*;
import ghidra.util.datastruct.FixedSizeStack;
import resources.Icons;
import resources.ResourceManager;

public class GhidraScriptEditorComponentProvider extends ComponentProvider {
	static final String EDITOR_COMPONENT_NAME="EDITOR";
	
	static final String CHANGE_DESTINATION_TITLE = "Where Would You Like to Store Your Changes?";
	static final String FILE_ON_DISK_CHANGED_TITLE = "File Changed on Disk";
	static final String FILE_ON_DISK_MISSING_TITLE = "File on Disk is Missing";

	static final String SAVE_CHANGES_AS_TEXT = "Save Changes As...";
	static final String OVERWRITE_CHANGES_TEXT = "Overwrite Changes on Disk";
	static final String KEEP_CHANGES_TEXT = "Keep Changes";
	static final String DISCARD_CHANGES_TEXT = "Discard Changes";

	private static final int MAX_UNDO_REDO_SIZE = 50;

	private static Font defaultFont = new Font("monospaced", Font.PLAIN, 12);

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


	private GhidraScriptMgrPlugin plugin;
	private GhidraScriptComponentProvider provider;
	private String title;

	private ResourceFile scriptSourceFile;
	private String fileHash;

	private DockingAction saveAction;
	private DockingAction saveAsAction;
	private DockingAction runAction;
	private DockingAction undoAction;
	private DockingAction redoAction;
	private DockingAction fontAction;

	private JTextArea textArea;
	private JScrollPane scrollPane;

	private FixedSizeStack<UndoableEdit> undoStack = new FixedSizeStack<>(MAX_UNDO_REDO_SIZE);
	private FixedSizeStack<UndoableEdit> redoStack = new FixedSizeStack<>(MAX_UNDO_REDO_SIZE);

	GhidraScriptEditorComponentProvider(GhidraScriptMgrPlugin plugin,
			GhidraScriptComponentProvider provider, ResourceFile scriptSourceFile)
			throws IOException {
		super(plugin.getTool(), "Script Editor", plugin.getName());
		this.plugin = plugin;
		this.provider = provider;
		setHelpLocation(new HelpLocation(plugin.getName(), plugin.getName()));
		setWindowGroup(GhidraScriptComponentProvider.WINDOW_GROUP);
		setIntraGroupPosition(WindowPosition.RIGHT);

		loadScript(scriptSourceFile);

		addToTool();
		setVisible(true);

		createActions();
	}

	private void loadScript(ResourceFile scriptFile) throws IOException {
		this.scriptSourceFile = scriptFile;
		File fileOnDisk = scriptSourceFile.getFile(false);
		if (fileOnDisk == null || !fileOnDisk.exists()) {
			// deleted?
			return;
		}

		this.fileHash = MD5Utilities.getMD5Hash(fileOnDisk);
		title = scriptSourceFile.getName() + (isReadOnly(scriptSourceFile) ? " (Read-Only) " : "");
		setTitle(title);
		String scriptSource = loadSciptFile();

		if (textArea == null) {
			// first time loading
			textArea = new KeyMasterTextArea(scriptSource);
			scrollPane = new JScrollPane(textArea);
			scrollPane.setName("EDITOR_SCROLL_PANE");
			scrollPane.setPreferredSize(new Dimension(400, 400));
		}
		else {
			textArea.setText(scriptSource);
		}
	}

	private static boolean isReadOnly(ResourceFile scriptSourceFile) {
		return GhidraScriptUtil.isSystemScript(scriptSourceFile);
	}

//    private boolean isSystemScript() {
//    	if (scriptSourceFile == null) {
//    		return false;
//    	}
//    	File system = new File(GhidraScriptUtil.SYS_SCRIPTS_DIR);
//    	return system.equals( scriptSourceFile.getParentFile() );
//    }
	private void clearUndoRedoStack() {
		undoStack.clear();
		redoStack.clear();
		updateUndoRedoAction();
	}

	private void updateUndoRedoAction() {
		undoAction.setEnabled(!undoStack.isEmpty());
		redoAction.setEnabled(!redoStack.isEmpty());
		updateChangedState();
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

	boolean hasChanges() {
		return !undoStack.isEmpty() || isFileOnDiskMissing();
	}

	private void updateChangedState() {
		boolean hasChanges = hasChanges();
		if (hasChanges) {
			setTitle("*" + title);
		}
		else {
			setTitle(title);
		}
		contextChanged();
	}

	private void clearChanges() {
		try {
			fileHash = MD5Utilities.getMD5Hash(scriptSourceFile.getFile(false));
		}
		catch (IOException e) {
			Msg.showError(this, null, "Script File Error",
				"Error accessing file: " + scriptSourceFile, e);
		}
		clearUndoRedoStack();
		updateChangedState();
	}

	private String loadSciptFile() throws IOException {
		StringBuffer buffer = new StringBuffer();
		BufferedReader reader =
			new BufferedReader(new InputStreamReader(scriptSourceFile.getInputStream()));
		try {
			while (true) {
				String line = reader.readLine();
				if (line == null) {
					break;
				}
				buffer.append(line);
				buffer.append('\n');
			}
		}
		finally {
			reader.close();
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
				return contextObject == GhidraScriptEditorComponentProvider.this && !undoStack.isEmpty();
			}
		};
		undoAction.setDescription("Undo");
		undoAction.setToolBarData(
			new ToolBarData(ResourceManager.loadImage("images/undo.png"), "UndoRedo"));
		undoAction.setEnabled(false);
		undoAction.setKeyBindingData(new KeyBindingData(
			KeyStroke.getKeyStroke(KeyEvent.VK_Z, DockingUtils.CONTROL_KEY_MODIFIER_MASK)));
		plugin.getTool().addLocalAction(this, undoAction);

		redoAction = new DockingAction("Redo", plugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				redo();
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				Object contextObject = context.getContextObject();
				return contextObject == GhidraScriptEditorComponentProvider.this && !redoStack.isEmpty();
			}
		};
		redoAction.setDescription("Redo");
		redoAction.setToolBarData(
			new ToolBarData(ResourceManager.loadImage("images/redo.png"), "UndoRedo"));
		redoAction.setKeyBindingData(new KeyBindingData(
			KeyStroke.getKeyStroke(KeyEvent.VK_Y, DockingUtils.CONTROL_KEY_MODIFIER_MASK)));
		redoAction.setEnabled(false);
		plugin.getTool().addLocalAction(this, redoAction);

		saveAction = new DockingAction("Save Script", plugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				save();
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				Object contextObject = context.getContextObject();
				if (contextObject != GhidraScriptEditorComponentProvider.this) {
					return false;
				}

				if (isReadOnly(scriptSourceFile)) {
					return false;
				}

				return hasChanges();
			}
		};
		saveAction.setDescription("Save");
		saveAction.setToolBarData(
			new ToolBarData(ResourceManager.loadImage("images/disk.png"), "Save"));
		saveAction.setKeyBindingData(new KeyBindingData(
			KeyStroke.getKeyStroke(KeyEvent.VK_S, DockingUtils.CONTROL_KEY_MODIFIER_MASK)));

		plugin.getTool().addLocalAction(this, saveAction);

		DockingAction refreshAction = new DockingAction("Refresh Script", plugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				refresh();
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				Object contextObject = context.getContextObject();
				return contextObject == GhidraScriptEditorComponentProvider.this;
			}
		};
		refreshAction.setDescription("Refresh the contents of the editor from the file on disk");
		refreshAction.setToolBarData(new ToolBarData(Icons.REFRESH_ICON, "Refresh"));
		refreshAction.setEnabled(true);
		plugin.getTool().addLocalAction(this, refreshAction);

		saveAsAction = new DockingAction("Save Script As", plugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				saveAs();
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				Object contextObject = context.getContextObject();
				return contextObject == GhidraScriptEditorComponentProvider.this;
			}
		};
		saveAsAction.setDescription("Save As...");
		saveAsAction.setToolBarData(
			new ToolBarData(ResourceManager.loadImage("images/disk_save_as.png"), "Save"));
		saveAsAction.setEnabled(true);
		plugin.getTool().addLocalAction(this, saveAsAction);

		runAction = new DockingAction("Run Script", plugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				if (hasChanges()) {
					if (isReadOnly(scriptSourceFile)) {
						Msg.showError(getClass(), getComponent(), getName(),
							"Unable to run read-only script because there are unsaved changes.");
						return;
					}
					int result = OptionDialog.showYesNoDialog(getComponent(), getName(),
						"File " + scriptSourceFile.getName() +
							" has changed. Do you want to save it first?\n");
					if (result == OptionDialog.OPTION_ONE) {
						save();
					}
				}
				provider.runScript(scriptSourceFile);
			}
		};
		runAction.setToolBarData(
			new ToolBarData(ResourceManager.loadImage("images/play.png"), "ZRun"));
		runAction.setDescription("Run Editor's Script");
		runAction.setPopupMenuData(new MenuData(new String[] { "Run" }, "ZRun"));
		runAction.setEnabled(true);
		runAction.setHelpLocation(new HelpLocation(plugin.getName(), "Run"));
		plugin.getTool().addLocalAction(this, runAction);

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

//****************************************************************/
		// DO NOT REMOVE THIS CODE!!
		// We need to override certain keybindings so that no other components in
		// Ghidra receive them
		KeyBindingUtils.registerAction(textArea, saveAction, this);
		KeyBindingUtils.registerAction(textArea, redoAction, this);
		KeyBindingUtils.registerAction(textArea, undoAction, this);
//****************************************************************/
	}

	private void refresh() {
		if (isFileOnDiskMissing()) {
			if (handleDeletedFile()) {
				provider.refresh();  // force the provider to remove its reference to the file
			}
			return;
		}

		// if not changed, then do nothing but print a message to let the user know that we 
		// tried
		if (!hasFileOnDiskChanged()) {
			plugin.getTool().setStatusInfo("Refresh Script - file has not changed");
			return;
		}

		// dirty file, but clean editor--just reload
		if (!hasChanges()) {
			reloadScript();
			return;
		}

		// this case means changed disk file and changed editor
		handleChangesOnDisk();
	}

	boolean isFileOnDiskMissing() {
		File fileOnDisk = scriptSourceFile.getFile(false);
		return !fileOnDisk.exists();
	}

	boolean hasFileOnDiskChanged() {
		File fileOnDisk = scriptSourceFile.getFile(false);
		if (fileOnDisk == null || !fileOnDisk.exists()) {
			// deleted?
			return true;
		}

		try {
			String currentHash = MD5Utilities.getMD5Hash(fileOnDisk);
			return !fileHash.equals(currentHash);
		}
		catch (IOException e) {
			Msg.showError(this, null, "Script File Error",
				"Error accessing file: " + scriptSourceFile, e);
			return false;
		}
	}

	/** 
	 * Returns false if the user cancels--meaning they did not make a decision regarding the
	 * file (or 'handle' it).
	 */
	private boolean handleDeletedFile() {
		int choice = OptionDialog.showOptionDialog(scrollPane, FILE_ON_DISK_MISSING_TITLE,
			"The script file on disk no longer exists.\nWould you like to " +
				"keep the changes in the editor or discard your changes?",
			KEEP_CHANGES_TEXT, DISCARD_CHANGES_TEXT, OptionDialog.QUESTION_MESSAGE);

		if (choice == OptionDialog.CANCEL_OPTION) {
			// Cancel
			return false;
		}

		if (choice == OptionDialog.OPTION_TWO) {
			// Discard Changes!
			closeComponentWithoutSaving();
			return true;
		}

		saveAs();
		return true;
	}

	private void handleChangesOnDisk() {

		int choice = OptionDialog.showOptionDialog(scrollPane, FILE_ON_DISK_CHANGED_TITLE,
			"<html>The contents of the script file have changed on disk.<br><br>Would " +
				"you like to <b>keep your changes</b> in the editor or <b><font color=\"red\">" +
				"discard</font></b> your changes?",
			KEEP_CHANGES_TEXT, DISCARD_CHANGES_TEXT, OptionDialog.QUESTION_MESSAGE);

		if (choice == OptionDialog.CANCEL_OPTION) {
			// Cancel
			return;
		}

		if (choice == OptionDialog.OPTION_TWO) {
			// Discard Changes!
			reloadScript();
			return;
		}

		// implicit: choice == OptionDialog.OPTION_ONE

		//
		// The user wants to keep the changes, but how?
		//
		choice = OptionDialog.showOptionDialog(scrollPane, CHANGE_DESTINATION_TITLE,
			"<html>You can save your current changes to <b>another file</b> or " +
				"<b><font color=\"red\">overwrite</font></b> the contents of the file on disk.",
			SAVE_CHANGES_AS_TEXT, OVERWRITE_CHANGES_TEXT, OptionDialog.QUESTION_MESSAGE);

		//
		// Cancel
		//
		if (choice == OptionDialog.OPTION_THREE) {
			// Cancel
			return;
		}

		//
		// Save As...
		//
		ResourceFile previousFile = scriptSourceFile;
		if (choice == OptionDialog.OPTION_ONE) {
			// Save As...
			if (saveAs()) {
				// Save As completed successfully; open a new editor 
				// with the original file
				provider.editScriptInGhidra(previousFile);
			}

			return;
		}

		//
		// Overwrite changes on disk with a normal save operation
		//
		doSave();
	}

	private void reloadScript() {
		// this will overwrite any changes--be sure to resolve that before calling this method!
		try {
			loadScript(scriptSourceFile);
			fileHash = MD5Utilities.getMD5Hash(scriptSourceFile.getFile(false));
			clearChanges();
			refreshAction();
		}
		catch (IOException e) {
			Msg.showError(this, getComponent(), "Error reloading script: " + scriptSourceFile,
				e.getMessage(), e);
		}
	}

	private void doSelectFont() {
		FontPropertyEditor editor = new FontPropertyEditor();
		editor.setValue(defaultFont);
		editor.showDialog();
		defaultFont = (Font) editor.getValue();

		Collection<GhidraScriptEditorComponentProvider> values = provider.getEditorMap().values();
		Iterator<GhidraScriptEditorComponentProvider> iterator = values.iterator();
		while (iterator.hasNext()) {
			GhidraScriptEditorComponentProvider editorComponent = iterator.next();
			editorComponent.textArea.setFont(defaultFont);
		}
	}

	private void save() {
		if (!hasChanges()) {
			return;
		}

		if (scriptSourceFile == null) {
			saveAs();
			return;
		}

		if (isFileOnDiskMissing()) {
			doSave();
			return;
		}

		if (hasFileOnDiskChanged()) {
			// special case--the editor has been changed AND the file has been changed on disk
			handleChangesOnDisk();
			return;
		}

		doSave();
	}

	private void doSave() {
		String text = textArea.getText();

		try {
			PrintWriter writer = new PrintWriter(new FileWriter(scriptSourceFile.getFile(false)));
			writer.print(text);
			writer.close();
			clearChanges();
			provider.getTable().repaint();
			refreshAction();
		}
		catch (IOException e) {
			if (scriptSourceFile.canWrite()) {
				Msg.showError(getClass(), getComponent(), "Error saving script", e.getMessage());
			}
			else {
				Msg.showError(getClass(), getComponent(), "Error saving script",
					"The file is not writable.");
			}
		}

		provider.scriptUpdated(scriptSourceFile);
	}

	private void refreshAction() {
		ScriptAction action = provider.getActionManager().get(scriptSourceFile);
		if (action != null) {
			action.refresh();
		}
	}

	private boolean saveAs() {
		HelpLocation help = new HelpLocation(plugin.getName(), saveAction.getName());
		SaveDialog dialog =
			new SaveDialog(getComponent(), "Save Script", provider, scriptSourceFile, help);
		if (dialog.isCancelled()) {
			return false;
		}

		ResourceFile saveAsFile = dialog.getFile();
		boolean exists = saveAsFile.exists();
		if (exists) {
			int result = OptionDialog.showYesNoDialog(getComponent(), getName(),
				"Do you want to OVERWRITE the following script:\n" + saveAsFile.getName());
			if (result != OptionDialog.OPTION_ONE) {
				return false;
			}
		}

		provider.enableScriptDirectory(saveAsFile.getParentFile());

		try {
			String str = textArea.getText();
			str = str.replaceAll(GhidraScriptUtil.getBaseName(scriptSourceFile),
				GhidraScriptUtil.getBaseName(saveAsFile));
			textArea.setText(str);

			PrintWriter writer = new PrintWriter(new FileWriter(saveAsFile.getFile(false)));
			writer.print(str);
			writer.close();

			provider.switchEditor(scriptSourceFile, saveAsFile);
			scriptSourceFile = saveAsFile;

			title = saveAsFile.getName();

			clearChanges();

			provider.sortScripts();
			return true;
		}
		catch (IOException e) {
			Msg.showError(getClass(), getComponent(), "Error saving as script", e.getMessage());
			return false;
		}
	}

//==================================================================================================
// ComponentProvider Methods
//==================================================================================================

	@Override
	public void closeComponent() {
		if (isFileOnDiskMissing()) {
			if (!handleDeletedFile()) {
				return; // user cancelled
			}
			provider.refresh();
		}

		closeComponentSavingAsNecessary();
	}

	private void closeComponentSavingAsNecessary() {
		provider.removeScriptEditor(scriptSourceFile, true);
	}

	private void closeComponentWithoutSaving() {
		provider.removeScriptEditor(scriptSourceFile, false);
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		return createContext(this);
	}

	@Override
	public JComponent getComponent() {
		return scrollPane;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================
	/**
	 * Special JTextArea that knows how to properly handle it's key events.
	 * See {@link #processKeyBinding(KeyStroke, KeyEvent, int, boolean)}
	 */
	private class KeyMasterTextArea extends JTextArea {

		private KeyMasterTextArea(String text) {
			super(text);

			setFont(defaultFont);
			setName(EDITOR_COMPONENT_NAME);
			setWrapStyleWord(false);
			Document document = getDocument();
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
