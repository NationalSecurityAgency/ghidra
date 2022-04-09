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

import java.awt.BorderLayout;
import java.util.List;

import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import docking.DialogComponentProvider;
import ghidra.app.script.ScriptInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.HelpLocation;
import ghidra.util.Swing;

/**
 * A dialog that prompts the user to select a script.
 */
public class ScriptSelectionDialog extends DialogComponentProvider {

	private ScriptSelectionEditor editor;
	private PluginTool tool;
	private List<ScriptInfo> scriptInfos;
	private ScriptInfo userChoice;

	ScriptSelectionDialog(GhidraScriptMgrPlugin plugin, List<ScriptInfo> scriptInfos) {
		super("Run Script", true, true, true, false);
		this.tool = plugin.getTool();
		this.scriptInfos = scriptInfos;

		init();

		setHelpLocation(new HelpLocation(plugin.getName(), "Script Quick Launch"));
	}

	private void init() {
		buildEditor();

		addOKButton();
		addCancelButton();
	}

	private void buildEditor() {
		removeWorkPanel();

		editor = new ScriptSelectionEditor(scriptInfos);

		editor.setConsumeEnterKeyPress(false); // we want to handle Enter key presses

		editor.addEditorListener(new ScriptEditorListener() {
			@Override
			public void editingCancelled() {
				if (isVisible()) {
					cancelCallback();
				}
			}

			@Override
			public void editingStopped() {
				if (isVisible()) {
					okCallback();
				}
			}
		});
		editor.addDocumentListener(new DocumentListener() {

			@Override
			public void changedUpdate(DocumentEvent e) {
				textUpdated();
			}

			@Override
			public void insertUpdate(DocumentEvent e) {
				textUpdated();
			}

			@Override
			public void removeUpdate(DocumentEvent e) {
				textUpdated();
			}

			private void textUpdated() {
				clearStatusText();
			}

		});

		JComponent mainPanel = createEditorPanel();
		addWorkPanel(mainPanel);

		rootPanel.validate();
	}

	private JComponent createEditorPanel() {
		JPanel mainPanel = new JPanel(new BorderLayout());
		mainPanel.add(editor.getEditorComponent(), BorderLayout.NORTH);
		return mainPanel;
	}

	public void show() {
		tool.showDialog(this);
	}

	public ScriptInfo getUserChoice() {
		return userChoice;
	}

	@Override
	protected void dialogShown() {
		Swing.runLater(() -> editor.requestFocus());
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

		if (!editor.validateUserSelection()) {
			setStatusText("Invalid script name");
			return;
		}

		userChoice = editor.getEditorValue();

		clearStatusText();
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

}
