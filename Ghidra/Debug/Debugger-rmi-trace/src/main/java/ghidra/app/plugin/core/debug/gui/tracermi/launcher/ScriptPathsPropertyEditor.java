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
package ghidra.app.plugin.core.debug.gui.tracermi.launcher;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.event.ActionEvent;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.swing.JButton;
import javax.swing.JPanel;

import org.apache.commons.text.StringEscapeUtils;

import docking.DockingWindowManager;
import docking.widgets.OptionDialog;
import docking.widgets.filechooser.GhidraFileChooserMode;
import docking.widgets.pathmanager.*;
import utility.function.Callback;

public class ScriptPathsPropertyEditor extends AbstractTypedPropertyEditor<String> {

	@Override
	protected String fromText(String text) {
		return text;
	}

	@Override
	public String getJavaInitializationString() {
		return "\"" + StringEscapeUtils.escapeJava(getValue()) + "\"";
	}

	@Override
	public Component getCustomEditor() {
		return new ScriptPathsEditor();
	}

	protected class ScriptPathsEditor extends JPanel {
		public ScriptPathsEditor() {
			super(new BorderLayout());
			JButton button = new JButton("Edit Paths");
			button.addActionListener(this::showDialog);
			add(button);
		}

		protected void showDialog(ActionEvent evt) {
			DockingWindowManager.showDialog(this, new ScriptPathsDialog());
		}
	}

	protected class ScriptPathsDialog extends AbstractPathsDialog {
		protected ScriptPathsDialog() {
			super("Debugger Launch Script Paths");
		}

		@Override
		protected String[] loadPaths() {
			return getValue().lines().filter(d -> !d.isBlank()).toArray(String[]::new);
		}

		@Override
		protected void savePaths(String[] paths) {
			setValue(Stream.of(paths).collect(Collectors.joining("\n")));
		}

		@Override
		protected PathnameTablePanel newPathnameTablePanel() {
			PathnameTablePanel tablePanel = new ScriptPathsPanel(this::reset);
			tablePanel.setFileChooserProperties(getTitle(), "DebuggerLaunchScriptDirectory",
				GhidraFileChooserMode.DIRECTORIES_ONLY, true, null);
			return tablePanel;
		}
	}

	protected class ScriptPathsPanel extends PathnameTablePanel {
		public ScriptPathsPanel(Callback resetCallback) {
			// disable edits, top/bottom irrelevant, unordered
			super(null, resetCallback, false, false, false);
		}

		@Override
		protected int promptConfirmReset() {
			String confirmation = """
					<html><body width="200px">
					  Are you sure you would like to reload the Debugger's launcher script paths?
					  This will reset any changes you've made so far.
					</html>""";
			String header = "Reset Script Paths?";

			return OptionDialog.showYesNoDialog(this, header, confirmation);
		}
	}
}
