/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.framework.plugintool.mgr;

import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.dialog.SaveToolConfigDialog;
import ghidra.framework.preferences.Preferences;
import ghidra.util.Msg;
import ghidra.util.filechooser.GhidraFileChooserModel;
import ghidra.util.filechooser.GhidraFileFilter;

import java.io.File;
import java.io.IOException;

import docking.widgets.OptionDialog;
import docking.widgets.filechooser.GhidraFileChooser;

/**
 * Helper class to manage actions for saving and exporting the tool. 
 *
 */
public class DialogManager {
	private PluginTool tool;
	private SaveToolConfigDialog saveToolDialog;
	private GhidraFileChooser ghidraFileChooser;

	public DialogManager(PluginTool tool) {
		this.tool = tool;
	}

	/**
	 * Show the "Save Tool" dialog.  Returns true if the user performed a 'save as'; returns false
	 * if the user cancelled.
	 *
	 */
	public boolean saveToolAs() {
		if (saveToolDialog == null) {
			saveToolDialog = new SaveToolConfigDialog(tool, tool.getToolServices());
		}
		saveToolDialog.show(tool.getName(), tool.getToolName());

		return !saveToolDialog.didCancel();
	}

	/**
	 * Write this tool to a filename; the user is prompted for
	 * a filename.
	 */
	public void exportTool() {
		GhidraFileChooser fileChooser = getFileChooser();

		File exportFile = null;
		while (exportFile == null) {
			exportFile = fileChooser.getSelectedFile(); // show the chooser
			if (exportFile == null) {
				return; // user cancelled
			}

			Preferences.setProperty(Preferences.LAST_TOOL_EXPORT_DIRECTORY, exportFile.getParent());
			if (!exportFile.getName().endsWith(".tool")) {
				exportFile = new File(exportFile.getAbsolutePath() + ".tool");
			}
			if (exportFile.exists()) {
				int result =
					OptionDialog.showOptionDialog(tool.getToolFrame(), "Overwrite?",
						"Overwrite existing file, " + exportFile.getName() + "?", "Overwrite",
						OptionDialog.QUESTION_MESSAGE);
				if (result != OptionDialog.OPTION_ONE) {
					exportFile = null; // user chose not to overwrite
				}
			}
		}

		try {
			tool.getProject().getToolServices().exportTool(exportFile, tool);
			Msg.info(this, "Successfully exported " + tool.getName() + " to " +
				exportFile.getAbsolutePath());
		}
		catch (IOException e) {
			Msg.showError(this, tool.getToolFrame(), "Error Exporting Tool",
				"Error exporting tool: " + e.getMessage(), e);
		}
		catch (Exception e) {
			Msg.showError(this, null, "Error", "Error exporting tool tool", e);
		}

	}

	private GhidraFileChooser getFileChooser() {
		if (ghidraFileChooser != null) {
			return ghidraFileChooser; // lazy inited
		}

		GhidraFileChooser newFileChooser = new GhidraFileChooser(tool.getToolFrame());
		newFileChooser.setFileFilter(new GhidraFileFilter() {
			public boolean accept(File file, GhidraFileChooserModel model) {
				if (file == null) {
					return false;
				}

				if (file.isDirectory()) {
					return true;
				}

				return file.getAbsolutePath().toLowerCase().endsWith("tool");
			}

			public String getDescription() {
				return "Tools";
			}
		});

		String exportDir = Preferences.getProperty(Preferences.LAST_TOOL_EXPORT_DIRECTORY);
		if (exportDir != null) {
			newFileChooser.setCurrentDirectory(new File(exportDir));
		}

		newFileChooser.setTitle("Export Tool");
		newFileChooser.setApproveButtonText("Export");

		return newFileChooser;
	}
}
