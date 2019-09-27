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
package ghidra.framework.plugintool.mgr;

import java.io.File;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import docking.widgets.OptionDialog;
import docking.widgets.filechooser.GhidraFileChooser;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.dialog.SaveToolConfigDialog;
import ghidra.util.Msg;

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
	 * Write our tool to a filename; the user is prompted for a filename
	 */
	public void exportTool() {
		ToolTemplate template = tool.getToolTemplate(true);
		exportTool(template);
	}

	private void exportTool(ToolTemplate template) {
		ToolServices services = tool.getProject().getToolServices();
		try {
			File savedFile = services.exportTool(template);
			if (savedFile != null) {
				Msg.info(this, "Successfully exported " + tool.getName() + " to " +
					savedFile.getAbsolutePath());
			}
		}
		catch (Exception e) {
			Msg.showError(this, null, "Error", "Error exporting tool tool", e);
		}
	}

	/**
	 * Exports a version of our tool without any config settings.  This is useful for making a
	 * new 'default' tool to be shared with others, which will not contain any user settings.
	 */
	public void exportDefaultTool() {

		Project project = tool.getProject();
		ToolChest toolChest = project.getLocalToolChest();
		ToolTemplate[] templates = toolChest.getToolTemplates();
		List<String> namesList =
			Arrays.stream(templates).map(t -> t.getName()).collect(Collectors.toList());
		if (namesList.isEmpty()) {
			Msg.showInfo(this, null, "No Tools", "There are no tools to export");
			return;
		}

		String[] names = namesList.toArray(new String[namesList.size()]);
		String choice = OptionDialog.showInputChoiceDialog(null, "Choose Tool", "Choose Tool",
			names, null, OptionDialog.QUESTION_MESSAGE);
		if (choice == null) {
			return;
		}

		ToolTemplate template = toolChest.getToolTemplate(choice);
		Tool templateTool = template.createTool(project);
		ToolTemplate defaultTemplate = templateTool.getToolTemplate(false);

		exportTool(defaultTemplate);
	}

}
