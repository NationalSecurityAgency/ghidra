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

import ghidra.framework.model.ToolServices;
import ghidra.framework.model.ToolTemplate;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.dialog.SaveToolConfigDialog;
import ghidra.util.Msg;

/**
 * Helper class to manage actions for saving and exporting the tool
 */
public class DialogManager {
	private PluginTool tool;
	private SaveToolConfigDialog saveToolDialog;

	public DialogManager(PluginTool tool) {
		this.tool = tool;
	}

	/**
	 * Show the "Save Tool" dialog.  Returns true if the user performed a 'save as'; returns false
	 * if the user cancelled.
	 * @return false if the user cancelled
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

	/**
	 * Exports a version of our tool without any config settings.  This is useful for making a
	 * new 'default' tool to be shared with others, which will not contain any user settings.
	 */
	public void exportDefaultTool() {
		ToolTemplate template = tool.getToolTemplate(false);
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
}
