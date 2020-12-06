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
package ghidra.app.plugin.core.decompile.actions;

import java.io.File;

import javax.swing.JComponent;

import docking.action.MenuData;
import docking.widgets.OptionDialog;
import docking.widgets.filechooser.GhidraFileChooser;
import ghidra.app.decompiler.component.DecompilerController;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.util.HelpTopics;
import ghidra.util.HelpLocation;
import ghidra.util.filechooser.ExtensionFileFilter;

public class DebugDecompilerAction extends AbstractDecompilerAction {

	private DecompilerController controller;

	public DebugDecompilerAction(DecompilerController controller) {
		super("Debug Function Decompilation");
		setHelpLocation(new HelpLocation(HelpTopics.DECOMPILER, "ToolBarDebug"));
		this.controller = controller;
		setMenuBarData(new MenuData(new String[] { "Debug Function Decompilation" }, "xDebug"));
	}

	@Override
	protected boolean isEnabledForDecompilerContext(DecompilerActionContext context) {
		return context.getFunction() != null;
	}

	@Override
	protected void decompilerActionPerformed(DecompilerActionContext context) {
		JComponent parentComponent = context.getDecompilerPanel();
		GhidraFileChooser fileChooser = new GhidraFileChooser(parentComponent);
		fileChooser.setTitle("Please Choose Output File");
		fileChooser.setFileFilter(new ExtensionFileFilter(new String[] { "xml" }, "XML Files"));
		File file = fileChooser.getSelectedFile();
		if (file == null) {
			return;
		}
		if (file.exists()) {
			if (OptionDialog.showYesNoDialog(parentComponent, "Overwrite Existing File?",
				"Do you want to overwrite the existing file?") == OptionDialog.OPTION_TWO) {
				return;
			}
		}
		controller.setStatusMessage("Dumping debug info to " + file.getAbsolutePath());
		controller.refreshDisplay(controller.getProgram(), controller.getLocation(), file);
	}

}
