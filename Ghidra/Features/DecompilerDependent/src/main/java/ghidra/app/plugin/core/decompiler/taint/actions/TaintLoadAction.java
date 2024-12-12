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
package ghidra.app.plugin.core.decompiler.taint.actions;

import java.io.File;

import javax.swing.Icon;

import docking.action.MenuData;
import docking.action.ToolBarData;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import generic.theme.GIcon;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.plugin.core.decompiler.taint.TaintPlugin;
import ghidra.app.plugin.core.decompiler.taint.TaintState;
import ghidra.app.util.HelpTopics;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;

/**
 * Normal workflow is for a QUERY to be executed which is immediately followed by ingesting the results for use.
 * 
 * <p>
 * This action will allow PREVIOUSLY generated query output (possibly generated externally) to be read
 * in for the program binary.
 * 
 * <p>
 * Action triggered from a specific token in the decompiler window to mark a variable as a source or
 * sink and generate the requisite query. This can be an input parameter, a stack variable, a
 * variable associated with a register, or a "dynamic" variable.
 */
public class TaintLoadAction extends TaintAbstractDecompilerAction {

	private TaintPlugin plugin;
	private TaintState state;

	private static String loadSarifFileIconString = "icon.fsbrowser.file.extension.obj";
	private static Icon loadSarifFileIcon = new GIcon(loadSarifFileIconString);

	public TaintLoadAction(TaintPlugin plugin, TaintState state) {
		super("Load SARIF file");
		setHelpLocation(new HelpLocation(TaintPlugin.HELP_LOCATION, "TaintLoadSarif"));

		setMenuBarData(new MenuData(new String[] { "Source-Sink", getName() }));
		setToolBarData(new ToolBarData(loadSarifFileIcon));

		this.plugin = plugin;
		this.state = state;
	}

	@Override
	protected boolean isEnabledForDecompilerContext(DecompilerActionContext context) {
		// this should always be enabled; we do not need any sources or sinks designated.
		return true;
	}

	@Override
	protected void decompilerActionPerformed(DecompilerActionContext context) {
		Program program = context.getProgram();
		PluginTool tool = context.getTool();

		// Objectives:
		// Pop a file dialog to select the SARIF file.

		// need to pop-up a file chooser dialog.
		GhidraFileChooser file_chooser = new GhidraFileChooser(tool.getToolFrame());
		file_chooser.setCurrentDirectory(new File(state.getOptions().getTaintEnginePath()));
		file_chooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
		file_chooser.setTitle("Select a Source-Sink Query Results SARIF File");

		File sarifFile = file_chooser.getSelectedFile(true);

		if (sarifFile != null && sarifFile.canRead()) {
			plugin.consoleMessage(
				String.format("Setting feature file: %s\n", sarifFile.getAbsolutePath()));
			state.loadTaintData(program, sarifFile);
			plugin.consoleMessage("external query results loaded.");
		}
		else {
			plugin.consoleMessage("No sarif file specified, or file does not exist.");

		}
	}
}
