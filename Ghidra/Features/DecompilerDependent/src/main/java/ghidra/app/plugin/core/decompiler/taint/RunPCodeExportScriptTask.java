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
package ghidra.app.plugin.core.decompiler.taint;

import java.io.File;
import java.nio.file.Path;

import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraState;
import ghidra.app.services.ConsoleService;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

public class RunPCodeExportScriptTask extends Task {

	private PluginTool tool;
	private GhidraScript script;
	private GhidraState currentState;
	private ConsoleService console;
	private String scriptName;

	public RunPCodeExportScriptTask(PluginTool tool, GhidraScript script, GhidraState currentState,
			ConsoleService console) {
		super(script.getSourceFile().getName(), true, false, false);
		this.tool = tool;
		this.script = script;
		this.scriptName = script.getSourceFile().getName();
		this.console = console;
		this.currentState = currentState;
	}

	@Override
	public void run(TaskMonitor monitor) {
		try {
			Thread.currentThread().setName(scriptName);

			ToolOptions options = tool.getOptions("Decompiler");
			String facts_directory =
				options.getString(TaintOptions.OP_KEY_TAINT_FACTS_DIR, "/tmp/export");
			Path facts_path = Path.of(facts_directory);
			if (!facts_path.toFile().exists() || !facts_path.toFile().isDirectory()) {
				Msg.info(this, "Facts Path: " + facts_path.toString() + " does not exists.");
				facts_directory = getDirectoryPath(facts_directory,
					"Select full path to the directory containing the facts files");
				if (facts_directory == null) {
					Msg.info(this, "User cancelled operation; existing script.");
					return;
				}
				Msg.info(this, "Using .facts files in: " + facts_directory);
				options.setString(TaintOptions.OP_KEY_TAINT_FACTS_DIR, facts_directory);
			}
			script.setScriptArgs(new String[] { facts_directory });

			console.addMessage(scriptName, "Running...");
			script.execute(currentState, monitor, console.getStdOut());
			console.addMessage(scriptName, "Finished!");
		}
		catch (CancelledException e) {
			console.addErrorMessage(scriptName, "User cancelled script.");
		}
		catch (Exception e) {
			if (!monitor.isCancelled()) {
				Msg.showError(this, null, getTaskTitle(), "Error running script: " + scriptName +
					"\n" + e.getClass().getName() + ": " + e.getMessage(), e);
				console.addErrorMessage("", "Error running script: " + scriptName);
				console.addException(scriptName, e);
			}
		}
	}

	private String getDirectoryPath(String path, String title) {
		GhidraFileChooser chooser = new GhidraFileChooser(null);
		chooser.setCurrentDirectory(new File(path));
		chooser.setFileSelectionMode(GhidraFileChooserMode.DIRECTORIES_ONLY);
		chooser.setTitle(title);
		File selectedDir = chooser.getSelectedFile();
		if (selectedDir != null && !chooser.wasCancelled()) {
			return selectedDir.getAbsolutePath();
		}
		return null;
	}

	public Program getProgram() {
		return script.getCurrentProgram();
	}
}
