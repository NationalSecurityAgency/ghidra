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
import java.io.IOException;
import java.lang.ProcessBuilder.Redirect;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import ghidra.app.services.ConsoleService;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

public class CreateTargetIndexTask extends Task {

	private TaintPlugin plugin;
	private Program program;

	public CreateTargetIndexTask(TaintPlugin plugin, Program program) {
		super("Create Target Index Action", true, true, false, false);
		this.plugin = plugin;
		this.program = program;
	}

	private File getFilePath(String initial_directory, String title) {

		GhidraFileChooser chooser = new GhidraFileChooser(null);
		chooser.setCurrentDirectory(new File(initial_directory));
		chooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
		chooser.setTitle(title);
		File selectedFile = chooser.getSelectedFile();
		if (selectedFile != null) {
			return selectedFile;
		}

		return selectedFile;
	}

	private String getDirectoryPath(String path, String title) {

		GhidraFileChooser chooser = new GhidraFileChooser(null);
		chooser.setCurrentDirectory(new File(path));
		chooser.setFileSelectionMode(GhidraFileChooserMode.DIRECTORIES_ONLY);
		chooser.setTitle(title);
		File selectedDir = chooser.getCurrentDirectory();
		if (selectedDir != null && !chooser.wasCancelled()) {
			return selectedDir.getAbsolutePath();
		}
		return null;
	}

	private boolean indexProgram(String engine_path, String facts_path, String index_directory) {

		boolean rvalue = true;

		List<String> param_list = new ArrayList<String>();
		plugin.getTaintState().buildIndex(param_list, engine_path, facts_path, index_directory);
		Msg.info(this, "Index Param List: " + param_list.toString());

		try {
			ProcessBuilder pb = new ProcessBuilder(param_list);
			pb.directory(new File(facts_path));
			pb.redirectError(Redirect.INHERIT);
			Process p = pb.start();
			p.waitFor();

		}
		catch (IOException | InterruptedException e) {
			Msg.error(this, "Problems running index: " + e);
			rvalue = false;
		}

		return rvalue;
	}

	@Override
	public void run(TaskMonitor monitor) throws CancelledException {

		monitor.initialize(program.getFunctionManager().getFunctionCount());
		PluginTool tool = plugin.getTool();
		ConsoleService consoleService = tool.getService(ConsoleService.class);

		ToolOptions options = tool.getOptions("Decompiler");

		// This will pull all the Taint options default set in the plugin.  These could also be set in Ghidra configuration files.
		String enginePathName = options.getString(TaintOptions.OP_KEY_TAINT_ENGINE_PATH,
			"/home/user/workspace/engine_binary");
		String factsDirectory =
			options.getString(TaintOptions.OP_KEY_TAINT_FACTS_DIR, "/tmp/export");
		String indexDirectory =
			options.getString(TaintOptions.OP_KEY_TAINT_OUTPUT_DIR, "/tmp/output");
		String indexDBName = options.getString(TaintOptions.OP_KEY_TAINT_DB, "ctadlir.db");

		// builds a custom db name with the string of the binary embedded in it for better identification.
		indexDBName = TaintOptions.makeDBName(indexDBName, program.getName());

		Path enginePath = Path.of(enginePathName);
		File engineFile = enginePath.toFile();

		if (!engineFile.exists() || !engineFile.canExecute()) {
			Msg.info(this, "The engine binary (" + engineFile.getAbsolutePath() +
				") cannot be found or executed.");
			engineFile = getFilePath(enginePathName, "Select the engine binary");
		}

		consoleService.addMessage("Create Index", "using engine at: " + enginePath.toString());

		Path factsPath = Path.of(factsDirectory);

		if (!factsPath.toFile().exists() || !factsPath.toFile().isDirectory()) {
			Msg.info(this, "Facts Path: " + factsPath.toString() + " does not exist.");
			factsDirectory = getDirectoryPath(factsDirectory,
				"Select full path to the directory containing the FACTS files");
			if (factsDirectory == null) {
				Msg.info(this, "User cancelled operation; existing script.");
				return;
			}
			Msg.info(this, "Using .facts files in: " + factsDirectory);
			options.setString(TaintOptions.OP_KEY_TAINT_FACTS_DIR, factsDirectory);
		}
		else {
			factsDirectory = factsPath.toString();
		}

		consoleService.addMessage("Create Index", "using facts path: " + factsDirectory);
		Path indexPath0 = Path.of(indexDirectory);
		Path indexPath = Path.of(indexDirectory, indexDBName);

		if (!indexPath0.toFile().exists() || !indexPath0.toFile().isDirectory()) {
			// the index has already been build. Use it?
			Msg.info(this, "Index Path: " + indexPath.toString() + " does not exist.");
			indexDirectory = getDirectoryPath(indexDirectory,
				"Select full path to the directory to containthe INDEX file");
			indexPath = Path.of(indexDirectory, indexDBName);
			options.setString(TaintOptions.OP_KEY_TAINT_OUTPUT_DIR, indexDirectory);
		}

		consoleService.addMessage("Create Index", "using index path: " + indexDirectory);
		Msg.info(this, "Engine Path: " + engineFile.toString());
		Msg.info(this, "Facts Path: " + factsDirectory);
		Msg.info(this, "Index Path: " + indexDirectory);

		boolean success = indexProgram(engineFile.toString(), factsDirectory, indexDirectory);
		consoleService.addMessage("Create Index", "indexing status: " + success);
		monitor.clearCancelled();
	}
}
