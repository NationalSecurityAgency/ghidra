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

import ghidra.app.services.ConsoleService;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

public class PurgeIndexTask extends Task {

	private TaintPlugin plugin;
	private Program program;

	public PurgeIndexTask(TaintPlugin plugin, Program program) {
		super("Purge Index Action", true, true, false, false);
		this.plugin = plugin;
		this.program = program;
	}

	@Override
	public void run(TaskMonitor monitor) throws CancelledException {

		PluginTool tool = plugin.getTool();
		ConsoleService consoleService = tool.getService(ConsoleService.class);

		ToolOptions options = tool.getOptions("Decompiler");

		// This will pull all the Taint options default set in the plugin.  These could also be set in Ghidra configuration files.
		String facts_directory =
			options.getString(TaintOptions.OP_KEY_TAINT_FACTS_DIR, "/tmp/export");
		String index_directory =
			options.getString(TaintOptions.OP_KEY_TAINT_OUTPUT_DIR, "/tmp/output");
		String index_db_name = options.getString(TaintOptions.OP_KEY_TAINT_DB, "ctadlir.db");

		// builds a custom db name with the string of the binary embedded in it for better identification.
		index_db_name = TaintOptions.makeDBName(index_db_name, program.getName());

		Path facts_path = Path.of(facts_directory);
		File facts = facts_path.toFile();
		if (facts.exists() && facts.isDirectory()) {
			Msg.info(this, "Deleting contents: " + facts_path.toString());
			File[] files = facts.listFiles();
			for (File f : files) {
				f.delete();
			}
		}
		consoleService.addMessage("Purge Index", "using facts path: " + facts_path);

		Path index_path = Path.of(index_directory, index_db_name);
		File index = index_path.toFile();
		if (index.exists() && !index.isDirectory()) {
			Msg.info(this, "Deleting index: " + index_path.toString());
			index.delete();
		}
		consoleService.addMessage("Purge Index", "using index path: " + index_path);
	}
}
