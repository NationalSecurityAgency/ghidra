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
package ghidra.jython;

import java.io.File;
import java.util.concurrent.atomic.AtomicBoolean;

import org.python.core.PyException;

import db.Transaction;
import generic.jar.ResourceFile;
import ghidra.app.plugin.core.interpreter.InterpreterConsole;
import ghidra.app.script.GhidraState;
import ghidra.app.script.ScriptControls;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * Thread responsible for executing a jython command for the plugin.
 */
class JythonPluginExecutionThread extends Thread {

	private JythonPlugin plugin;
	private String cmd;
	private AtomicBoolean moreInputWanted;

	/**
	 * Creates a new jython plugin execution thread that executes the given command for the given
	 * plugin.
	 * 
	 * @param plugin The jython plugin to execute the command for.
	 * @param cmd The jython command to execute.
	 * @param moreInputWanted Gets set to indicate that the executed command expects more input.
	 */
	JythonPluginExecutionThread(JythonPlugin plugin, String cmd, AtomicBoolean moreInputWanted) {
		super("Jython plugin execution thread");

		this.plugin = plugin;
		this.cmd = cmd;
		this.moreInputWanted = moreInputWanted;
	}

	@Override
	public void run() {

		TaskMonitor interactiveTaskMonitor = plugin.getInteractiveTaskMonitor();
		JythonScript interactiveScript = plugin.getInteractiveScript();
		Program program = plugin.getCurrentProgram();
		InterpreterConsole console = plugin.getConsole();

		// Setup transaction for the execution.
		try (Transaction tx = program != null ? program.openTransaction("Jython command") : null) {
			// Setup Ghidra state to be passed into interpreter
			interactiveTaskMonitor.clearCancelled();
			interactiveScript.setSourceFile(new ResourceFile(new File("jython")));
			PluginTool tool = plugin.getTool();
			interactiveScript.set(
				new GhidraState(tool, tool.getProject(), program, plugin.getProgramLocation(),
					plugin.getProgramSelection(), plugin.getProgramHighlight()),
				new ScriptControls(console, interactiveTaskMonitor));

			// Execute the command
			moreInputWanted.set(false);
			moreInputWanted.set(plugin.getInterpreter().push(cmd, plugin.getInteractiveScript()));
		}
		catch (PyException pye) {
			String exceptionName = PyException.exceptionClassName(pye.type);
			if (exceptionName.equalsIgnoreCase("exceptions.SystemExit")) {
				plugin.reset();
			}
			else {
				console.getErrWriter()
						.println(
							"Suppressing exception: " + PyException.exceptionClassName(pye.type));
			}
		}
		catch (StackOverflowError soe) {
			console.getErrWriter().println("Stack overflow!");
		}
		finally {
			interactiveScript.end(false); // end any transactions the script may have started
		}
	}
}
