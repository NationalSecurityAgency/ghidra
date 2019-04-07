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
package ghidra.python;

import java.io.File;
import java.io.PrintWriter;
import java.util.concurrent.atomic.AtomicBoolean;

import org.python.core.PyException;

import generic.jar.ResourceFile;
import ghidra.app.script.GhidraState;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * Thread responsible for executing a python command for the plugin.
 */
class PythonPluginExecutionThread extends Thread {

	private PythonPlugin plugin;
	private String cmd;
	private AtomicBoolean moreInputWanted;

	/**
	 * Creates a new python plugin execution thread that executes the given command for the given plugin.
	 * 
	 * @param plugin The python plugin to execute the command for.
	 * @param cmd The python command to execute.
	 * @param moreInputWanted Gets set to indicate that the executed command expects more input.
	 */
	PythonPluginExecutionThread(PythonPlugin plugin, String cmd, AtomicBoolean moreInputWanted) {
		super("Python plugin execution thread");

		this.plugin = plugin;
		this.cmd = cmd;
		this.moreInputWanted = moreInputWanted;
	}

	@Override
	public void run() {

		TaskMonitor interactiveTaskMonitor = plugin.getInteractiveTaskMonitor();
		PythonScript interactiveScript = plugin.getInteractiveScript();
		Program program = plugin.getCurrentProgram();

		// Setup transaction for the execution.
		int transaction_number = -1;
		if (program != null) {
			transaction_number = program.startTransaction("Python command");
		}

		// Setup Ghidra state to be passed into interpreter
		interactiveTaskMonitor.clearCanceled();
		interactiveScript.setSourceFile(new ResourceFile(new File("python")));
		PluginTool tool = plugin.getTool();
		interactiveScript.set(
			new GhidraState(tool, tool.getProject(), program, plugin.getProgramLocation(),
				plugin.getProgramSelection(), plugin.getProgramHighlight()),
			interactiveTaskMonitor, new PrintWriter(plugin.getConsole().getStdOut()));

		// Execute the command
		boolean commit = false;
		moreInputWanted.set(false);
		try {
			moreInputWanted.set(plugin.getInterpreter().push(cmd, plugin.getInteractiveScript()));
			commit = true;
		}
		catch (PyException pye) {
			String exceptionName = PyException.exceptionClassName(pye.type);
			if (exceptionName.equalsIgnoreCase("exceptions.SystemExit")) {
				plugin.reset();
			}
			else {
				plugin.getConsole().getErrWriter().println("Suppressing exception: " +
					PyException.exceptionClassName(pye.type));
			}
		}
		catch (StackOverflowError soe) {
			plugin.getConsole().getErrWriter().println("Stack overflow!");
		}
		finally {
			// Re-get the current program in case the user closed the program while a long running 
			// command was executing.
			program = plugin.getCurrentProgram();
			if (program != null) {
				program.endTransaction(transaction_number, commit);
			}
		}
	}
}
