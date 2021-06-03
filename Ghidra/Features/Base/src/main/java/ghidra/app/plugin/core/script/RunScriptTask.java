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
package ghidra.app.plugin.core.script;

import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraState;
import ghidra.app.services.ConsoleService;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

class RunScriptTask extends Task {
	private ConsoleService console;
	private GhidraState currentState;
	private String scriptName;
	private GhidraScript script;

	RunScriptTask(GhidraScript script, GhidraState currentState, ConsoleService console) {
		super(script.getSourceFile().getName(), true, false, false);
		this.script = script;
		this.scriptName = script.getSourceFile().getName();
		this.console = console;
		this.currentState = currentState;
	}

	@Override
	public void run(TaskMonitor monitor) {
		try {
			Thread.currentThread().setName(scriptName);

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

	public Program getProgram() {
		return script.getCurrentProgram();
	}
}
