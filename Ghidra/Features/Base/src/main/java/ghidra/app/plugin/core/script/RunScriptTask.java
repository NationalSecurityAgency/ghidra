/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import generic.jar.ResourceFile;
import ghidra.app.script.*;
import ghidra.app.services.ConsoleService;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

import java.util.*;

class RunScriptTask extends Task {
	private ResourceFile scriptSourceFile;
	private ConsoleService console;
	private GhidraState currentState;
	private String scriptName;
	private GhidraScript script;

	RunScriptTask(ResourceFile scriptSourceFile, GhidraScript script, GhidraState currentState,
			ConsoleService console) {
		super(scriptSourceFile.getName(), true, false, false);
		this.scriptSourceFile = scriptSourceFile;
		this.script = script;
		this.scriptName = scriptSourceFile.getName();
		this.console = console;
		this.currentState = currentState;
	}

	@Override
	public void run(TaskMonitor monitor) {
		if (scriptHasNameCollision()) {
			return;
		}

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

	private boolean scriptHasNameCollision() {
		if (checkDuplicate()) {
			Msg.showWarn(this, null, "Duplicated Script", "Unable to run script '" + scriptName +
				"'. Name is not unique (see log for detailed script locations).");
			return true;
		}
		return false;
	}

	private boolean checkDuplicate() {
		ScriptInfo thisInfo = GhidraScriptUtil.getScriptInfo(scriptSourceFile);
		thisInfo.setDuplicate(false);

		List<ScriptInfo> duplicateScripts = new ArrayList<ScriptInfo>();

		Iterator<ScriptInfo> iter = GhidraScriptUtil.getScriptInfoIterator();
		while (iter.hasNext()) {
			ScriptInfo otherInfo = iter.next();
			if (thisInfo.equals(otherInfo)) {
				continue;
			}

			if (thisInfo.getName().equals(otherInfo.getName())) {
				thisInfo.setDuplicate(true);
				otherInfo.setDuplicate(true);
				duplicateScripts.add(otherInfo);
			}
		}

		boolean isDuplicate = thisInfo.isDuplicate();
		if (isDuplicate) {
			Msg.warn(this, "Found multiple scripts with the same name: ");
			Msg.warn(this, "\t" + thisInfo.getSourceFile().toString());
			for (ScriptInfo scriptInfo : duplicateScripts) {
				Msg.warn(this, "\t" + scriptInfo.getSourceFile().getAbsolutePath());
			}
		}
		return isDuplicate;
	}

	public Program getProgram() {
		return script.getCurrentProgram();
	}
}
