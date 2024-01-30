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
package ghidra.app.plugin.core.debug.gui.control;

import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.services.DebuggerConsoleService;
import ghidra.debug.api.target.Target.ActionEntry;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

class TargetActionTask extends Task {
	private final PluginTool tool;
	private final ActionEntry entry;

	public TargetActionTask(PluginTool tool, String title, ActionEntry entry) {
		super(title, false, false, false);
		this.tool = tool;
		this.entry = entry;
	}

	@Override
	public void run(TaskMonitor monitor) throws CancelledException {
		try {
			entry.run(false);
		}
		catch (Throwable e) {
			reportError(e);
		}
	}

	private void reportError(Throwable error) {
		DebuggerConsoleService consoleService = tool.getService(DebuggerConsoleService.class);
		if (consoleService != null) {
			consoleService.log(DebuggerResources.ICON_LOG_ERROR, error.getMessage());
		}
		else {
			Msg.showError(this, null, "Control Error", error.getMessage(), error);
		}
	}
}
