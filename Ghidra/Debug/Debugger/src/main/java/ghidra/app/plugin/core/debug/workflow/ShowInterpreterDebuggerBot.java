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
package ghidra.app.plugin.core.debug.workflow;

import java.util.concurrent.CompletableFuture;

import ghidra.app.services.DebuggerInterpreterService;
import ghidra.app.services.DebuggerWorkflowFrontEndService;
import ghidra.dbg.DebugModelConventions;
import ghidra.dbg.DebuggerObjectModel;
import ghidra.dbg.target.TargetInterpreter;
import ghidra.debug.api.workflow.DebuggerBot;
import ghidra.debug.api.workflow.DebuggerBotInfo;
import ghidra.framework.options.annotation.HelpInfo;
import ghidra.framework.plugintool.PluginToolUtils;
import ghidra.util.Msg;
import ghidra.util.Swing;

@DebuggerBotInfo(
	description = "Show debugger interpreters",
	details = """
			Listens for new debuggers supporting the interpreter interface, and when found,
			displays that interpeter.""",
	help = @HelpInfo(anchor = "show_interpreter"),
	enabledByDefault = true)
public class ShowInterpreterDebuggerBot implements DebuggerBot {
	private DebuggerWorkflowFrontEndService service;

	@Override
	public void enable(DebuggerWorkflowFrontEndService service) {
		this.service = service;

		// Do not retroactively display interpreters
	}

	@Override
	public boolean isEnabled() {
		return service != null;
	}

	@Override
	public void disable() {
		service = null;
	}

	@Override
	public void modelAdded(DebuggerObjectModel model) {
		model.fetchModelRoot().thenCompose(root -> {
			CompletableFuture<? extends TargetInterpreter> fi =
				DebugModelConventions.findSuitable(TargetInterpreter.class, root);
			return fi;
		}).thenAccept(interpreter -> {
			if (interpreter == null) {
				return;
			}
			DebuggerInterpreterService interpreterService =
				PluginToolUtils.getServiceFromRunningCompatibleTool(service.getTool(),
					DebuggerInterpreterService.class);
			if (interpreterService == null) {
				return;
			}
			Swing.runIfSwingOrRunLater(() -> {
				interpreterService.showConsole(interpreter);
			});
		}).exceptionally(ex -> {
			Msg.error(this, "Error displaying debugger interpreter for " + model, ex);
			return null;
		});
	}

	@Override
	public void modelRemoved(DebuggerObjectModel model) {
		// Destruction of interpreter should cause console to become inactive
	}
}
