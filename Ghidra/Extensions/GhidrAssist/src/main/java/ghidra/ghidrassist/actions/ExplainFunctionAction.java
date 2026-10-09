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
package ghidra.ghidrassist.actions;

import java.util.List;

import docking.ActionContext;
import ghidra.ghidrassist.ClaudeMessage;
import ghidra.ghidrassist.ClaudeOptions;
import ghidra.ghidrassist.DecompilerHelper;
import ghidra.ghidrassist.GhidrAssistPlugin;
import ghidra.ghidrassist.GhidrAssistProvider;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;

public class ExplainFunctionAction extends GhidrAssistAction {

	public ExplainFunctionAction(GhidrAssistPlugin plugin) {
		super(plugin, "GhidrAssist Explain Function", "Explain Function");
	}

	@Override
	public void actionPerformed(ActionContext context) {
		Function fn = ActionSupport.functionOf(context);
		Program program = ActionSupport.programOf(context);
		if (fn == null || program == null) {
			return;
		}

		TaskLauncher.launch(new Task("GhidrAssist: Explain " + fn.getName(), true, false, true) {
			@Override
			public void run(TaskMonitor monitor) {
				monitor.setMessage("Decompiling " + fn.getName());
				String c = DecompilerHelper.decompile(program, fn, monitor);
				if (c == null) {
					plugin.getProvider().postSystemMessage(
						"[explain] Could not decompile " + fn.getName() + ".");
					return;
				}
				monitor.setMessage("Asking Claude");
				String prompt = """
					Explain the following decompiled C function. Be concise.

					Report:
					- One-line purpose
					- Inputs / outputs / side effects
					- Any suspicious or notable behavior (crypto, networking, parsing, obfuscation, \
					  unchecked user input, hard-coded constants worth noting)

					Function name in the binary: %s
					Entry point: %s

					```c
					%s
					```
					""".formatted(fn.getName(), fn.getEntryPoint(), c);

				ClaudeOptions opts = plugin.options();
				GhidrAssistProvider.StreamHandle out =
					plugin.getProvider().beginStream("explain " + fn.getName());
				plugin.claude().stream(opts, List.of(ClaudeMessage.user(prompt)),
					out::append, out::close, out::error);
			}
		});
	}
}
