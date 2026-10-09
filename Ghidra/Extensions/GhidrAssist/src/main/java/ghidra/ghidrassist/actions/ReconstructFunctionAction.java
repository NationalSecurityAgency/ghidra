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

public class ReconstructFunctionAction extends GhidrAssistAction {

	public ReconstructFunctionAction(GhidrAssistPlugin plugin) {
		super(plugin, "GhidrAssist Reconstruct Function", "Reconstruct as C");
	}

	@Override
	public void actionPerformed(ActionContext context) {
		Function fn = ActionSupport.functionOf(context);
		Program program = ActionSupport.programOf(context);
		if (fn == null || program == null) {
			return;
		}

		TaskLauncher.launch(
			new Task("GhidrAssist: Reconstruct " + fn.getName(), true, false, true) {
				@Override
				public void run(TaskMonitor monitor) {
					monitor.setMessage("Decompiling " + fn.getName());
					String c = DecompilerHelper.decompile(program, fn, monitor);
					if (c == null) {
						plugin.getProvider().postSystemMessage(
							"[reconstruct] Could not decompile " + fn.getName() + ".");
						return;
					}
					String prompt = """
						Rewrite the following decompiler output as idiomatic, portable C. \
						Preserve semantics exactly; do not invent calls, structs, or \
						behavior. Keep the same function name and signature unless the \
						decompiler produced something clearly nonsensical. Prefer named \
						constants and clear control flow over the decompiler's goto-heavy \
						style. Return only the rewritten function in a single ```c``` \
						fenced block, no commentary.

						```c
						%s
						```
						""".formatted(c);

					ClaudeOptions opts = plugin.options();
					GhidrAssistProvider.StreamHandle out =
						plugin.getProvider().beginStream("reconstruct " + fn.getName());
					plugin.claude().stream(opts, List.of(ClaudeMessage.user(prompt)),
						out::append, out::close, out::error);
				}
			});
	}
}
