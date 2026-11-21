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
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;

/**
 * Suggests a cleaner C signature for the current function. The suggestion is
 * posted into the chat panel for the user to review; applying it to the
 * program is left as a manual step (parsing arbitrary C declarations and
 * mapping them to Ghidra data types is error-prone, and we don't want the
 * assistant silently rewriting function prototypes).
 */
public class SuggestSignatureAction extends GhidrAssistAction {

	public SuggestSignatureAction(GhidrAssistPlugin plugin) {
		super(plugin, "GhidrAssist Suggest Signature", "Suggest Signature");
	}

	@Override
	public void actionPerformed(ActionContext context) {
		Function fn = ActionSupport.functionOf(context);
		Program program = ActionSupport.programOf(context);
		if (fn == null || program == null) {
			return;
		}

		TaskLauncher.launch(
			new Task("GhidrAssist: Signature for " + fn.getName(), true, false, true) {
				@Override
				public void run(TaskMonitor monitor) {
					String c = DecompilerHelper.decompile(program, fn, monitor);
					if (c == null) {
						plugin.getProvider().postSystemMessage(
							"[signature] Could not decompile " + fn.getName() + ".");
						return;
					}
					String prompt = """
						Based on this decompiled function, propose a cleaner C signature \
						(return type + typed, named parameters). Rules:
						- Keep the function name %s.
						- Use common libc / POSIX types where they clearly apply (size_t, \
						  ssize_t, const char *, FILE *, etc.).
						- If a parameter's role is unclear, keep its original name.
						- Return exactly one line: just the prototype, ending with a \
						  semicolon. No prose, no code fences.

						```c
						%s
						```
						""".formatted(fn.getName(), c);

					ClaudeOptions opts = plugin.options();
					try {
						String sig = plugin.claude()
								.complete(opts, List.of(ClaudeMessage.user(prompt)));
						plugin.getProvider().postAssistantMessage(
							"signature " + fn.getName(),
							sig.trim() +
								"\n\n(Apply manually via Edit Function Signature; the plugin " +
								"will not rewrite prototypes automatically.)");
					}
					catch (Exception e) {
						plugin.getProvider().postSystemMessage(
							"[signature] error: " + e.getMessage());
					}
				}
			});
	}
}
