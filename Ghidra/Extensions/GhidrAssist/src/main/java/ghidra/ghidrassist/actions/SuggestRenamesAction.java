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

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.swing.SwingUtilities;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import docking.ActionContext;
import docking.widgets.OptionDialog;
import ghidra.ghidrassist.ClaudeMessage;
import ghidra.ghidrassist.ClaudeOptions;
import ghidra.ghidrassist.DecompilerHelper;
import ghidra.ghidrassist.GhidrAssistPlugin;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;

/**
 * Asks Claude for better names for the current function and its parameters /
 * locals. The response is parsed as a strict JSON object. The user confirms
 * the renames in a dialog before any are applied, and application happens
 * inside a single Ghidra transaction so Undo rolls everything back.
 */
public class SuggestRenamesAction extends GhidrAssistAction {

	public SuggestRenamesAction(GhidrAssistPlugin plugin) {
		super(plugin, "GhidrAssist Suggest Renames", "Suggest Renames");
	}

	@Override
	public void actionPerformed(ActionContext context) {
		Function fn = ActionSupport.functionOf(context);
		Program program = ActionSupport.programOf(context);
		if (fn == null || program == null) {
			return;
		}

		TaskLauncher.launch(new Task("GhidrAssist: Renames for " + fn.getName(),
			true, false, true) {

			@Override
			public void run(TaskMonitor monitor) {
				String c = DecompilerHelper.decompile(program, fn, monitor);
				if (c == null) {
					plugin.getProvider().postSystemMessage(
						"[rename] Could not decompile " + fn.getName() + ".");
					return;
				}
				String prompt = """
					Suggest better names for the function and its variables based on \
					this decompiled C.

					Return ONLY a JSON object matching:
					{
					  "function": "<new function name or null>",
					  "renames": { "<old_name>": "<new_name>", ... }
					}

					Rules:
					- Only propose a rename when you are confident. If unsure, omit it.
					- Keep identifiers valid C: ASCII letters/digits/underscore, not starting \
					  with a digit.
					- Preserve calling convention and visibility; do not propose names starting \
					  with underscore for public-looking functions.
					- No prose, no code fences. Just the JSON.

					Current function name: %s

					```c
					%s
					```
					""".formatted(fn.getName(), c);

				ClaudeOptions opts = plugin.options();
				String response;
				try {
					response = plugin.claude().complete(opts, List.of(ClaudeMessage.user(prompt)));
				}
				catch (Exception e) {
					plugin.getProvider().postSystemMessage("[rename] error: " + e.getMessage());
					return;
				}
				JsonObject obj = parseJsonObjectLoose(response);
				if (obj == null) {
					plugin.getProvider().postAssistantMessage(
						"renames " + fn.getName(),
						"Could not parse response as JSON. Raw reply:\n" + response);
					return;
				}

				String newFnName = null;
				if (obj.has("function") && !obj.get("function").isJsonNull()) {
					JsonElement fe = obj.get("function");
					if (fe.isJsonPrimitive()) {
						newFnName = fe.getAsString();
					}
				}
				Map<String, String> renames = new LinkedHashMap<>();
				if (obj.has("renames") && obj.get("renames").isJsonObject()) {
					for (Map.Entry<String, JsonElement> e : obj.getAsJsonObject("renames")
							.entrySet()) {
						if (e.getValue().isJsonPrimitive()) {
							renames.put(e.getKey(), e.getValue().getAsString());
						}
					}
				}

				StringBuilder preview = new StringBuilder();
				if (newFnName != null && !newFnName.equals(fn.getName())) {
					preview.append("function: ")
							.append(fn.getName())
							.append("  →  ")
							.append(newFnName)
							.append('\n');
				}
				for (Map.Entry<String, String> r : renames.entrySet()) {
					if (!r.getKey().equals(r.getValue())) {
						preview.append("  ")
								.append(r.getKey())
								.append("  →  ")
								.append(r.getValue())
								.append('\n');
					}
				}
				if (preview.length() == 0) {
					plugin.getProvider().postSystemMessage(
						"[rename] Claude did not propose any renames.");
					return;
				}

				final String finalFnName = newFnName;
				SwingUtilities.invokeLater(() -> {
					int choice = OptionDialog.showYesNoDialog(null,
						"GhidrAssist — Apply Renames?",
						"Apply the following renames to " + fn.getName() + "?\n\n" + preview);
					if (choice == OptionDialog.YES_OPTION) {
						int applied =
							applyRenames(program, fn, finalFnName, renames);
						plugin.getProvider().postSystemMessage(
							"[rename] Applied " + applied + " name change" +
								(applied == 1 ? "" : "s") + ".");
					}
				});
			}
		});
	}

	private static int applyRenames(Program program, Function fn, String newFnName,
			Map<String, String> renames) {
		int applied = 0;
		int tx = program.startTransaction("GhidrAssist: rename " + fn.getName());
		boolean commit = false;
		try {
			if (newFnName != null && !newFnName.isBlank() && !newFnName.equals(fn.getName())) {
				try {
					fn.setName(newFnName, SourceType.USER_DEFINED);
					applied++;
				}
				catch (DuplicateNameException | InvalidInputException ignored) {
				}
			}
			applied += applyToVariables(fn.getParameters(), renames);
			applied += applyToVariables(fn.getLocalVariables(), renames);
			commit = true;
		}
		finally {
			program.endTransaction(tx, commit);
		}
		return applied;
	}

	private static int applyToVariables(Variable[] vars, Map<String, String> renames) {
		int count = 0;
		for (Variable v : vars) {
			String n = v.getName();
			String target = renames.get(n);
			if (target == null || target.isBlank() || target.equals(n)) {
				continue;
			}
			try {
				if (v instanceof Parameter p) {
					p.setName(target, SourceType.USER_DEFINED);
				}
				else {
					v.setName(target, SourceType.USER_DEFINED);
				}
				count++;
			}
			catch (DuplicateNameException | InvalidInputException ignored) {
			}
		}
		return count;
	}

	private static JsonObject parseJsonObjectLoose(String response) {
		String s = response == null ? "" : response.trim();
		if (s.startsWith("```")) {
			int firstNl = s.indexOf('\n');
			if (firstNl >= 0) {
				s = s.substring(firstNl + 1);
			}
			if (s.endsWith("```")) {
				s = s.substring(0, s.length() - 3);
			}
			s = s.trim();
		}
		int start = s.indexOf('{');
		int end = s.lastIndexOf('}');
		if (start < 0 || end <= start) {
			return null;
		}
		try {
			return JsonParser.parseString(s.substring(start, end + 1)).getAsJsonObject();
		}
		catch (Exception e) {
			return null;
		}
	}
}
