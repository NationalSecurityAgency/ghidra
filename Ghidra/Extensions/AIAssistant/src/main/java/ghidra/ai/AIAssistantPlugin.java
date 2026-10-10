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
package ghidra.ai;

import ghidra.app.CorePluginPackage;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.task.TaskMonitor;

/**
 * Built-in AI assistant: a docked chat window (Hebrew UI) backed by Claude that can explain the
 * current function, suggest names, and answer free-form questions about the program.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.ANALYSIS,
	shortDescription = "AI Assistant (Claude)",
	description = "עוזר AI מובנה: הסבר פונקציות, הצעת שמות ושאלות חופשיות על הקוד, בעברית."
)
//@formatter:on
public class AIAssistantPlugin extends ProgramPlugin {

	static final String OPTIONS_CATEGORY = "עוזר AI";
	static final String OPTION_API_KEY = "מפתח API של Anthropic";
	static final String OPTION_MODEL = "מודל";
	static final String DEFAULT_MODEL = "claude-opus-5-5";

	private AIAssistantProvider provider;
	private final ClaudeClient claude = new ClaudeClient();

	public AIAssistantPlugin(PluginTool tool) {
		super(tool);
		registerOptions();
		provider = new AIAssistantProvider(this);
		provider.addToTool();
	}

	private void registerOptions() {
		ToolOptions options = tool.getOptions(OPTIONS_CATEGORY);
		options.registerOption(OPTION_API_KEY, "", null,
			"מפתח ה-API של Anthropic. אם ריק, נעשה שימוש במשתנה הסביבה ANTHROPIC_API_KEY.");
		options.registerOption(OPTION_MODEL, DEFAULT_MODEL, null, "מזהה המודל של Claude");
	}

	String getApiKey() {
		String key = tool.getOptions(OPTIONS_CATEGORY).getString(OPTION_API_KEY, "").strip();
		if (key.isEmpty()) {
			String env = System.getenv("ANTHROPIC_API_KEY");
			key = env == null ? "" : env.strip();
		}
		return key;
	}

	String getModel() {
		String model = tool.getOptions(OPTIONS_CATEGORY).getString(OPTION_MODEL, DEFAULT_MODEL);
		return model == null || model.isBlank() ? DEFAULT_MODEL : model.strip();
	}

	ClaudeClient getClaude() {
		return claude;
	}

	Program getProgram() {
		return currentProgram;
	}

	Function getCurrentFunction() {
		ProgramLocation loc = currentLocation;
		if (currentProgram == null || loc == null || loc.getAddress() == null) {
			return null;
		}
		return currentProgram.getFunctionManager().getFunctionContaining(loc.getAddress());
	}

	/**
	 * Decompiles the given function to C, or returns null if decompilation fails.
	 */
	String decompile(Function function, TaskMonitor monitor) {
		DecompInterface ifc = new DecompInterface();
		try {
			if (!ifc.openProgram(function.getProgram())) {
				return null;
			}
			DecompileResults results = ifc.decompileFunction(function, 60, monitor);
			if (results == null || !results.decompileCompleted()) {
				return null;
			}
			return results.getDecompiledFunction().getC();
		}
		finally {
			ifc.dispose();
		}
	}

	@Override
	protected void dispose() {
		provider.dispose();
		super.dispose();
	}
}
