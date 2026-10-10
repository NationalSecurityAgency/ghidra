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

import java.util.Objects;

import ghidra.app.CorePluginPackage;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.task.TaskMonitor;

/**
 * Built-in AI assistant: a docked chat window (Hebrew UI) that answers questions about the open
 * program by investigating it with tools (search, cross references, decompiler, navigation).
 * Supports Anthropic Claude, Google AI Studio (Gemini) and any OpenAI-compatible service.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.ANALYSIS,
	shortDescription = "AI Assistant",
	description = "עוזר AI מובנה: שאלות על התוכנית (איפה נמצא X, מה גורם ל-Y), הסבר פונקציות " +
		"והצעת שמות. תומך ב-Claude, Gemini (Google AI Studio) וכל שירות תואם OpenAI."
)
//@formatter:on
public class AIAssistantPlugin extends ProgramPlugin {

	static final String OPTIONS_CATEGORY = "עוזר AI";
	static final String OPTION_PROVIDER = "ספק AI";
	static final String OPTION_CLAUDE_KEY = "Claude - מפתח API";
	static final String OPTION_CLAUDE_MODEL = "Claude - מודל";
	static final String OPTION_GEMINI_KEY = "Gemini - מפתח API (Google AI Studio)";
	static final String OPTION_GEMINI_MODEL = "Gemini - מודל";
	static final String OPTION_OPENAI_KEY = "OpenAI - מפתח API";
	static final String OPTION_OPENAI_MODEL = "OpenAI - מודל";
	static final String OPTION_OPENAI_URL = "OpenAI - כתובת שרת (Base URL)";

	static final String DEFAULT_CLAUDE_MODEL = "claude-opus-5-5";
	static final String DEFAULT_GEMINI_MODEL = "gemini-flash-latest";
	static final String DEFAULT_OPENAI_MODEL = "gpt-5";

	/** Everything that identifies a configured backend; a change means a new conversation. */
	private record ProviderConfig(ProviderType type, String key, String model, String url) {}

	private AIAssistantProvider provider;
	private final AITools tools;
	private AIProvider backend;
	private ProviderConfig backendConfig;
	private DecompInterface decompiler;
	private Program decompilerProgram;

	public AIAssistantPlugin(PluginTool tool) {
		super(tool);
		registerOptions();
		tools = new AITools(this);
		provider = new AIAssistantProvider(this);
		provider.addToTool();
	}

	private void registerOptions() {
		ToolOptions o = tool.getOptions(OPTIONS_CATEGORY);
		o.registerOption(OPTION_PROVIDER, ProviderType.CLAUDE, null,
			"איזה שירות AI ישמש את העוזר");
		o.registerOption(OPTION_CLAUDE_KEY, "", null,
			"מפתח API של Anthropic (console.anthropic.com). " +
				"אם ריק, נעשה שימוש במשתנה הסביבה ANTHROPIC_API_KEY.");
		o.registerOption(OPTION_CLAUDE_MODEL, DEFAULT_CLAUDE_MODEL, null, "מזהה מודל Claude");
		o.registerOption(OPTION_GEMINI_KEY, "", null,
			"מפתח API מ-Google AI Studio (aistudio.google.com). " +
				"אם ריק, נעשה שימוש במשתנה הסביבה GEMINI_API_KEY או GOOGLE_API_KEY.");
		o.registerOption(OPTION_GEMINI_MODEL, DEFAULT_GEMINI_MODEL, null,
			"מזהה מודל Gemini, למשל gemini-flash-latest או gemini-pro-latest");
		o.registerOption(OPTION_OPENAI_KEY, "", null,
			"מפתח API לשירות התואם OpenAI. אם ריק, נעשה שימוש ב-OPENAI_API_KEY. " +
				"שרתים מקומיים (Ollama, LM Studio) לרוב לא צריכים מפתח.");
		o.registerOption(OPTION_OPENAI_MODEL, DEFAULT_OPENAI_MODEL, null,
			"שם המודל בשירות (למשל gpt-5, deepseek-chat, llama3.1)");
		o.registerOption(OPTION_OPENAI_URL, OpenAICompatibleProvider.DEFAULT_BASE_URL, null,
			"כתובת ה-API. דוגמאות: https://api.openai.com/v1, https://openrouter.ai/api/v1, " +
				"https://api.deepseek.com/v1, http://localhost:11434/v1 (Ollama), " +
				"http://localhost:1234/v1 (LM Studio)");
	}

	ProviderType getProviderType() {
		return tool.getOptions(OPTIONS_CATEGORY).getEnum(OPTION_PROVIDER, ProviderType.CLAUDE);
	}

	private ProviderConfig readConfig() {
		ToolOptions o = tool.getOptions(OPTIONS_CATEGORY);
		ProviderType type = getProviderType();
		return switch (type) {
			case CLAUDE -> new ProviderConfig(type,
				key(o.getString(OPTION_CLAUDE_KEY, ""), "ANTHROPIC_API_KEY"),
				value(o.getString(OPTION_CLAUDE_MODEL, ""), DEFAULT_CLAUDE_MODEL), null);
			case GEMINI -> new ProviderConfig(type,
				key(o.getString(OPTION_GEMINI_KEY, ""), "GEMINI_API_KEY", "GOOGLE_API_KEY"),
				value(o.getString(OPTION_GEMINI_MODEL, ""), DEFAULT_GEMINI_MODEL), null);
			case OPENAI_COMPATIBLE -> new ProviderConfig(type,
				key(o.getString(OPTION_OPENAI_KEY, ""), "OPENAI_API_KEY"),
				value(o.getString(OPTION_OPENAI_MODEL, ""), DEFAULT_OPENAI_MODEL),
				value(o.getString(OPTION_OPENAI_URL, ""),
					OpenAICompatibleProvider.DEFAULT_BASE_URL));
		};
	}

	/**
	 * @return a short description of the configured backend, e.g. "Anthropic Claude
	 * (claude-opus-5-5)"
	 */
	String describeBackend() {
		ProviderConfig c = readConfig();
		return c.type() + " (" + c.model() + ")";
	}

	/**
	 * @return null if the backend is ready, otherwise a Hebrew explanation of what is missing
	 */
	String getConfigurationProblem() {
		ProviderConfig c = readConfig();
		boolean local = c.type() == ProviderType.OPENAI_COMPATIBLE &&
			c.url().matches("(?i)https?://(localhost|127\\.0\\.0\\.1|\\[::1\\]).*");
		if (c.key().isEmpty() && !local) {
			return "חסר מפתח API עבור " + c.type() + ". הגדר אותו ב-Edit > Tool Options > " +
				OPTIONS_CATEGORY + ".";
		}
		return null;
	}

	/**
	 * Asks the configured AI a question; it may call tools to investigate the program.
	 */
	String ask(String question, AIProvider.ToolCallListener listener, TaskMonitor monitor)
			throws Exception {
		AIProvider ai = getBackend();
		tools.setMonitor(monitor);
		try {
			return ai.ask(question, tools, listener);
		}
		finally {
			tools.setMonitor(null);
		}
	}

	synchronized void resetConversation() {
		if (backend != null) {
			backend.reset();
		}
	}

	private synchronized AIProvider getBackend() {
		ProviderConfig config = readConfig();
		if (backend == null || !Objects.equals(config, backendConfig)) {
			backend = switch (config.type()) {
				case CLAUDE -> new ClaudeProvider(config.key(), config.model(),
					System.getenv("ANTHROPIC_BASE_URL"));
				case GEMINI -> new GeminiProvider(config.key(), config.model(), null);
				case OPENAI_COMPATIBLE -> new OpenAICompatibleProvider(config.key(),
					config.model(), config.url());
			};
			backendConfig = config;
		}
		return backend;
	}

	private static String key(String configured, String... envVars) {
		if (configured != null && !configured.isBlank()) {
			return configured.strip();
		}
		for (String env : envVars) {
			String v = System.getenv(env);
			if (v != null && !v.isBlank()) {
				return v.strip();
			}
		}
		return "";
	}

	private static String value(String configured, String def) {
		return configured == null || configured.isBlank() ? def : configured.strip();
	}

	Program getProgram() {
		return currentProgram;
	}

	Address getCurrentAddress() {
		ProgramLocation loc = currentLocation;
		return loc == null ? null : loc.getAddress();
	}

	String getSelectionDescription() {
		if (currentSelection == null || currentSelection.isEmpty()) {
			return null;
		}
		return currentSelection.getMinAddress() + " - " + currentSelection.getMaxAddress() +
			" (" + currentSelection.getNumAddresses() + " bytes)";
	}

	Function getCurrentFunction() {
		Address addr = getCurrentAddress();
		if (currentProgram == null || addr == null) {
			return null;
		}
		return currentProgram.getFunctionManager().getFunctionContaining(addr);
	}

	/**
	 * Decompiles the given function to C, or returns null if decompilation fails. The decompiler
	 * process is kept alive between calls, since a single question may decompile many functions.
	 */
	synchronized String decompile(Function function, TaskMonitor monitor) {
		Program program = function.getProgram();
		if (decompiler == null || decompilerProgram != program) {
			disposeDecompiler();
			decompiler = new DecompInterface();
			if (!decompiler.openProgram(program)) {
				disposeDecompiler();
				return null;
			}
			decompilerProgram = program;
		}
		DecompileResults results = decompiler.decompileFunction(function, 60, monitor);
		if (results == null || !results.decompileCompleted()) {
			return null;
		}
		return results.getDecompiledFunction().getC();
	}

	private synchronized void disposeDecompiler() {
		if (decompiler != null) {
			decompiler.dispose();
		}
		decompiler = null;
		decompilerProgram = null;
	}

	@Override
	protected void programDeactivated(Program program) {
		if (program == decompilerProgram) {
			disposeDecompiler();
		}
	}

	@Override
	protected void dispose() {
		disposeDecompiler();
		provider.dispose();
		super.dispose();
	}
}
