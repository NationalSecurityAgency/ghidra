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

import java.io.File;
import java.util.Objects;

import docking.widgets.OptionDialog;
import ghidra.app.CorePluginPackage;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.util.exporter.CppExporter;
import ghidra.app.util.exporter.OriginalFileExporter;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
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
	static final String OPTION_ALLOW_EDITS = "אפשר ל-AI לערוך את התוכנית";
	static final String OPTION_DOC_MAX = "תיעוד הכל - מספר פונקציות מקסימלי";

	/** Marks comments written by the assistant, so re-running "document all" skips them. */
	static final String AI_COMMENT_PREFIX = "[AI] ";

	static final String DEFAULT_CLAUDE_MODEL = "claude-opus-5-5";
	static final String DEFAULT_GEMINI_MODEL = "gemini-flash-latest";
	static final String DEFAULT_OPENAI_MODEL = "gpt-5";

	/** Everything that identifies a configured backend; a change means a new conversation. */
	private record ProviderConfig(ProviderType type, String key, String model, String url) {}

	private AIAssistantProvider provider;
	private AIProvider backend;
	private ProviderConfig backendConfig;
	private DecompInterface decompiler;
	private Program decompilerProgram;

	public AIAssistantPlugin(PluginTool tool) {
		super(tool);
		registerOptions();
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
		o.registerOption(OPTION_ALLOW_EDITS, true, null,
			"אם מסומן, ה-AI יכול להציע שינויים (שינוי שמות, הערות, חתימות, Patch, מחיקת " +
				"פונקציות). כל שינוי דורש את אישורך וניתן לביטול עם Ctrl+Z.");
		o.registerOption(OPTION_DOC_MAX, 200, null,
			"כמה פונקציות לכל היותר יתועדו בלחיצה על \"תעד הכל בעברית\" (כל פונקציה היא " +
				"בקשה נפרדת ל-AI ועולה כסף)");
	}

	boolean isEditingAllowed() {
		return tool.getOptions(OPTIONS_CATEGORY).getBoolean(OPTION_ALLOW_EDITS, true);
	}

	int getDocumentLimit() {
		return Math.max(1, tool.getOptions(OPTIONS_CATEGORY).getInt(OPTION_DOC_MAX, 200));
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
		AITools tools = new AITools(this, isEditingAllowed());
		tools.setMonitor(monitor);
		tools.setApprover(this::approveEdit);
		return ai.ask(question, tools, listener);
	}

	/** Shows the approval dialog for a change the AI wants to make. */
	private AITools.Approval approveEdit(String description) {
		int choice = OptionDialog.showOptionDialog(tool.getActiveWindow(),
			"עוזר AI מבקש לבצע שינוי",
			description + "\n\nאפשר לבטל את השינוי אחר כך עם Ctrl+Z.",
			"אשר", "אשר את כל השינויים בשאלה הזו", "דחה", OptionDialog.QUESTION_MESSAGE);
		return switch (choice) {
			case 1 -> AITools.Approval.YES;
			case 2 -> AITools.Approval.YES_TO_ALL;
			default -> AITools.Approval.NO;
		};
	}

	/**
	 * Writes a short Hebrew plate comment above every function that has none yet, using a
	 * separate one-shot request per function.
	 * @param listener receives progress lines for the chat window
	 * @return a summary of what was done
	 */
	String documentAllFunctions(java.util.function.Consumer<String> listener,
			TaskMonitor monitor) throws Exception {
		Program program = currentProgram;
		int limit = getDocumentLimit();
		java.util.List<Function> todo = new java.util.ArrayList<>();
		for (Function f : program.getFunctionManager().getFunctions(true)) {
			String plate = f.getComment();
			if (!f.isThunk() && (plate == null || plate.isBlank())) {
				todo.add(f);
			}
			if (todo.size() >= limit) {
				break;
			}
		}
		monitor.initialize(todo.size(), "מתעד פונקציות בעברית");
		int done = 0;
		for (Function f : todo) {
			if (monitor.isCancelled()) {
				break;
			}
			monitor.setMessage("מתעד את " + f.getName() + " (" + (done + 1) + "/" + todo.size() +
				")");
			String code = decompile(f, monitor);
			if (code == null) {
				monitor.incrementProgress();
				continue;
			}
			AIProvider oneShot = createBackend(readConfig());
			String summary = oneShot.ask("""
					Write a short documentation comment, in Hebrew, for the function below: 					one to three sentences on what it does and anything notable (inputs, 					outputs, side effects, security relevance). If its current name is 					generic (FUN_...), add a last line 'שם מוצע: <name>'. Reply with the 					comment text only, no markdown.

					```c
					""" + code + "\n```", AITools.none(this), (n, a) -> {});
			String text = AI_COMMENT_PREFIX + summary.strip();
			program.withTransaction("AI: תיעוד " + f.getName(), () -> f.setComment(text));
			listener.accept("  📝 " + f.getName() + ": " + firstLine(summary));
			done++;
			monitor.incrementProgress();
		}
		return "תועדו " + done + " פונקציות" +
			(todo.size() >= limit ? " (הגעת למגבלה של " + limit + "; אפשר להריץ שוב להמשך)" : "") +
			". ההערות מופיעות מעל כל פונקציה ברישום ובדה-קומפיילר.";
	}

	private static String firstLine(String text) {
		String line = text.strip().lines().findFirst().orElse("");
		return line.length() > 120 ? line.substring(0, 120) + "..." : line;
	}

	/**
	 * Exports the program's bytes, including all patches, in the original file format, so the
	 * result can be run (or compared) like the original binary.
	 */
	boolean exportPatchedBinary(File file, TaskMonitor monitor) throws Exception {
		return new OriginalFileExporter().export(file, currentProgram, null, monitor);
	}

	/**
	 * Exports the whole program as decompiled C (with the Hebrew comments), as a starting point
	 * for rebuilding it from source.
	 */
	boolean exportAllC(File file, TaskMonitor monitor) throws Exception {
		CppExporter exporter = new CppExporter(null, true, true, true, true, false, null);
		return exporter.export(file, currentProgram, null, monitor);
	}

	synchronized void resetConversation() {
		if (backend != null) {
			backend.reset();
		}
	}

	private synchronized AIProvider getBackend() {
		ProviderConfig config = readConfig();
		if (backend == null || !Objects.equals(config, backendConfig)) {
			backend = createBackend(config);
			backendConfig = config;
		}
		return backend;
	}

	private static AIProvider createBackend(ProviderConfig config) {
		return switch (config.type()) {
			case CLAUDE -> new ClaudeProvider(config.key(), config.model(),
				System.getenv("ANTHROPIC_BASE_URL"));
			case GEMINI -> new GeminiProvider(config.key(), config.model(), null);
			case OPENAI_COMPATIBLE -> new OpenAICompatibleProvider(config.key(), config.model(),
				config.url());
		};
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
		DecompileResults results = decompileResults(function, monitor);
		return results == null ? null : results.getDecompiledFunction().getC();
	}

	/**
	 * Decompiles a function, or returns null if decompilation fails.
	 */
	synchronized DecompileResults decompileResults(Function function, TaskMonitor monitor) {
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
		return results;
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
