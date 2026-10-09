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
package ghidra.ghidrassist;

import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.HelpLocation;

/**
 * Reads GhidrAssist settings out of Ghidra's Tool Options so the plugin and
 * all its actions see one authoritative snapshot.
 */
public final class ClaudeOptions {

	public static final String OPTIONS_TITLE = "GhidrAssist";
	public static final String OPT_API_KEY = "Anthropic API Key";
	public static final String OPT_MODEL = "Model";
	public static final String OPT_BASE_URL = "API Base URL";
	public static final String OPT_MAX_TOKENS = "Max Response Tokens";
	public static final String OPT_SYSTEM_PROMPT = "System Prompt";

	public static final String DEFAULT_MODEL = "claude-sonnet-5-5";
	public static final String DEFAULT_BASE_URL = "https://api.anthropic.com";
	public static final int DEFAULT_MAX_TOKENS = 4096;
	public static final String DEFAULT_SYSTEM_PROMPT =
		"You are a reverse-engineering assistant embedded in Ghidra. The user is looking at " +
			"decompiled C produced from a stripped binary. Be concise, accurate, and never invent " +
			"behavior that is not supported by the code shown. When asked to rename or retype, " +
			"return only the requested JSON — no prose, no code fences.";

	private final String apiKey;
	private final String model;
	private final String baseUrl;
	private final int maxTokens;
	private final String systemPrompt;

	private ClaudeOptions(String apiKey, String model, String baseUrl, int maxTokens,
			String systemPrompt) {
		this.apiKey = apiKey;
		this.model = model;
		this.baseUrl = baseUrl;
		this.maxTokens = maxTokens;
		this.systemPrompt = systemPrompt;
	}

	public static void register(PluginTool tool) {
		ToolOptions opt = tool.getOptions(OPTIONS_TITLE);
		HelpLocation help = new HelpLocation("GhidrAssist", "Options");
		opt.registerOption(OPT_API_KEY, "", help,
			"Anthropic API key. Stored in your Ghidra user preferences, never transmitted " +
				"anywhere other than the configured base URL.");
		opt.registerOption(OPT_MODEL, DEFAULT_MODEL, help,
			"Claude model id (e.g. claude-sonnet-5-5, claude-opus-5-5, claude-haiku-4-5-20251001).");
		opt.registerOption(OPT_BASE_URL, DEFAULT_BASE_URL, help,
			"Base URL for the Anthropic API. Change for a proxy or compatible gateway.");
		opt.registerOption(OPT_MAX_TOKENS, DEFAULT_MAX_TOKENS, help,
			"Maximum tokens to request per response.");
		opt.registerOption(OPT_SYSTEM_PROMPT, DEFAULT_SYSTEM_PROMPT, help,
			"System prompt sent on every request.");
	}

	public static ClaudeOptions read(PluginTool tool) {
		ToolOptions opt = tool.getOptions(OPTIONS_TITLE);
		return new ClaudeOptions(
			opt.getString(OPT_API_KEY, ""),
			opt.getString(OPT_MODEL, DEFAULT_MODEL),
			opt.getString(OPT_BASE_URL, DEFAULT_BASE_URL),
			opt.getInt(OPT_MAX_TOKENS, DEFAULT_MAX_TOKENS),
			opt.getString(OPT_SYSTEM_PROMPT, DEFAULT_SYSTEM_PROMPT));
	}

	public boolean isConfigured() {
		return apiKey != null && !apiKey.isBlank();
	}

	public String apiKey() {
		return apiKey;
	}

	public String model() {
		return model;
	}

	public String baseUrl() {
		return baseUrl;
	}

	public int maxTokens() {
		return maxTokens;
	}

	public String systemPrompt() {
		return systemPrompt;
	}
}
