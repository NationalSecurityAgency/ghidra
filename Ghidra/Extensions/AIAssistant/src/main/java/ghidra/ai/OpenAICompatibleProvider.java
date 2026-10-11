/* ###
 * IP: HexToCode_License
 *
 * HexToCode
 * Copyright (c) 2026 Shmuel Sinay <g47ben@gmail.com>. All rights reserved.
 *
 * Licensed under the HexToCode Restricted License; see the LICENSE file at the
 * root of this distribution. You may not use, copy, modify or distribute this
 * file except as that license allows.
 */
package ghidra.ai;

import java.util.HashMap;
import java.util.Map;

import com.google.gson.*;

/**
 * Backend for any service that speaks the OpenAI "chat completions" API: OpenAI, OpenRouter,
 * DeepSeek, Groq, Mistral, xAI, and local servers such as Ollama or LM Studio.
 */
class OpenAICompatibleProvider implements AIProvider {

	static final String DEFAULT_BASE_URL = "https://api.openai.com/v1";

	private final String apiKey;
	private final String model;
	private final String baseUrl;
	private final JsonArray messages = new JsonArray();

	OpenAICompatibleProvider(String apiKey, String model, String baseUrl) {
		this.apiKey = apiKey;
		this.model = model;
		this.baseUrl = baseUrl == null || baseUrl.isBlank() ? DEFAULT_BASE_URL
				: baseUrl.replaceAll("/+$", "");
	}

	@Override
	public synchronized void reset() {
		while (!messages.isEmpty()) {
			messages.remove(messages.size() - 1);
		}
	}

	@Override
	public synchronized String ask(String userText, AITools tools, ToolCallListener listener)
			throws Exception {
		if (messages.isEmpty()) {
			messages.add(message("system", SYSTEM_PROMPT));
		}
		int start = messages.size();
		messages.add(message("user", userText));

		Map<String, String> headers = new HashMap<>();
		if (!apiKey.isEmpty()) {
			// local servers (Ollama, LM Studio) usually need no key
			headers.put("Authorization", "Bearer " + apiKey);
		}
		try {
			for (int round = 0; round <= MAX_TOOL_ROUNDS; round++) {
				JsonObject body = new JsonObject();
				body.addProperty("model", model);
				body.add("messages", messages);
				if (!tools.getSpecs().isEmpty()) {
					body.add("tools", toolDefinitions(tools));
				}

				JsonObject response = HttpJson.post(baseUrl + "/chat/completions", headers, body);
				JsonArray choices = response.getAsJsonArray("choices");
				if (choices == null || choices.isEmpty()) {
					rollback(start);
					return "[לא התקבלה תשובה מהשרת]";
				}
				JsonObject choice = choices.get(0).getAsJsonObject();
				JsonObject reply = choice.getAsJsonObject("message");

				// Re-send only the standard fields; some servers reject extra ones
				JsonObject assistant = new JsonObject();
				assistant.addProperty("role", "assistant");
				JsonElement content = reply.get("content");
				assistant.add("content", content == null ? JsonNull.INSTANCE : content);
				JsonArray calls = reply.has("tool_calls") && reply.get("tool_calls").isJsonArray()
						? reply.getAsJsonArray("tool_calls")
						: new JsonArray();
				if (!calls.isEmpty()) {
					assistant.add("tool_calls", calls);
				}
				messages.add(assistant);

				if (calls.isEmpty()) {
					String text = content == null || content.isJsonNull() ? ""
							: content.getAsString();
					String finish = choice.has("finish_reason") &&
						!choice.get("finish_reason").isJsonNull()
								? choice.get("finish_reason").getAsString()
								: "";
					if (finish.equals("length")) {
						text += "\n[התשובה נקטעה - הגיעה למגבלת האורך]";
					}
					else if (finish.equals("content_filter")) {
						text += "\n[התשובה נחסמה על ידי מסנן התוכן]";
					}
					return text.strip();
				}

				for (JsonElement c : calls) {
					JsonObject call = c.getAsJsonObject();
					JsonObject fn = call.getAsJsonObject("function");
					String name = fn.get("name").getAsString();
					String rawArgs = fn.has("arguments") && !fn.get("arguments").isJsonNull()
							? fn.get("arguments").getAsString()
							: "{}";
					JsonObject args = HttpJson.parseArgs(rawArgs);
					listener.toolCalled(name, args.toString());

					JsonObject toolMsg = new JsonObject();
					toolMsg.addProperty("role", "tool");
					toolMsg.add("tool_call_id", call.get("id"));
					toolMsg.addProperty("content", tools.execute(name, args));
					messages.add(toolMsg);
				}
			}
			return "[הופסק: יותר מדי צעדי חיפוש בשאלה אחת]";
		}
		catch (Exception e) {
			rollback(start);
			throw e;
		}
	}

	private void rollback(int size) {
		while (messages.size() > size) {
			messages.remove(messages.size() - 1);
		}
	}

	private static JsonArray toolDefinitions(AITools tools) {
		JsonArray array = new JsonArray();
		for (AITools.ToolSpec spec : tools.getSpecs()) {
			JsonObject fn = new JsonObject();
			fn.addProperty("name", spec.name());
			fn.addProperty("description", spec.description());
			fn.add("parameters", HttpJson.schema(spec));
			JsonObject tool = new JsonObject();
			tool.addProperty("type", "function");
			tool.add("function", fn);
			array.add(tool);
		}
		return array;
	}

	private static JsonObject message(String role, String content) {
		JsonObject m = new JsonObject();
		m.addProperty("role", role);
		m.addProperty("content", content);
		return m;
	}
}
