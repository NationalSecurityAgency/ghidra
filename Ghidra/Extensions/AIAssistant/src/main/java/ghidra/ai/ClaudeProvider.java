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

import java.util.*;

import com.anthropic.client.AnthropicClient;
import com.anthropic.client.okhttp.AnthropicOkHttpClient;
import com.anthropic.core.JsonValue;
import com.anthropic.errors.*;
import com.anthropic.models.messages.*;
import com.google.gson.JsonObject;

/**
 * Anthropic Claude backend, using the official Java SDK.
 */
class ClaudeProvider implements AIProvider {

	private final String apiKey;
	private final String model;
	private final String baseUrl;
	private final List<MessageParam> history = new ArrayList<>();
	private AnthropicClient client;

	ClaudeProvider(String apiKey, String model, String baseUrl) {
		this.apiKey = apiKey;
		this.model = model;
		this.baseUrl = baseUrl;
	}

	@Override
	public synchronized void reset() {
		history.clear();
	}

	@Override
	public synchronized String ask(String userText, AITools tools, ToolCallListener listener)
			throws Exception {
		if (client == null) {
			AnthropicOkHttpClient.Builder builder = AnthropicOkHttpClient.builder().apiKey(apiKey);
			if (baseUrl != null && !baseUrl.isBlank()) {
				builder.baseUrl(baseUrl);
			}
			client = builder.build();
		}
		List<Tool> toolDefs = toTools(tools);
		int start = history.size();
		history.add(MessageParam.builder().role(MessageParam.Role.USER).content(userText).build());

		try {
			for (int round = 0; round <= MAX_TOOL_ROUNDS; round++) {
				MessageCreateParams.Builder params = MessageCreateParams.builder()
						.model(model)
						.maxTokens(16000L)
						.system(SYSTEM_PROMPT)
						.messages(history)
						.outputConfig(
							OutputConfig.builder().effort(OutputConfig.Effort.MEDIUM).build())
						// If the primary model declines, let the API retry on a fallback model
						.putAdditionalHeader("anthropic-beta", "server-side-fallback-2026-07-01")
						.putAdditionalBodyProperty("fallbacks", JsonValue.from("default"));
				toolDefs.forEach(params::addTool);

				Message response = client.messages().create(params.build());
				history.add(response.toParam());

				List<ContentBlockParam> results = new ArrayList<>();
				for (ContentBlock block : response.content()) {
					block.toolUse().ifPresent(use -> {
						JsonObject args = toJson(use._input());
						listener.toolCalled(use.name(), args.toString());
						String result = tools.execute(use.name(), args);
						results.add(ContentBlockParam.ofToolResult(ToolResultBlockParam.builder()
								.toolUseId(use.id())
								.content(result)
								.build()));
					});
				}

				StopReason stop = response.stopReason().orElse(null);
				if (results.isEmpty() || !StopReason.TOOL_USE.equals(stop)) {
					return finalText(response, stop);
				}
				history.add(MessageParam.builder()
						.role(MessageParam.Role.USER)
						.contentOfBlockParams(results)
						.build());
			}
			return "[הופסק: יותר מדי צעדי חיפוש בשאלה אחת]";
		}
		catch (UnauthorizedException | PermissionDeniedException e) {
			rollback(start);
			throw new AIException(401, e.getMessage());
		}
		catch (RateLimitException e) {
			rollback(start);
			throw new AIException(429, e.getMessage());
		}
		catch (Exception e) {
			rollback(start);
			throw e;
		}
	}

	/** Drops a failed exchange so the next request starts from a valid conversation. */
	private void rollback(int size) {
		while (history.size() > size) {
			history.remove(history.size() - 1);
		}
	}

	private static String finalText(Message response, StopReason stop) {
		StringBuilder sb = new StringBuilder();
		for (ContentBlock block : response.content()) {
			block.text().ifPresent(t -> sb.append(t.text()));
		}
		if (StopReason.REFUSAL.equals(stop)) {
			sb.append("\n[הבקשה נדחתה על ידי המודל]");
		}
		else if (StopReason.MAX_TOKENS.equals(stop)) {
			sb.append("\n[התשובה נקטעה - הגיעה למגבלת האורך]");
		}
		return sb.toString().strip();
	}

	private static List<Tool> toTools(AITools tools) {
		List<Tool> list = new ArrayList<>();
		for (AITools.ToolSpec spec : tools.getSpecs()) {
			Tool.InputSchema.Properties.Builder props = Tool.InputSchema.Properties.builder();
			spec.properties().forEach((k, v) -> props.putAdditionalProperty(k, JsonValue.from(v)));
			list.add(Tool.builder()
					.name(spec.name())
					.description(spec.description())
					.inputSchema(Tool.InputSchema.builder()
							.properties(props.build())
							.required(spec.required())
							.build())
					.build());
		}
		return list;
	}

	@SuppressWarnings("unchecked")
	private static JsonObject toJson(JsonValue value) {
		Map<String, Object> map = value.convert(Map.class);
		return map == null ? new JsonObject()
				: HttpJson.GSON.toJsonTree(map).getAsJsonObject();
	}
}
