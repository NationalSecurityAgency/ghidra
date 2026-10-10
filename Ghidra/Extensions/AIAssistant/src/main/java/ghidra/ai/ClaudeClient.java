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

import java.util.ArrayList;
import java.util.List;

import com.anthropic.client.AnthropicClient;
import com.anthropic.client.okhttp.AnthropicOkHttpClient;
import com.anthropic.core.JsonValue;
import com.anthropic.models.messages.*;

/**
 * Thin wrapper around the Anthropic Java SDK that keeps a running conversation so the user
 * can ask follow-up questions about the code they are looking at.
 */
class ClaudeClient {

	private static final String SYSTEM_PROMPT = """
			You are an expert reverse engineer embedded inside Ghidra. The user is analyzing a \
			binary and will send you decompiled C, disassembly, or questions about them. \
			Always answer in Hebrew (keep code, identifiers and technical terms in English). \
			Be concise and concrete: explain what the code does, point out notable behavior \
			(crypto, networking, string handling, anti-debugging, vulnerabilities), and when asked \
			for names, suggest clear snake_case or camelCase identifiers with a one-line reason.""";

	private final List<MessageParam> history = new ArrayList<>();
	private AnthropicClient client;
	private String clientKey;

	synchronized void reset() {
		history.clear();
	}

	/**
	 * Sends a user message (with the conversation so far) and returns Claude's reply text.
	 */
	synchronized String send(String apiKey, String model, String userText) {
		AnthropicClient c = getClient(apiKey);

		history.add(MessageParam.builder()
				.role(MessageParam.Role.USER)
				.content(userText)
				.build());

		MessageCreateParams params = MessageCreateParams.builder()
				.model(model)
				.maxTokens(16000L)
				.system(SYSTEM_PROMPT)
				.messages(history)
				.outputConfig(OutputConfig.builder().effort(OutputConfig.Effort.MEDIUM).build())
				// If the primary model declines, let the API retry on a fallback model
				.putAdditionalHeader("anthropic-beta", "server-side-fallback-2026-07-01")
				.putAdditionalBodyProperty("fallbacks", JsonValue.from("default"))
				.build();

		Message response;
		try {
			response = c.messages().create(params);
		}
		catch (RuntimeException e) {
			// Keep the history consistent so the next request is still valid
			history.remove(history.size() - 1);
			throw e;
		}

		history.add(response.toParam());

		StringBuilder sb = new StringBuilder();
		for (ContentBlock block : response.content()) {
			block.text().ifPresent(t -> sb.append(t.text()));
		}

		if (response.stopReason().map(r -> r.equals(StopReason.REFUSAL)).orElse(false)) {
			sb.append("\n[הבקשה נדחתה על ידי המודל]");
		}
		else if (response.stopReason().map(r -> r.equals(StopReason.MAX_TOKENS)).orElse(false)) {
			sb.append("\n[התשובה נקטעה - הגיעה למגבלת האורך]");
		}
		return sb.toString().strip();
	}

	private AnthropicClient getClient(String apiKey) {
		if (client == null || !apiKey.equals(clientKey)) {
			client = AnthropicOkHttpClient.builder().apiKey(apiKey).build();
			clientKey = apiKey;
		}
		return client;
	}
}
