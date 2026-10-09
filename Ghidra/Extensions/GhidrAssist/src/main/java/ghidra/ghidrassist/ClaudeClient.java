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

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.time.Duration;
import java.util.List;
import java.util.function.Consumer;
import java.util.stream.Stream;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/**
 * Thin wrapper over the Anthropic Messages API. One instance per plugin;
 * calls are stateless and safe to issue from a background thread.
 */
public final class ClaudeClient {

	private static final String ANTHROPIC_VERSION = "2023-06-01";

	private final HttpClient http;
	private final Gson gson = new Gson();

	public ClaudeClient() {
		this.http = HttpClient.newBuilder()
				.connectTimeout(Duration.ofSeconds(20))
				.version(HttpClient.Version.HTTP_1_1)
				.build();
	}

	/**
	 * Non-streaming call; blocks until the full response is available.
	 */
	public String complete(ClaudeOptions opts, List<ClaudeMessage> history)
			throws IOException, InterruptedException {

		if (!opts.isConfigured()) {
			throw new IOException("No Anthropic API key configured. Set it in " +
				"Edit → Tool Options → GhidrAssist.");
		}

		JsonObject body = buildRequestBody(opts, history, false);
		HttpRequest req = HttpRequest.newBuilder()
				.uri(URI.create(opts.baseUrl() + "/v1/messages"))
				.timeout(Duration.ofMinutes(5))
				.header("x-api-key", opts.apiKey())
				.header("anthropic-version", ANTHROPIC_VERSION)
				.header("content-type", "application/json")
				.POST(BodyPublishers.ofString(gson.toJson(body)))
				.build();

		HttpResponse<String> resp = http.send(req, BodyHandlers.ofString());
		if (resp.statusCode() / 100 != 2) {
			throw new IOException("Anthropic API error " + resp.statusCode() + ": " + resp.body());
		}
		return extractText(JsonParser.parseString(resp.body()).getAsJsonObject());
	}

	/**
	 * Streaming call. {@code onDelta} is invoked for every text fragment as it
	 * arrives; {@code onDone} is invoked once with the full concatenated text.
	 * {@code onError} is invoked on any transport or protocol failure.
	 * All callbacks run on the thread doing the HTTP read, not on the EDT.
	 */
	public void stream(ClaudeOptions opts, List<ClaudeMessage> history,
			Consumer<String> onDelta, Consumer<String> onDone, Consumer<Throwable> onError) {

		try {
			if (!opts.isConfigured()) {
				throw new IOException("No Anthropic API key configured. Set it in " +
					"Edit → Tool Options → GhidrAssist.");
			}

			JsonObject body = buildRequestBody(opts, history, true);
			HttpRequest req = HttpRequest.newBuilder()
					.uri(URI.create(opts.baseUrl() + "/v1/messages"))
					.timeout(Duration.ofMinutes(5))
					.header("x-api-key", opts.apiKey())
					.header("anthropic-version", ANTHROPIC_VERSION)
					.header("content-type", "application/json")
					.header("accept", "text/event-stream")
					.POST(BodyPublishers.ofString(gson.toJson(body)))
					.build();

			HttpResponse<Stream<String>> resp = http.send(req, BodyHandlers.ofLines());
			if (resp.statusCode() / 100 != 2) {
				StringBuilder err = new StringBuilder();
				resp.body().forEach(l -> err.append(l).append('\n'));
				throw new IOException(
					"Anthropic API error " + resp.statusCode() + ": " + err.toString().trim());
			}

			StringBuilder full = new StringBuilder();
			try (Stream<String> lines = resp.body()) {
				lines.forEach(line -> {
					if (!line.startsWith("data:")) {
						return;
					}
					String payload = line.substring(5).trim();
					if (payload.isEmpty() || payload.equals("[DONE]")) {
						return;
					}
					try {
						JsonObject obj = JsonParser.parseString(payload).getAsJsonObject();
						String type = obj.has("type") ? obj.get("type").getAsString() : "";
						if ("content_block_delta".equals(type)) {
							JsonObject delta = obj.getAsJsonObject("delta");
							if (delta != null && delta.has("text")) {
								String frag = delta.get("text").getAsString();
								full.append(frag);
								onDelta.accept(frag);
							}
						}
						else if ("error".equals(type) && obj.has("error")) {
							JsonObject e = obj.getAsJsonObject("error");
							throw new RuntimeException(e.toString());
						}
					}
					catch (RuntimeException parseErr) {
						// Swallow malformed events — the stream may still recover.
					}
				});
			}
			onDone.accept(full.toString());
		}
		catch (Throwable t) {
			onError.accept(t);
		}
	}

	private JsonObject buildRequestBody(ClaudeOptions opts, List<ClaudeMessage> history,
			boolean stream) {
		JsonObject body = new JsonObject();
		body.addProperty("model", opts.model());
		body.addProperty("max_tokens", opts.maxTokens());
		if (opts.systemPrompt() != null && !opts.systemPrompt().isBlank()) {
			body.addProperty("system", opts.systemPrompt());
		}
		if (stream) {
			body.addProperty("stream", true);
		}
		JsonArray msgs = new JsonArray();
		for (ClaudeMessage m : history) {
			JsonObject jm = new JsonObject();
			jm.addProperty("role", m.role());
			jm.addProperty("content", m.content());
			msgs.add(jm);
		}
		body.add("messages", msgs);
		return body;
	}

	private static String extractText(JsonObject response) {
		JsonElement content = response.get("content");
		if (content == null || !content.isJsonArray()) {
			return "";
		}
		StringBuilder sb = new StringBuilder();
		for (JsonElement e : content.getAsJsonArray()) {
			if (!e.isJsonObject()) {
				continue;
			}
			JsonObject block = e.getAsJsonObject();
			String type = block.has("type") ? block.get("type").getAsString() : "";
			if ("text".equals(type) && block.has("text")) {
				sb.append(block.get("text").getAsString());
			}
		}
		return sb.toString();
	}
}
