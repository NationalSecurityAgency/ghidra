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

import java.io.IOException;
import java.net.ProxySelector;
import java.net.URI;
import java.net.http.*;
import java.time.Duration;
import java.util.Map;

import com.google.gson.*;

/**
 * Minimal JSON-over-HTTP helper for the providers that have no Java SDK.
 */
class HttpJson {

	private static final HttpClient CLIENT = HttpClient.newBuilder()
			.proxy(ProxySelector.getDefault())
			.connectTimeout(Duration.ofSeconds(30))
			.build();

	static final Gson GSON = new Gson();

	private HttpJson() {
		// utility class
	}

	static JsonObject post(String url, Map<String, String> headers, JsonObject body)
			throws IOException, InterruptedException, AIProvider.AIException {
		HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(url))
				.timeout(Duration.ofMinutes(10))
				.header("Content-Type", "application/json")
				.POST(HttpRequest.BodyPublishers.ofString(GSON.toJson(body)));
		headers.forEach(request::header);

		HttpResponse<String> response =
			CLIENT.send(request.build(), HttpResponse.BodyHandlers.ofString());
		String text = response.body();
		if (response.statusCode() / 100 != 2) {
			throw new AIProvider.AIException(response.statusCode(),
				response.statusCode() + ": " + errorMessage(text));
		}
		return JsonParser.parseString(text).getAsJsonObject();
	}

	private static String errorMessage(String body) {
		try {
			JsonElement e = JsonParser.parseString(body);
			if (e.isJsonArray() && !e.getAsJsonArray().isEmpty()) {
				e = e.getAsJsonArray().get(0);
			}
			JsonObject o = e.getAsJsonObject();
			if (o.has("error")) {
				JsonElement err = o.get("error");
				if (err.isJsonObject() && err.getAsJsonObject().has("message")) {
					return err.getAsJsonObject().get("message").getAsString();
				}
				return err.toString();
			}
		}
		catch (RuntimeException ex) {
			// not JSON; fall through
		}
		return body.length() > 500 ? body.substring(0, 500) : body;
	}

	/** Converts a tool's parameter description to a JSON schema object. */
	static JsonObject schema(AITools.ToolSpec spec) {
		JsonObject schema = new JsonObject();
		schema.addProperty("type", "object");
		schema.add("properties", GSON.toJsonTree(spec.properties()));
		if (!spec.required().isEmpty()) {
			schema.add("required", GSON.toJsonTree(spec.required()));
		}
		return schema;
	}

	static JsonObject parseArgs(String json) {
		if (json == null || json.isBlank()) {
			return new JsonObject();
		}
		try {
			JsonElement e = JsonParser.parseString(json);
			return e.isJsonObject() ? e.getAsJsonObject() : new JsonObject();
		}
		catch (RuntimeException e) {
			return new JsonObject();
		}
	}
}
