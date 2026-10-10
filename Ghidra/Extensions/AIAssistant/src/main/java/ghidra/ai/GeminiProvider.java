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

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import com.google.gson.*;

/**
 * Google Gemini backend (Google AI Studio API key), using the generateContent REST API.
 */
class GeminiProvider implements AIProvider {

	static final String DEFAULT_BASE_URL = "https://generativelanguage.googleapis.com/v1beta";

	private final String apiKey;
	private final String model;
	private final String baseUrl;
	private final JsonArray contents = new JsonArray();

	GeminiProvider(String apiKey, String model, String baseUrl) {
		this.apiKey = apiKey;
		this.model = model;
		this.baseUrl = baseUrl == null || baseUrl.isBlank() ? DEFAULT_BASE_URL
				: baseUrl.replaceAll("/+$", "");
	}

	@Override
	public synchronized void reset() {
		while (!contents.isEmpty()) {
			contents.remove(contents.size() - 1);
		}
	}

	@Override
	public synchronized String ask(String userText, AITools tools, ToolCallListener listener)
			throws Exception {
		int start = contents.size();
		contents.add(content("user", textPart(userText)));
		try {
			String url = baseUrl + "/models/" + URLEncoder.encode(model, StandardCharsets.UTF_8) +
				":generateContent";
			for (int round = 0; round <= MAX_TOOL_ROUNDS; round++) {
				JsonObject body = new JsonObject();
				body.add("systemInstruction", content(null, textPart(SYSTEM_PROMPT)));
				body.add("contents", contents);
				body.add("tools", toolDeclarations(tools));

				JsonObject response =
					HttpJson.post(url, Map.of("x-goog-api-key", apiKey), body);
				JsonArray candidates = response.getAsJsonArray("candidates");
				if (candidates == null || candidates.isEmpty()) {
					rollback(start);
					return "[הבקשה נחסמה על ידי Gemini: " + response.get("promptFeedback") + "]";
				}
				JsonObject candidate = candidates.get(0).getAsJsonObject();
				JsonObject modelContent = candidate.getAsJsonObject("content");
				if (modelContent == null) {
					rollback(start);
					return "[לא התקבלה תשובה מ-Gemini: " + candidate.get("finishReason") + "]";
				}
				// keep the whole content (including thought signatures) for the next turn
				contents.add(modelContent);

				JsonArray responses = new JsonArray();
				StringBuilder text = new StringBuilder();
				JsonArray parts = modelContent.getAsJsonArray("parts");
				for (JsonElement p : parts == null ? new JsonArray() : parts) {
					JsonObject part = p.getAsJsonObject();
					if (part.has("functionCall")) {
						JsonObject call = part.getAsJsonObject("functionCall");
						String name = call.get("name").getAsString();
						JsonObject args = call.has("args") && call.get("args").isJsonObject()
								? call.getAsJsonObject("args")
								: new JsonObject();
						listener.toolCalled(name, args.toString());
						String result = tools.execute(name, args);

						JsonObject fr = new JsonObject();
						fr.addProperty("name", name);
						if (call.has("id")) {
							fr.add("id", call.get("id"));
						}
						JsonObject resultObj = new JsonObject();
						resultObj.addProperty("result", result);
						fr.add("response", resultObj);
						JsonObject responsePart = new JsonObject();
						responsePart.add("functionResponse", fr);
						responses.add(responsePart);
					}
					else if (part.has("text") && !part.has("thought")) {
						text.append(part.get("text").getAsString());
					}
				}

				if (responses.isEmpty()) {
					String reason = candidate.has("finishReason")
							? candidate.get("finishReason").getAsString()
							: "";
					if (reason.equals("MAX_TOKENS")) {
						text.append("\n[התשובה נקטעה - הגיעה למגבלת האורך]");
					}
					else if (reason.equals("SAFETY") || reason.equals("PROHIBITED_CONTENT")) {
						text.append("\n[התשובה נחסמה על ידי Gemini]");
					}
					return text.toString().strip();
				}
				JsonObject toolTurn = new JsonObject();
				toolTurn.addProperty("role", "user");
				toolTurn.add("parts", responses);
				contents.add(toolTurn);
			}
			return "[הופסק: יותר מדי צעדי חיפוש בשאלה אחת]";
		}
		catch (Exception e) {
			rollback(start);
			throw e;
		}
	}

	private void rollback(int size) {
		while (contents.size() > size) {
			contents.remove(contents.size() - 1);
		}
	}

	private static JsonArray toolDeclarations(AITools tools) {
		JsonArray decls = new JsonArray();
		for (AITools.ToolSpec spec : tools.getSpecs()) {
			JsonObject d = new JsonObject();
			d.addProperty("name", spec.name());
			d.addProperty("description", spec.description());
			if (!spec.properties().isEmpty()) {
				// Gemini rejects an OBJECT schema with no properties
				d.add("parameters", HttpJson.schema(spec));
			}
			decls.add(d);
		}
		JsonObject tool = new JsonObject();
		tool.add("functionDeclarations", decls);
		JsonArray array = new JsonArray();
		array.add(tool);
		return array;
	}

	private static JsonObject textPart(String text) {
		JsonObject part = new JsonObject();
		part.addProperty("text", text);
		return part;
	}

	private static JsonObject content(String role, JsonObject part) {
		JsonObject c = new JsonObject();
		if (role != null) {
			c.addProperty("role", role);
		}
		JsonArray parts = new JsonArray();
		parts.add(part);
		c.add("parts", parts);
		return c;
	}
}
