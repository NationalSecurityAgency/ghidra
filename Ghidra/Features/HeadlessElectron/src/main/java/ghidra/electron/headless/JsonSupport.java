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
package ghidra.electron.headless;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.UUID;

import com.google.gson.*;
import com.sun.net.httpserver.HttpExchange;

class JsonSupport {
	static final Gson GSON = new GsonBuilder().serializeNulls().setPrettyPrinting().create();

	private JsonSupport() {
	}

	static <T> T readJson(HttpExchange exchange, Class<T> type) throws IOException {
		try (InputStream in = exchange.getRequestBody();
				InputStreamReader reader = new InputStreamReader(in, StandardCharsets.UTF_8)) {
			return GSON.fromJson(reader, type);
		}
	}

	static String requestId(HttpExchange exchange) {
		String requestId = exchange.getRequestHeaders().getFirst("X-Request-Id");
		if (requestId == null || requestId.isBlank()) {
			return UUID.randomUUID().toString();
		}
		return requestId;
	}

	static void writeEnvelope(HttpExchange exchange, int statusCode, String requestId, Object data)
			throws IOException {
		writeJson(exchange, statusCode, new ApiEnvelope(requestId, data, null));
	}

	static void writeError(HttpExchange exchange, int statusCode, String requestId, ApiError error)
			throws IOException {
		writeJson(exchange, statusCode, new ApiEnvelope(requestId, null, error));
	}

	static void writeJson(HttpExchange exchange, int statusCode, Object payload) throws IOException {
		byte[] bytes = GSON.toJson(payload).getBytes(StandardCharsets.UTF_8);
		exchange.getResponseHeaders().set("Content-Type", "application/json");
		exchange.sendResponseHeaders(statusCode, bytes.length);
		try (OutputStream out = exchange.getResponseBody()) {
			out.write(bytes);
		}
	}

	static void writeFile(HttpExchange exchange, Path file, String contentType, String dispositionType,
			String fileName) throws IOException {
		exchange.getResponseHeaders().set("Content-Type", contentType);
		exchange.getResponseHeaders().set("Content-Disposition",
			dispositionType + "; filename=\"" + fileName + "\"");
		exchange.sendResponseHeaders(200, Files.size(file));
		try (OutputStream out = exchange.getResponseBody()) {
			Files.copy(file, out);
		}
	}
}
