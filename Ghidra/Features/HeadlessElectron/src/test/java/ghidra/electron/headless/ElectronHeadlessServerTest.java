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

import static org.junit.Assert.*;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.http.*;
import java.nio.file.Path;
import java.util.concurrent.*;

import org.junit.*;

import com.google.gson.JsonObject;

import generic.test.AbstractGenericTest;

public class ElectronHeadlessServerTest extends AbstractGenericTest {
	private ElectronHeadlessServer server;
	private HttpClient client;
	private String baseUrl;
	private Path tempDir;

	@Before
	public void setUpServer() throws Exception {
		tempDir = createTempDirectory("headless-server");
		server = new ElectronHeadlessServer(new EventBroker(), tempDir, 0, new FakeProjectOps(),
			new FakeExecutionEngine());
		server.start();
		client = HttpClient.newHttpClient();
		baseUrl = "http://127.0.0.1:" + server.getPort();
	}

	@After
	public void tearDownServer() {
		server.stop();
	}

	@Test
	public void testHealthEndpoint() throws Exception {
		JsonObject json = getJson("/api/v1/health");
		assertEquals("1.0", json.get("protocolVersion").getAsString());
		assertEquals("ok", json.getAsJsonObject("data").get("status").getAsString());
	}

	@Test
	public void testProjectCreateAndList() throws Exception {
		String createBody = """
			{"projectPath":"%s","projectName":"server-alpha"}
			""".formatted(tempDir.toString().replace("\\", "\\\\"));
		JsonObject create = sendJson("/api/v1/projects", "POST", createBody);
		assertTrue(create.getAsJsonObject("data").get("created").getAsBoolean());

		JsonObject list = getJson("/api/v1/projects");
		assertEquals(1, list.getAsJsonObject("data").getAsJsonArray("projects").size());
	}

	@Test
	public void testValidationErrorForMissingInputPath() throws Exception {
		sendJson("/api/v1/projects", "POST",
			("{\"projectPath\":\"%s\",\"projectName\":\"server-beta\"}")
				.formatted(tempDir.toString().replace("\\", "\\\\")));
		JsonObject list = getJson("/api/v1/projects");
		String projectId = list.getAsJsonObject("data").getAsJsonArray("projects").get(0)
				.getAsJsonObject().get("projectId").getAsString();

		HttpResponse<String> response = send("/api/v1/projects/" + projectId + "/import-and-analyze",
			"POST", "{\"inputPath\":\"/no/such/file\"}");
		assertEquals(422, response.statusCode());
		JsonObject error = JsonSupport.GSON.fromJson(response.body(), JsonObject.class);
		assertEquals("VALIDATION_ERROR",
			error.getAsJsonObject("error").get("code").getAsString());
	}

	@Test
	public void testSseReceivesProjectCreatedEvent() throws Exception {
		ExecutorService executor = Executors.newSingleThreadExecutor();
		try {
			Future<String> future = executor.submit(() -> {
				try (BufferedReader reader = new BufferedReader(new InputStreamReader(
					URI.create(baseUrl + "/api/v1/events?since=0").toURL().openStream()))) {
					String line;
					while ((line = reader.readLine()) != null) {
						if (line.startsWith("event:")) {
							return line;
						}
					}
					return "";
				}
			});

			sendJson("/api/v1/projects", "POST",
				("{\"projectPath\":\"%s\",\"projectName\":\"sse-alpha\"}")
					.formatted(tempDir.toString().replace("\\", "\\\\")));

			String eventLine = future.get(5, TimeUnit.SECONDS);
			assertEquals("event: project.created", eventLine);
		}
		finally {
			executor.shutdownNow();
		}
	}

	private JsonObject getJson(String path) throws Exception {
		return JsonSupport.GSON.fromJson(send(path, "GET", null).body(), JsonObject.class);
	}

	private JsonObject sendJson(String path, String method, String body) throws Exception {
		return JsonSupport.GSON.fromJson(send(path, method, body).body(), JsonObject.class);
	}

	private HttpResponse<String> send(String path, String method, String body) throws Exception {
		HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(baseUrl + path))
				.header("Content-Type", "application/json")
				.header("X-Request-Id", "test-request");
		if ("POST".equals(method)) {
			builder.POST(HttpRequest.BodyPublishers.ofString(body == null ? "" : body));
		}
		else {
			builder.GET();
		}
		return client.send(builder.build(), HttpResponse.BodyHandlers.ofString());
	}
}
