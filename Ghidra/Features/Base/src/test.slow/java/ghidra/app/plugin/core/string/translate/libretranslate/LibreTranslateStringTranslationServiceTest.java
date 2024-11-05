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
package ghidra.app.plugin.core.string.translate.libretranslate;

import static ghidra.app.plugin.core.string.translate.libretranslate.LibreTranslatePlugin.SOURCE_LANGUAGE_OPTION.*;
import static ghidra.app.plugin.core.string.translate.libretranslate.LibreTranslateStringTranslationService.*;
import static java.net.HttpURLConnection.*;
import static org.junit.Assert.*;

import java.io.IOException;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.Before;
import org.junit.Test;

import com.google.gson.*;
import com.sun.net.httpserver.*;

import docking.AbstractErrDialog;
import docking.widgets.SelectFromListDialog;
import ghidra.app.plugin.core.string.translate.libretranslate.LibreTranslatePlugin.SOURCE_LANGUAGE_OPTION;
import ghidra.app.plugin.core.string.translate.libretranslate.LibreTranslateStringTranslationService.SupportedLanguage;
import ghidra.app.services.StringTranslationService.TranslateOptions;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;
import ghidra.program.util.ProgramLocation;
import ghidra.test.AbstractProgramBasedTest;
import ghidra.test.ToyProgramBuilder;
import ghidra.util.Msg;
import ghidra.util.Swing;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Tests the LibreTranslateStringTranslationService by creating a mock HTTP server that responds
 * to the minimal requests the service needs.
 */
public class LibreTranslateStringTranslationServiceTest extends AbstractProgramBasedTest {

	private static int LAST_SERVER_PORT_NUM = 8000 + 5000;
	private int supportedLanguageCount = 10;
	private AtomicInteger translateRequestCount = new AtomicInteger(); // number of times translate handler has been invoked
	private AtomicInteger translateStringCount = new AtomicInteger(); // number of strings that translate handler has processed
	private List<String> translateSourceLangs = Collections.synchronizedList(new ArrayList<>());
	private List<Data> strings = new ArrayList<>();

	@Test
	public void testWrongServerURL() throws IOException {
		// test what happens when the server returns 404's for the REST api requests
		HttpServer server = createMockHttpServer();
		try {
			server.start();
			LibreTranslateStringTranslationService sts =
				new LibreTranslateStringTranslationService(getURI(server.getAddress()), null,
					AUTO, "en", 100, 1000, 1000);

			setErrorsExpected(true); // don't kill the test because Msg.showError() was called somewhere
			Swing.runNow(() -> sts.translate(program, List.of(progLoc(0)), TranslateOptions.NONE));
			setErrorsExpected(false);

			waitForTasks();

			// we SHOULD get an error dialog because got bad http status result
			AbstractErrDialog errDlg = waitForErrorDialog();
			errDlg.dispose();
		}
		finally {
			server.stop(0);
		}
	}

	@Test
	public void testIncompatibleJSonResponse() throws IOException {
		// test what happens when the server accepts requests on the REST api endpoint URL, but
		// returns unexpected json values

		HttpServer server = createMockHttpServer(false);
		server.createContext("/", this::mockUnexpectedJsonResultHandler);

		try {
			server.start();
			LibreTranslateStringTranslationService sts =
				new LibreTranslateStringTranslationService(getURI(server.getAddress()), null,
					AUTO, "en", 100, 1000, 1000);

			setErrorsExpected(true); // don't kill the test because Msg.showError() was called somewhere
			Swing.runNow(() -> sts.translate(program, List.of(progLoc(0)), TranslateOptions.NONE));
			setErrorsExpected(false);

			waitForTasks();

			// we SHOULD get an error dialog because got bad http status result
			AbstractErrDialog errDlg = waitForErrorDialog();
			errDlg.dispose();
		}
		finally {
			server.stop(0);
		}
	}

	@Test
	public void testIncompatibleServerURL() throws IOException {
		// test what happens when the server accepts requests on the REST api endpoint URL, but its
		// not json

		HttpServer server = createMockHttpServer(false);
		server.createContext("/", this::mockUnexpectedTextResultHandler);

		try {
			server.start();
			LibreTranslateStringTranslationService sts =
				new LibreTranslateStringTranslationService(getURI(server.getAddress()), null,
					AUTO, "en", 100, 1000, 1000);

			setErrorsExpected(true); // don't kill the test because Msg.showError() was called somewhere
			Swing.runNow(() -> sts.translate(program, List.of(progLoc(0)), TranslateOptions.NONE));
			setErrorsExpected(false);

			waitForTasks();

			// we SHOULD get an error dialog because got bad http status result
			AbstractErrDialog errDlg = waitForErrorDialog();
			errDlg.dispose();
		}
		finally {
			server.stop(0);
		}
	}

	@Test
	public void testNoResponseFromURL() {
		// test what happens when the URL doesn't point to active server

		LibreTranslateStringTranslationService sts = new LibreTranslateStringTranslationService(
			getURI(nextUnusedAddr()), null, AUTO, "en", 100, 1000, 1000);

		setErrorsExpected(true); // don't kill the test because Msg.showError() was called somewhere
		Swing.runNow(() -> sts.translate(program, List.of(progLoc(0)), TranslateOptions.NONE));
		setErrorsExpected(false);

		waitForTasks();

		// we SHOULD get an error dialog because got bad http status result
		AbstractErrDialog errDlg = waitForErrorDialog();
		errDlg.dispose();
	}

	@Test
	public void testTranslateRequest() throws IOException {
		HttpServer server = createMockHttpServer();
		server.createContext("/translate", this::mockTranslateHandler);
		try {
			server.start();
			LibreTranslateStringTranslationService sts =
				new LibreTranslateStringTranslationService(getURI(server.getAddress()), null,
					AUTO, "en", 100, 1000, 1000);

			Swing.runNow(() -> sts.translate(program, List.of(progLoc(0)), TranslateOptions.NONE));
			assertEquals(translateRequestCount.get(), 1);

			String xlatedStr =
				TranslationSettingsDefinition.TRANSLATION.getTranslatedValue(strings.get(0));
			assertEquals("result0", xlatedStr);
		}
		finally {
			server.stop(0);
		}
	}

	@SuppressWarnings("unchecked")
	@Test
	public void testPromptForSourceLangTranslateRequest() throws IOException, CancelledException {
		HttpServer server = createMockHttpServer();
		server.createContext("/translate", this::mockTranslateHandler);
		server.createContext("/languages", this::mockLangHandler);

		try {
			server.start();
			LibreTranslateStringTranslationService sts =
				new LibreTranslateStringTranslationService(getURI(server.getAddress()), null,
					SOURCE_LANGUAGE_OPTION.PROMPT, "en", 100, 1000, 1000);
			List<SupportedLanguage> langs = sts.getSupportedLanguages(TaskMonitor.DUMMY);
			SupportedLanguage langToPick = langs.get(1);

			Swing.runLater(
				() -> sts.translate(program, List.of(progLoc(0)), TranslateOptions.NONE));

			@SuppressWarnings({ "rawtypes" })
			SelectFromListDialog selectDlg = waitForDialogComponent(SelectFromListDialog.class);

			Swing.runNow(() -> selectDlg.setSelectedObject(langToPick.getDescription()));
			Swing.runNow(() -> pressButtonByText(selectDlg, "OK"));

			waitForTasks();

			assertEquals(translateRequestCount.get(), 1);
			assertEquals(1, translateSourceLangs.size());
			assertEquals(langToPick.langCode(), translateSourceLangs.get(0));
		}
		finally {
			server.stop(0);
		}
	}

	@Test(timeout = 20000)
	public void testTimeoutTranslateRequest() throws IOException {
		HttpServer server = createMockHttpServer();

		server.createContext("/translate", wrapHandlerWithDelay(this::mockTranslateHandler, 5000));
		try {
			server.start();
			LibreTranslateStringTranslationService sts = new LibreTranslateStringTranslationService(
				getURI(server.getAddress()), null, AUTO, "en", 100, 1000, 1);

			Swing.runLater(() -> {
				setErrorsExpected(true); // don't kill the test because Msg.showError() was called somewhere
				sts.translate(program, List.of(progLoc(0)), TranslateOptions.NONE);
				setErrorsExpected(false);
			});

			waitForTasks();

			// we SHOULD get an error dialog because we forced the http request to timeout
			AbstractErrDialog errDlg = waitForErrorDialog();
			errDlg.dispose();
		}
		finally {
			server.stop(0);
		}
	}

	@Test(timeout = 20000)
	public void testRetryTranslateRequest() throws IOException {
		HttpServer server = createMockHttpServer();
		server.createContext("/translate", wrapHandlerWithDelay(this::mockTranslateHandler, 2000));
		try {
			server.start();
			LibreTranslateStringTranslationService sts = new LibreTranslateStringTranslationService(
				getURI(server.getAddress()), null, AUTO, "en", 100, 1500, 1);

			Swing.runNow(() -> sts.translate(program, List.of(progLoc(0)), TranslateOptions.NONE));
			assertTrue(translateRequestCount.get() > 1);
			waitForTasks();
		}
		finally {
			server.stop(0);
		}
	}

	@Test
	public void testBatchTranslateRequest() throws IOException {
		int batchSize = 2;
		HttpServer server = createMockHttpServer();
		server.createContext("/translate", this::mockTranslateHandler);
		try {
			server.start();
			LibreTranslateStringTranslationService sts =
				new LibreTranslateStringTranslationService(getURI(server.getAddress()), null, AUTO,
					"en", batchSize, 1000, 1000);

			List<ProgramLocation> stringLocs = strings.stream()
					.map(data -> new ProgramLocation(program, data.getAddress()))
					.toList();
			int expectedBatchCount = stringLocs.size() / batchSize;
			expectedBatchCount += (stringLocs.size() % batchSize != 0 ? 1 : 0);

			Swing.runNow(() -> sts.translate(program, stringLocs, TranslateOptions.NONE));

			assertEquals(translateRequestCount.get(), expectedBatchCount);
			assertEquals(translateStringCount.get(), stringLocs.size());
			waitForTasks();
		}
		finally {
			server.stop(0);
		}
	}

	@Test
	public void testLanguagesRequest() throws IOException, CancelledException {
		HttpServer server = createMockHttpServer();
		server.createContext("/languages", this::mockLangHandler);
		try {
			server.start();
			LibreTranslateStringTranslationService sts = new LibreTranslateStringTranslationService(
				getURI(server.getAddress()), null, AUTO, "en", 100, 1000, 1000);

			List<SupportedLanguage> langs = sts.getSupportedLanguages(TaskMonitor.DUMMY);
			assertEquals(supportedLanguageCount, langs.size());
		}
		finally {
			server.stop(0);
		}
	}

	//---------------------------------------------------------------------------------------------
	@Before
	public void setUp() throws Exception {
		initialize();
	}

	@Override
	protected ProgramDB getProgram() throws Exception {
		ToyProgramBuilder builder = new ToyProgramBuilder("String Examples", false);
		builder.createMemory("RAM", "0x0", 0x500);

		strings.add(builder.createString("0x100", "Hello World!\n", StandardCharsets.US_ASCII, true,
			StringDataType.dataType));
		strings.add(builder.createString("0x10e", "Next string", StandardCharsets.US_ASCII, true,
			StringDataType.dataType));

		strings.add(builder.createString("0x150", bytes(0, 1, 2, 3, 4, 0x80, 0x81, 0x82, 0x83),
			StandardCharsets.US_ASCII, StringDataType.dataType));

		strings.add(
			builder.createString("0x200", "\u6211\u96bb\u6c23\u588a\u8239\u88dd\u6eff\u6652\u9c54",
				StandardCharsets.UTF_16, true, UnicodeDataType.dataType));

		strings.add(builder.createString("0x250", "Exception %s\n\tline: %d\n",
			StandardCharsets.US_ASCII, true, StringDataType.dataType));

		strings.add(builder.createString("0x330",
			"A: \u6211\u96bb\u6c23\u588a\u8239\u88dd\u6eff\u6652\u9c54", StandardCharsets.UTF_8,
			true, StringUTF8DataType.dataType));

		strings.add(builder.createString("0x450",
			"Roses are \u001b[0;31mred\u001b[0m, violets are \u001b[0;34mblue. Hope you enjoy terminal hue",
			StandardCharsets.US_ASCII, true, StringDataType.dataType));

		return builder.getProgram();
	}

	private URI getURI(InetSocketAddress addr) {
		return URI.create("http://%s:%d".formatted(addr.getHostString(), addr.getPort()));
	}

	private HttpServer createMockHttpServer() throws IOException {
		return createMockHttpServer(true);
	}

	private HttpServer createMockHttpServer(boolean addDefaultHandler) throws IOException {
		IOException lastException = null;
		for (int retryNum = 0; retryNum < 10; retryNum++) {
			LAST_SERVER_PORT_NUM++; // don't try to reuse the same server port num in the same session
			InetSocketAddress serverAddress =
				new InetSocketAddress(InetAddress.getLoopbackAddress(), LAST_SERVER_PORT_NUM);

			try {
				HttpServer server = HttpServer.create(serverAddress, 0);
				if (addDefaultHandler) {
					server.createContext("/", this::mock404Handler);
				}
				return server;
			}
			catch (IOException e) {
				// ignore, just try again with next port num
				lastException = e;
			}
		}
		throw new IOException(
			"Could not allocate port for mock http server, last attempted port: " +
				LAST_SERVER_PORT_NUM,
			lastException);
	}

	private InetSocketAddress nextUnusedAddr() {
		LAST_SERVER_PORT_NUM++;
		return new InetSocketAddress(InetAddress.getLoopbackAddress(), LAST_SERVER_PORT_NUM);
	}

	private void assertContentType(HttpExchange httpExchange, String expectedType) {
		String contentType = httpExchange.getRequestHeaders()
				.getFirst(LibreTranslateStringTranslationService.CONTENT_TYPE_HEADER);
		contentType = Objects.requireNonNullElse(contentType, "missing");
		if (!expectedType.equals(contentType)) {
			fail("Content type incorrect: expected: %s, actual: %s".formatted(expectedType,
				contentType));
		}
	}

	private void log(HttpExchange httpExchange, String msg) {
		Msg.info(this, "[%s %s] %s".formatted(httpExchange.getLocalAddress(),
			httpExchange.getRequestURI(), msg));

	}

	private void mockLangHandler(HttpExchange httpExchange) throws IOException {
		assertContentType(httpExchange, CONTENT_TYPE_JSON);
		try {
			JsonArray langsResult = new JsonArray();
			for (int i = 0; i < supportedLanguageCount; i++) {
				JsonObject obj = new JsonObject();
				obj.addProperty("code", "%c%c".formatted('a' + i, 'a' + i));
				obj.addProperty("name", "Language " + i);
				JsonArray targets = new JsonArray();
				obj.add("targets", targets);
				langsResult.add(obj);
			}
			byte[] response = langsResult.toString().getBytes();

			httpExchange.getResponseHeaders().set(CONTENT_TYPE_HEADER, CONTENT_TYPE_JSON);
			httpExchange.sendResponseHeaders(HTTP_OK, response.length);
			httpExchange.getResponseBody().write(response);
		}
		finally {
			httpExchange.close();
		}
	}

	private void mockTranslateHandler(HttpExchange httpExchange) throws IOException {
		try {
			translateRequestCount.incrementAndGet();

			assertContentType(httpExchange, CONTENT_TYPE_JSON);

			String requestBody =
				new String(httpExchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);

			JsonObject request = JsonParser.parseString(requestBody).getAsJsonObject();
			JsonArray queryStrs = request.get("q").getAsJsonArray();
			String sourceLang = request.get("source").getAsString();

			translateSourceLangs.add(sourceLang);

			log(httpExchange,
				"request src=%s, strs=%s".formatted(sourceLang, queryStrs.toString()));

			JsonObject xlateResultObj = new JsonObject();
			JsonArray xlatedResults = new JsonArray();
			xlateResultObj.add("translatedText", xlatedResults);
			for (int i = 0; i < queryStrs.size(); i++) {
				xlatedResults.add("result" + translateStringCount.getAndIncrement());
			}
			log(httpExchange, "response: " + xlateResultObj);
			byte[] response = xlateResultObj.toString().getBytes();

			httpExchange.getResponseHeaders().set(CONTENT_TYPE_HEADER, CONTENT_TYPE_JSON);
			httpExchange.sendResponseHeaders(HTTP_OK, response.length);
			httpExchange.getResponseBody().write(response);
		}
		catch (Throwable th) {
			log(httpExchange, "Error during mockTranslateHandler: " + th.getMessage());
			throw th;
		}
		finally {
			httpExchange.close();
		}
	}

	private void mockUnexpectedJsonResultHandler(HttpExchange httpExchange) throws IOException {
		JsonObject jsonObj = new JsonObject();
		jsonObj.addProperty("something", "an unexpected value");
		byte[] response = jsonObj.toString().getBytes();

		httpExchange.getResponseHeaders().set(CONTENT_TYPE_HEADER, CONTENT_TYPE_JSON);
		httpExchange.sendResponseHeaders(HTTP_OK, response.length);
		httpExchange.getResponseBody().write(response);
		httpExchange.close();
	}

	private void mockUnexpectedTextResultHandler(HttpExchange httpExchange) throws IOException {
		// this returns OK for every URL
		byte[] response = "Hello world".toString().getBytes();

		httpExchange.getResponseHeaders().set(CONTENT_TYPE_HEADER, "text/plain");
		httpExchange.sendResponseHeaders(HTTP_OK, response.length);
		httpExchange.getResponseBody().write(response);
		httpExchange.close();
	}

	private HttpHandler wrapHandlerWithDelay(HttpHandler delegate, int delayMS) {
		return httpExchange -> {
			try {
				Thread.sleep(delayMS);
			}
			catch (InterruptedException e) {
				// ignore
			}
			delegate.handle(httpExchange);
		};
	}

	private void mock404Handler(HttpExchange httpExchange) throws IOException {
		try {
			httpExchange.sendResponseHeaders(HttpURLConnection.HTTP_NOT_FOUND, 0);
		}
		finally {
			httpExchange.close();
		}
	}

	private ProgramLocation progLoc(int stringNum) {
		return new ProgramLocation(program, strings.get(stringNum).getAddress());
	}

}
